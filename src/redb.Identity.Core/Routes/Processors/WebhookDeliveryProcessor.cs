using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using redb.Core.Models.Entities;
using redb.Identity.Contracts.Events;
using redb.Identity.Contracts.Routes;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.RedbCore.Extensions;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// W1 — fan-out delivery for every matching webhook subscription.
///
/// <para>
/// Consumes the wiretap of <c>identity-events</c> (one event = one invocation).
/// For each event:
///   <list type="number">
///   <item>Bulk-load enabled subscriptions
///     (<see cref="WebhookSubscriptionService.ListEnabledAsync"/>).</item>
///   <item>Filter each by <see cref="WebhookSubscriptionProps.EventTypeFilter"/>.</item>
///   <item>For each match, fire-and-forget an async delivery task that posts
///     the canonical JSON envelope through
///     <see cref="IProducerTemplate.SendAsync(string, IMessage)"/>. The URI
///     is opaque — <c>https://...</c>, <c>kafka://...</c>, <c>amqp://...</c>
///     — redb.Route resolves the transport. HMAC + timestamp + delivery id
///     headers travel via <see cref="IMessage.Headers"/>; the producer's
///     header-bridge copies them to the wire (HTTP headers, AMQP properties,
///     etc.). Per-subscription retry / backoff stays inside the processor.</item>
///   </list>
/// </para>
///
/// <para>
/// Delivery semantics are fire-and-forget RELATIVE to the originating
/// mutation: the originating exchange has already committed by the time
/// the wiretap reaches us. We MUST NOT block the event-dispatch route on
/// outbound latency — every delivery runs on its own <see cref="Task.Run"/>.
/// </para>
///
/// <para>
/// Architectural note: this processor is wired in
/// <see cref="IdentityCoreRouteBuilder"/> (Core) because subscriptions
/// themselves are a Core domain concept (storage + management). Transport-
/// agnosticism is preserved by going through <see cref="IProducerTemplate"/>
/// rather than reaching for <c>IHttpClientFactory</c> directly — Core never
/// learns about HTTP specifics.
/// </para>
/// </summary>
internal sealed class WebhookDeliveryProcessor : IProcessor
{
    private readonly IRouteContext _context;
    private readonly string? _redbName;
    private readonly ILogger<WebhookDeliveryProcessor> _logger;
    private IProducerTemplate? _producer;
    private readonly object _producerInitLock = new();

    public WebhookDeliveryProcessor(
        IRouteContext context, string? redbName,
        ILogger<WebhookDeliveryProcessor> logger)
    {
        _context = context;
        _redbName = redbName;
        _logger = logger;
    }

    /// <summary>
    /// Lazy producer template. Constructed on the first event so route-shape
    /// tests that pass a null context at Configure time don't trip
    /// ProducerTemplate's not-null guard.
    /// </summary>
    private IProducerTemplate GetProducer()
    {
        if (_producer is not null) return _producer;
        lock (_producerInitLock)
        {
            if (_producer is null)
            {
                var t = new redb.Route.Core.ProducerTemplate(_context);
                t.Start();
                _producer = t;
            }
        }
        return _producer;
    }

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        if (exchange.In.Body is not IdentityEvent evt)
            return;

        List<RedbObject<WebhookSubscriptionProps>> subscriptions;
        try
        {
            var redb = _context.GetRedbService(_redbName, exchange);
            var svc = new WebhookSubscriptionService(redb);
            subscriptions = await svc.ListEnabledAsync(ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "WebhookDelivery: failed to load subscriptions for event {EventType}; skipping delivery",
                evt.EventType);
            return;
        }

        if (subscriptions.Count == 0) return;

        var category = IdentityAuditEventIds.CategoryOf(evt.EventType);

        // Serialise the body ONCE — retries and parallel subscriptions reuse it.
        var jsonBody = JsonSerializer.Serialize(evt);
        var bodyBytes = Encoding.UTF8.GetBytes(jsonBody);

        foreach (var sub in subscriptions)
        {
            if (!WebhookSubscriptionService.Matches(sub.Props, evt.EventType, category)) continue;

            _ = Task.Run(() => DeliverAsync(sub.Id, sub.Props, evt, bodyBytes), CancellationToken.None);
        }
    }

    private async Task DeliverAsync(
        long subscriptionId,
        WebhookSubscriptionProps sub,
        IdentityEvent evt,
        byte[] bodyBytes)
    {
        var deliveryId = Guid.NewGuid().ToString("N");
        var timestamp = DateTimeOffset.UtcNow.ToString("O");
        // GitHub-style: signature covers the BODY only. Timestamp + Delivery
        // headers cover replay independently. Bytes-equal body is all anyone
        // needs to verify integrity.
        var signature = ComputeSignature(sub.HmacSecret, bodyBytes);

        Exception? lastException = null;

        for (var attempt = 1; attempt <= sub.MaxAttempts; attempt++)
        {
            try
            {
                var message = BuildMessage(sub, evt, bodyBytes, deliveryId, timestamp, signature, attempt);
                await GetProducer().SendAsync(sub.Url, message).ConfigureAwait(false);

                _logger.LogDebug(
                    "WebhookDelivery: {EventType} → {Url} attempt {Attempt}/{Max} delivered (delivery={Delivery})",
                    evt.EventType, sub.Url, attempt, sub.MaxAttempts, deliveryId);
                return;
            }
            catch (Exception ex)
            {
                lastException = ex;
                _logger.LogWarning(ex,
                    "WebhookDelivery: {EventType} → {Url} attempt {Attempt}/{Max} threw",
                    evt.EventType, sub.Url, attempt, sub.MaxAttempts);
            }

            if (attempt < sub.MaxAttempts)
            {
                var backoffMs = sub.RetryBackoffMs * Math.Pow(2, attempt - 1);
                await Task.Delay(TimeSpan.FromMilliseconds(Math.Min(backoffMs, 30_000))).ConfigureAwait(false);
            }
        }

        _logger.LogError(lastException,
            "WebhookDelivery: {EventType} → {Url} EXHAUSTED {Max} attempts delivery={Delivery}",
            evt.EventType, sub.Url, sub.MaxAttempts, deliveryId);
    }

    /// <summary>
    /// Compose the redb.Route message: bytes body + headers describing the
    /// envelope. The producer the URI resolves to copies header values onto
    /// the wire (HTTP request headers, AMQP application properties, …).
    /// </summary>
    private static IMessage BuildMessage(
        WebhookSubscriptionProps sub, IdentityEvent evt, byte[] bodyBytes,
        string deliveryId, string timestamp, string signature, int attempt)
    {
        var message = new Message(bodyBytes)
        {
            ContentType = "application/json"
        };
        // redb.Route HTTP producer reads this header to drive the request method.
        // Reserved redbHttp.* names are NOT bridged to the wire, so it never leaks
        // as an HTTP header on the receiver side.
        message.Headers["redbHttp.Method"] = "POST";
        message.Headers["X-RedbIdentity-Signature"] = $"sha256={signature}";
        message.Headers["X-RedbIdentity-Timestamp"] = timestamp;
        message.Headers["X-RedbIdentity-Delivery"] = deliveryId;
        message.Headers["X-RedbIdentity-EventType"] = evt.EventType;
        message.Headers["X-RedbIdentity-Attempt"] = attempt.ToString();

        if (sub.ExtraHeaders is { Count: > 0 } operatorHeaders)
        {
            foreach (var (k, v) in operatorHeaders)
            {
                // Reserved X-RedbIdentity-* headers always win.
                if (k.StartsWith("X-RedbIdentity-", StringComparison.OrdinalIgnoreCase)) continue;
                message.Headers[k] = v;
            }
        }
        return message;
    }

    private static string ComputeSignature(string secret, byte[] body)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        return Convert.ToHexString(hmac.ComputeHash(body)).ToLowerInvariant();
    }
}
