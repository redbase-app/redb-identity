using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using redb.Identity.Contracts.Routes;
using redb.Identity.Core.Configuration;
using redb.Route.Abstractions;
using redb.Route.Core;

namespace redb.Identity.Core.Services;

/// <summary>
/// N-4 (Session C): production <see cref="IEmailNotificationChannel"/> backed by the
/// redb.Route.Mail SMTP DSL. Renders the requested template through
/// <see cref="IEmailTemplateRegistry"/> and forwards the resulting message to
/// <see cref="IdentityEndpoints.EmailSend"/>, which the host route builder wires to a
/// <c>Smtp.Send(...)</c> producer when <see cref="SmtpOptions.Enabled"/> is <c>true</c>.
/// <para>
/// The channel only knows about route URIs and exchange headers — concrete SMTP details
/// (host / port / credentials / TLS) live entirely on the route definition, exactly as
/// the rest of the redb.Route ecosystem expects. This keeps the abstraction transport-
/// agnostic: swapping SMTP for SendGrid is a route change, not a channel change.
/// </para>
/// </summary>
public sealed class SmtpEmailNotificationChannel : IEmailNotificationChannel, IDisposable
{
    private readonly IRouteContext _routeContext;
    private readonly IEmailTemplateRegistry _registry;
    private readonly SmtpOptions _smtp;
    private readonly ILogger _logger;
    private readonly object _producerLock = new();
    private IProducerTemplate? _producer;
    private bool _disposed;

    public SmtpEmailNotificationChannel(
        IRouteContext routeContext,
        IEmailTemplateRegistry registry,
        IOptions<RedbIdentityOptions> options,
        ILoggerFactory? loggerFactory = null)
    {
        _routeContext = routeContext ?? throw new ArgumentNullException(nameof(routeContext));
        _registry = registry ?? throw new ArgumentNullException(nameof(registry));
        _smtp = options.Value.Smtp;
        _logger = loggerFactory?.CreateLogger<SmtpEmailNotificationChannel>() ?? (ILogger)NullLogger<SmtpEmailNotificationChannel>.Instance;
    }

    /// <inheritdoc />
    public async Task SendTemplateAsync(
        string to,
        string templateId,
        IReadOnlyDictionary<string, string> vars,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(to);
        ArgumentException.ThrowIfNullOrWhiteSpace(templateId);
        ArgumentNullException.ThrowIfNull(vars);

        // Render the template using the host-supplied registry. Locale negotiation lives
        // there; this channel only forwards the rendered output to the SMTP route.
        var rendered = await _registry.RenderAsync(templateId, locale: null, vars, ct).ConfigureAwait(false);

        var message = new Message
        {
            Body = rendered.HtmlBody ?? rendered.TextBody ?? string.Empty
        };
        message.Headers["redbMail.To"] = to;
        message.Headers["redbMail.Subject"] = rendered.Subject ?? string.Empty;
        if (!string.IsNullOrWhiteSpace(_smtp.FromAddress))
            message.Headers["redbMail.From"] = _smtp.FromAddress;
        // Force the SMTP component to treat the body as HTML and use TextBody as the
        // plain-text alternative — see redb.Route.Mail.SmtpComponent.BuildMimeMessage.
        message.Headers["redbMail.ContentType"] = "text/html";
        if (!string.IsNullOrWhiteSpace(rendered.TextBody))
            message.Headers["redbMail.TextBody"] = rendered.TextBody!;

        var producer = EnsureProducer();
        try
        {
            await producer.SendAsync(IdentityEndpoints.EmailSend, message).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            // Mirrors PasswordForgotProcessor's expectation that channel implementations
            // surface fatal issues but absorb transient ones. We log + rethrow so the
            // processor can keep the anti-enumeration contract (it catches and degrades).
            _logger.LogError(ex,
                "SmtpEmailNotificationChannel: send via {Endpoint} failed for {To} / {TemplateId}",
                IdentityEndpoints.EmailSend, to, templateId);
            throw;
        }
    }

    private IProducerTemplate EnsureProducer()
    {
        if (_producer is { IsStarted: true }) return _producer;
        lock (_producerLock)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(SmtpEmailNotificationChannel));
            if (_producer is { IsStarted: true }) return _producer;
            var p = new ProducerTemplate(_routeContext);
            p.Start();
            _producer = p;
            return _producer;
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        lock (_producerLock)
        {
            if (_disposed) return;
            _disposed = true;
            (_producer as IDisposable)?.Dispose();
            _producer = null;
        }
    }
}
