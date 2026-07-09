using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace redb.Identity.Core.Services;

/// <summary>
/// N-4 (Session C): test / preview implementation of
/// <see cref="IEmailNotificationChannel"/>. Captures every dispatched message in an
/// in-memory ring (default cap = 256 messages) instead of sending it out. Used in
/// integration tests to assert that the right templated e-mail reached the right
/// recipient with the right variables.
/// </summary>
/// <remarks>
/// Production hosts MUST replace this with a real SMTP / SendGrid / SES channel.
/// Registering this singleton in production silently swallows every notification.
/// </remarks>
public sealed class InMemoryEmailNotificationChannel : IEmailNotificationChannel
{
    private readonly IEmailTemplateRegistry _registry;
    private readonly int _capacity;
    private readonly ConcurrentQueue<CapturedEmail> _messages = new();

    public InMemoryEmailNotificationChannel(IEmailTemplateRegistry registry, int capacity = 256)
    {
        _registry = registry ?? throw new ArgumentNullException(nameof(registry));
        if (capacity <= 0) throw new ArgumentOutOfRangeException(nameof(capacity));
        _capacity = capacity;
    }

    /// <summary>Snapshot of all messages captured so far, oldest first.</summary>
    public IReadOnlyList<CapturedEmail> Messages => _messages.ToArray();

    /// <summary>All messages directed at the given recipient (case-insensitive match).</summary>
    public IReadOnlyList<CapturedEmail> ForRecipient(string to) =>
        _messages.Where(m => string.Equals(m.To, to, StringComparison.OrdinalIgnoreCase)).ToArray();

    /// <summary>Drops all captured messages.</summary>
    public void Clear()
    {
        while (_messages.TryDequeue(out _)) { }
    }

    public async Task SendTemplateAsync(
        string to,
        string templateId,
        IReadOnlyDictionary<string, string> vars,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(to)) throw new ArgumentException("recipient required", nameof(to));
        var rendered = await _registry.RenderAsync(templateId, locale: null, vars, ct).ConfigureAwait(false);
        _messages.Enqueue(new CapturedEmail
        {
            To = to,
            TemplateId = templateId,
            Subject = rendered.Subject,
            HtmlBody = rendered.HtmlBody,
            TextBody = rendered.TextBody,
            Vars = vars.ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.Ordinal),
            SentAt = DateTimeOffset.UtcNow,
        });
        // Cap the ring so misconfigured tests don't leak memory across the whole suite.
        while (_messages.Count > _capacity && _messages.TryDequeue(out _)) { }
    }
}

/// <summary>Snapshot of a single e-mail captured by <see cref="InMemoryEmailNotificationChannel"/>.</summary>
public sealed class CapturedEmail
{
    public required string To { get; init; }
    public required string TemplateId { get; init; }
    public required string Subject { get; init; }
    public required string HtmlBody { get; init; }
    public string? TextBody { get; init; }
    public required Dictionary<string, string> Vars { get; init; }
    public DateTimeOffset SentAt { get; init; }
}
