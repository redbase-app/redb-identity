using System.Security.Cryptography;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Identity.Core.Models;

namespace redb.Identity.Core.Services;

/// <summary>
/// W1 — backing store for outbound webhook subscriptions. CRUD + filter
/// evaluation + secret generation / rotation. The HTTP delivery is the
/// route consumer's job (<c>WebhookDeliveryRouteConsumer</c>); this
/// service is admin-side only.
/// </summary>
public sealed class WebhookSubscriptionService
{
    private readonly IRedbService _redb;

    public WebhookSubscriptionService(IRedbService redb) => _redb = redb;

    public async Task<RedbObject<WebhookSubscriptionProps>> CreateAsync(
        string url, string? displayName, string? description,
        string? eventTypeFilter, bool enabled, int timeoutMs, int maxAttempts, int retryBackoffMs,
        Dictionary<string, string>? extraHeaders,
        string? hmacSecret = null,
        CancellationToken ct = default)
    {
        var (urlErr, normalisedUrl) = ValidateUrl(url);
        if (urlErr is not null) throw new ArgumentException(urlErr, nameof(url));

        // Operator-supplied secret takes precedence; auto-generate when blank.
        // Enforce a minimum length to keep weak secrets out of the store.
        string secret;
        if (!string.IsNullOrWhiteSpace(hmacSecret))
        {
            if (hmacSecret.Length < 16)
                throw new ArgumentException("hmacSecret must be at least 16 characters.", nameof(hmacSecret));
            secret = hmacSecret;
        }
        else
        {
            secret = GenerateHmacSecret();
        }

        var obj = new RedbObject<WebhookSubscriptionProps>(new WebhookSubscriptionProps
        {
            DisplayName = string.IsNullOrWhiteSpace(displayName) ? null : displayName.Trim(),
            Description = description,
            Url = normalisedUrl,
            EventTypeFilter = string.IsNullOrWhiteSpace(eventTypeFilter) ? "*" : eventTypeFilter.Trim(),
            HmacSecret = secret,
            Enabled = enabled,
            TimeoutMs = Math.Clamp(timeoutMs, 500, 60_000),
            MaxAttempts = Math.Clamp(maxAttempts, 1, 10),
            RetryBackoffMs = Math.Clamp(retryBackoffMs, 50, 30_000),
            ExtraHeaders = extraHeaders,
            ConcurrencyToken = Guid.NewGuid().ToString("N")
        })
        {
            name = displayName ?? new Uri(normalisedUrl).Host
        };
        obj.id = await _redb.SaveAsync(obj).ConfigureAwait(false);
        return obj;
    }

    public async Task<RedbObject<WebhookSubscriptionProps>?> GetAsync(long id, CancellationToken ct = default)
        => await _redb.LoadAsync<WebhookSubscriptionProps>(id).ConfigureAwait(false);

    public async Task<List<RedbObject<WebhookSubscriptionProps>>> ListAsync(int offset, int count, CancellationToken ct = default)
    {
        return await _redb.Query<WebhookSubscriptionProps>()
            .OrderByRedb(o => o.Id)
            .Skip(offset)
            .Take(count)
            .ToListAsync()
            .ConfigureAwait(false);
    }

    public async Task<int> CountAsync(CancellationToken ct = default)
        => (int)await _redb.Query<WebhookSubscriptionProps>().CountAsync().ConfigureAwait(false);

    /// <summary>
    /// Bulk-load every enabled subscription. Called once per event by the
    /// delivery consumer — for the worst case of a heavy operator wiring
    /// dozens of subscriptions this is still a single round-trip per
    /// event, beating per-subscription evaluation. Higher cardinalities
    /// should grow a small in-memory cache; not warranted at preview.1.
    /// </summary>
    public async Task<List<RedbObject<WebhookSubscriptionProps>>> ListEnabledAsync(CancellationToken ct = default)
    {
        return await _redb.Query<WebhookSubscriptionProps>()
            .Where(p => p.Enabled == true)
            .ToListAsync()
            .ConfigureAwait(false);
    }

    public async Task UpdateAsync(
        long id,
        string? displayName, string? description, string? url, string? eventTypeFilter,
        bool? enabled, int? timeoutMs, int? maxAttempts, int? retryBackoffMs,
        Dictionary<string, string>? extraHeaders,
        CancellationToken ct = default)
    {
        var obj = await _redb.LoadAsync<WebhookSubscriptionProps>(id).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Webhook subscription {id} not found.");

        if (displayName is not null) obj.Props.DisplayName = string.IsNullOrWhiteSpace(displayName) ? null : displayName.Trim();
        if (description is not null) obj.Props.Description = description;
        if (url is not null)
        {
            var (urlErr, normalised) = ValidateUrl(url);
            if (urlErr is not null) throw new ArgumentException(urlErr, nameof(url));
            obj.Props.Url = normalised;
        }
        if (eventTypeFilter is not null) obj.Props.EventTypeFilter = string.IsNullOrWhiteSpace(eventTypeFilter) ? "*" : eventTypeFilter.Trim();
        if (enabled.HasValue) obj.Props.Enabled = enabled.Value;
        if (timeoutMs.HasValue) obj.Props.TimeoutMs = Math.Clamp(timeoutMs.Value, 500, 60_000);
        if (maxAttempts.HasValue) obj.Props.MaxAttempts = Math.Clamp(maxAttempts.Value, 1, 10);
        if (retryBackoffMs.HasValue) obj.Props.RetryBackoffMs = Math.Clamp(retryBackoffMs.Value, 50, 30_000);
        if (extraHeaders is not null) obj.Props.ExtraHeaders = extraHeaders;
        obj.Props.ConcurrencyToken = Guid.NewGuid().ToString("N");

        await _redb.SaveAsync(obj).ConfigureAwait(false);
    }

    public async Task DeleteAsync(long id, CancellationToken ct = default)
    {
        var obj = await _redb.LoadAsync<WebhookSubscriptionProps>(id).ConfigureAwait(false);
        if (obj is null) return;
        await _redb.DeleteAsync(obj).ConfigureAwait(false);
    }

    /// <summary>
    /// Generate a fresh secret, update the row, return the new value. The
    /// previous value is irrecoverable after this — receivers MUST be
    /// updated atomically.
    /// </summary>
    public async Task<string> RotateSecretAsync(long id, CancellationToken ct = default)
    {
        var obj = await _redb.LoadAsync<WebhookSubscriptionProps>(id).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"Webhook subscription {id} not found.");
        var newSecret = GenerateHmacSecret();
        obj.Props.HmacSecret = newSecret;
        obj.Props.ConcurrencyToken = Guid.NewGuid().ToString("N");
        await _redb.SaveAsync(obj).ConfigureAwait(false);
        return newSecret;
    }

    /// <summary>
    /// True when the subscription should receive the given event id /
    /// category pair. Public so the delivery consumer can call directly.
    /// </summary>
    public static bool Matches(WebhookSubscriptionProps sub, string eventType, string? category)
    {
        if (!sub.Enabled) return false;
        var filter = sub.EventTypeFilter?.Trim();
        if (string.IsNullOrEmpty(filter) || filter == "*") return true;

        var tokens = filter.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        foreach (var token in tokens)
        {
            if (token.StartsWith("cat:", StringComparison.OrdinalIgnoreCase))
            {
                var wantedCategory = token.Substring(4);
                if (!string.IsNullOrEmpty(category)
                    && string.Equals(category, wantedCategory, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            else
            {
                if (string.Equals(eventType, token, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }
        return false;
    }

    // ── Helpers ────────────────────────────────────────────────

    private static (string? Error, string Normalised) ValidateUrl(string url)
    {
        if (string.IsNullOrWhiteSpace(url)) return ("url is required", "");
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u))
            return ("url must be an absolute http(s) URL", url);
        if (u.Scheme != Uri.UriSchemeHttp && u.Scheme != Uri.UriSchemeHttps)
            return ("url scheme must be http or https", url);
        if (!string.IsNullOrEmpty(u.Fragment))
            return ("url fragment is not allowed", url);
        return (null, u.ToString());
    }

    private static string GenerateHmacSecret()
    {
        var bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToHexString(bytes);
    }
}
