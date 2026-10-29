using Microsoft.Extensions.Options;
using redb.Identity.Client.Backchannel;
using redb.Identity.Web.Configuration;

namespace redb.Identity.Web.Services;

/// <summary>
/// W6-0 — periodically polls the Identity host's
/// <c>GET /api/v1/identity/revoked-sids/since</c> endpoint and merges new entries
/// into <see cref="IRevokedSidsCache"/>. Runs as a singleton background service on
/// every Web BFF replica so each replica converges to the same blacklist within
/// <see cref="RevokedSidsClientOptions.PollInterval"/>.
/// </summary>
public sealed class RevokedSidsPollHostedService : BackgroundService
{
    private readonly IBackchannelIdentityClient _client;
    private readonly IRevokedSidsCache _cache;
    private readonly IOptions<IdentityWebOptions> _opts;
    private readonly ILogger<RevokedSidsPollHostedService> _log;

    public RevokedSidsPollHostedService(
        IBackchannelIdentityClient client,
        IRevokedSidsCache cache,
        IOptions<IdentityWebOptions> opts,
        ILogger<RevokedSidsPollHostedService> log)
    {
        _client = client;
        _cache = cache;
        _opts = opts;
        _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        // The poll authenticates as a backchannel service account (client credentials). With no
        // configured secret it can never obtain a token, so every poll would fail and spam the log.
        // This is the cluster-wide backchannel-logout blacklist — not needed for a single-node trial
        // (the SQLite+HTTPS out-of-the-box default). Skip it entirely; set
        // Identity:BackchannelClient:ClientSecret (+ the host's matching seed secret) to enable it.
        if (string.IsNullOrWhiteSpace(_opts.Value.BackchannelClient.ClientSecret))
        {
            _log.LogInformation(
                "Revoked-SIDs backchannel poll disabled — no Identity:BackchannelClient:ClientSecret configured. " +
                "Set it (and the host's SeedBackchannelClient secret) to enable cluster-wide backchannel logout.");
            return;
        }

        var interval = _opts.Value.RevokedSids.PollInterval;
        if (interval <= TimeSpan.Zero) interval = TimeSpan.FromMinutes(1);

        try
        {
            // Bootstrap poll, without cursor: the server returns a baseline window. The Identity host
            // may still be starting (the full image starts it and this server together), so until the
            // first answer a host that does not answer at all is retried soon and logged as information,
            // not as a warning; any other failure is a warning from the first try.
            var retry = BootstrapRetry;
            while (!await PollOnceAsync(starting: true, retry, ct).ConfigureAwait(false))
            {
                await Task.Delay(retry, ct).ConfigureAwait(false);
                retry = TimeSpan.FromTicks(Math.Min(retry.Ticks * 2, interval.Ticks));
            }

            using var timer = new PeriodicTimer(interval);
            while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
            {
                await PollOnceAsync(starting: false, interval, ct).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown.
        }
    }

    /// <summary>The first retry while the Identity host is starting; doubled up to the poll interval.</summary>
    internal static readonly TimeSpan BootstrapRetry = TimeSpan.FromSeconds(2);

    /// <summary>One poll; false when it failed. <paramref name="next"/> is when the next try comes, for the log.</summary>
    private async Task<bool> PollOnceAsync(bool starting, TimeSpan next, CancellationToken ct)
    {
        try
        {
            var resp = await _client.GetRevokedSidsSinceAsync(_cache.Cursor, ct).ConfigureAwait(false);
            _cache.Apply(resp.Entries);
            _cache.SetCursor(resp.NextCursor);

            if (resp.Entries.Count > 0)
            {
                _log.LogInformation(
                    "Revoked-SIDs poll: applied {Count} entries, next cursor {Cursor:O}",
                    resp.Entries.Count, resp.NextCursor);
            }
            return true;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            // Log a concise, actionable reason — NOT a stack trace. Typical causes: the Identity
            // host isn't up yet (startup), it's unreachable, or the backchannel secret is missing/
            // mismatched. The full exception is available at Debug for anyone who needs it.
            var reason = (ex.InnerException ?? ex).Message;
            if (starting && IsUnreachable(ex))
            {
                _log.LogInformation(
                    "Revoked-SIDs poll: Identity host {Host} not reachable yet ({Reason}); next try in {Next}.",
                    _opts.Value.ApiBaseUrl, reason, next);
            }
            else
            {
                _log.LogWarning(
                    "Revoked-SIDs poll skipped: {Reason} (Identity host {Host}). Retrying in {Interval}.",
                    reason, _opts.Value.ApiBaseUrl, next);
            }
            _log.LogDebug(ex, "Revoked-SIDs poll exception detail");
            return false;
        }
    }

    /// <summary>
    /// The host gave no HTTP answer at all (connection refused, name not resolved, TLS not up):
    /// what a host that is still starting looks like. An HTTP status, a refused secret included,
    /// is an answer and never counts as this.
    /// </summary>
    internal static bool IsUnreachable(Exception ex) =>
        ex is HttpRequestException { StatusCode: null } || ex.InnerException is HttpRequestException { StatusCode: null };
}
