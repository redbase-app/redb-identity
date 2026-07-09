using System.Net.Http.Headers;
using Microsoft.Extensions.Logging;
using redb.Core;
using redb.Identity.Core.Models;

namespace redb.Identity.Core.Services;

/// <summary>
/// Sends OIDC Back-Channel Logout 1.0 notifications to relying parties after a successful
/// logout. For each application that the user had active authorizations with AND that has
/// a <see cref="ApplicationProps.BackchannelLogoutUri"/> configured, POSTs a signed
/// <c>logout_token</c> to that URL.
///
/// <para>
/// Delivery is best-effort: failures are logged + emitted as an audit event, but do not
/// fail the logout operation. Persistent retry / DLQ should be handled by Multicast'ing
/// the audit event to a durable transport (RabbitMQ / Kafka) — see
/// <c>IdentityAuditOptions.Targets</c>.
/// </para>
/// </summary>
public sealed class BackchannelLogoutDispatcher
{
    private const string HttpClientName = "redb-identity-backchannel-logout";

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly LogoutTokenBuilder _tokenBuilder;
    private readonly ILogger<BackchannelLogoutDispatcher>? _logger;

    public BackchannelLogoutDispatcher(
        IHttpClientFactory httpClientFactory,
        LogoutTokenBuilder tokenBuilder,
        ILogger<BackchannelLogoutDispatcher>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(httpClientFactory);
        ArgumentNullException.ThrowIfNull(tokenBuilder);
        _httpClientFactory = httpClientFactory;
        _tokenBuilder = tokenBuilder;
        _logger = logger;
    }

    /// <summary>
    /// Sends logout_token POSTs for every distinct RP affected by a logout.
    /// </summary>
    /// <param name="redb">redb service for loading application records.</param>
    /// <param name="userId">End-user id (becomes <c>sub</c>).</param>
    /// <param name="sessionId">
    /// When &gt; 0 and the application opted into <c>BackchannelLogoutSessionRequired</c>,
    /// this becomes the <c>sid</c> claim.
    /// </param>
    /// <param name="applicationObjectIds">
    /// Distinct application object ids that the user had non-revoked authorizations with
    /// before this logout. Caller must collect them BEFORE revoking.
    /// </param>
    /// <returns>The number of POSTs successfully delivered (HTTP 2xx).</returns>
    public async Task<int> DispatchAsync(
        IRedbService redb,
        long userId,
        long sessionId,
        IReadOnlyCollection<long> applicationObjectIds,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(redb);
        ArgumentNullException.ThrowIfNull(applicationObjectIds);

        if (applicationObjectIds.Count == 0)
            return 0;

        if (!_tokenBuilder.CanIssue)
        {
            _logger?.LogDebug("LogoutTokenBuilder.CanIssue=false — skipping backchannel dispatch.");
            return 0;
        }

        var subject = userId.ToString(System.Globalization.CultureInfo.InvariantCulture);
        var sid = sessionId > 0 ? sessionId.ToString(System.Globalization.CultureInfo.InvariantCulture) : null;
        var http = _httpClientFactory.CreateClient(HttpClientName);
        if (http.Timeout == Timeout.InfiniteTimeSpan)
            http.Timeout = TimeSpan.FromSeconds(10);

        // Batch-load every distinct ApplicationProps in ONE query rather than per-id LoadAsync.
        // A user with many active client sessions otherwise turned this fan-out into an O(N)
        // round-trip storm before the HTTP fan-out even started.
        var distinctIds = applicationObjectIds.Where(i => i > 0).Distinct().ToArray();
        if (distinctIds.Length == 0)
            return 0;

        var apps = await redb.Query<ApplicationProps>()
            .WhereInRedb(o => o.Id, distinctIds)
            .ToListAsync()
            .ConfigureAwait(false);

        var delivered = 0;
        foreach (var loaded in apps)
        {
            // Hydrate copies _objects.value_string -> Props.ClientId (ClientId is [RedbIgnore]).
            var app = loaded.Hydrate();
            var props = app.Props;
            if (string.IsNullOrEmpty(props.BackchannelLogoutUri) || string.IsNullOrEmpty(props.ClientId))
                continue;

            var includeSid = props.BackchannelLogoutSessionRequired && sid is not null;
            var token = _tokenBuilder.Build(props.ClientId, subject, includeSid ? sid : null);
            if (token is null)
                continue;

            try
            {
                using var content = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("logout_token", token)
                });
                content.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");

                using var response = await http.PostAsync(props.BackchannelLogoutUri, content, ct).ConfigureAwait(false);
                if (response.IsSuccessStatusCode)
                {
                    delivered++;
                    _logger?.LogDebug("Backchannel logout delivered to {ClientId} ({Status}).",
                        props.ClientId, (int)response.StatusCode);
                }
                else
                {
                    _logger?.LogWarning("Backchannel logout to {ClientId} returned {Status}.",
                        props.ClientId, (int)response.StatusCode);
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
            {
                // Best-effort delivery: never let an RP outage break the logout flow.
                _logger?.LogWarning(ex, "Backchannel logout to {ClientId} ({Uri}) failed.",
                    props.ClientId, props.BackchannelLogoutUri);
            }
        }

        return delivered;
    }
}
