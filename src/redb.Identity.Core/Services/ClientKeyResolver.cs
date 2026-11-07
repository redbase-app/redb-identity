using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Tokens;
using redb.Core.Models.Entities;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Models;

namespace redb.Identity.Core.Services;

/// <summary>
/// Default <see cref="IClientKeyResolver"/>: inline JWKS first, then a cached fetch of the
/// client's <c>jwks_uri</c>.
/// <para>
/// Caching is delegated to <see cref="ConfigurationManager{T}"/> (the same primitive
/// <c>OidcFederatedAuthProvider</c> uses for federated OPs), one instance per URL: it keeps the
/// document, refreshes it in the background on <see cref="ClientKeysOptions.CacheLifetime"/>, and
/// rate-limits forced refreshes by <see cref="ClientKeysOptions.MinimumRefreshInterval"/>.
/// </para>
/// </summary>
internal sealed class ClientKeyResolver : IClientKeyResolver
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ClientKeysOptions _options;
    private readonly ILogger<ClientKeyResolver> _logger;

    /// <summary>One manager per <c>jwks_uri</c>; they hold the cached document, so they must live
    /// as long as this singleton rather than being rebuilt per request.</summary>
    private readonly ConcurrentDictionary<string, ConfigurationManager<JsonWebKeySet>> _managers = new(StringComparer.Ordinal);

    public ClientKeyResolver(
        IHttpClientFactory httpClientFactory,
        IOptions<RedbIdentityOptions> identityOptions,
        ILogger<ClientKeyResolver> logger)
    {
        _httpClientFactory = httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));
        _options = identityOptions?.Value?.ClientKeys ?? throw new ArgumentNullException(nameof(identityOptions));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async ValueTask<IReadOnlyCollection<SecurityKey>> GetSigningKeysAsync(
        RedbObject<ApplicationProps> application,
        bool forceRefresh = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(application);

        // Inline wins: operator-controlled and needs no network call. Matches the contract
        // documented on ApplicationProps.JwksUri ("prefers inline (cached) over endpoint").
        // A CONFIGURED inline set is final even when it yields nothing — falling back to
        // jwks_uri would hide a typo behind a working login. Only "not configured at all"
        // continues to the endpoint.
        var inline = ReadInlineKeys(application);
        if (inline is not null) return inline;

        var jwksUri = application.Props.JwksUri;
        if (string.IsNullOrWhiteSpace(jwksUri)) return [];

        return await FetchKeysAsync(jwksUri, application, forceRefresh, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Reads the inline JWKS. Returns <see langword="null"/> when the client has <b>no</b> inline
    /// set configured (the caller may then try <c>jwks_uri</c>), and a — possibly empty —
    /// collection when one <b>is</b> configured. The distinction is deliberate: an empty result
    /// from a configured-but-broken set must stop the lookup, not silently reroute it.
    /// </summary>
    private IReadOnlyCollection<SecurityKey>? ReadInlineKeys(RedbObject<ApplicationProps> application)
    {
        var json = application.Props.JsonWebKeySet;
        if (string.IsNullOrWhiteSpace(json)) return null;

        try
        {
            var set = JsonWebKeySet.Create(json);
            // Copy: the caller must not be able to mutate a set we may hand out again.
            return set.GetSigningKeys().ToArray();
        }
        catch (Exception e)
        {
            // A malformed inline JWKS is an operator error on this client only — log it and let
            // the caller treat the client as having no usable keys.
            _logger.LogWarning(
                e,
                "Client {ClientId} has an unparseable inline JWKS; treating it as having no keys.",
                application.Props.ClientId);
            return [];
        }
    }

    private async ValueTask<IReadOnlyCollection<SecurityKey>> FetchKeysAsync(
        string jwksUri,
        RedbObject<ApplicationProps> application,
        bool forceRefresh,
        CancellationToken cancellationToken)
    {
        var rejection = await OutboundUrlGuard.ValidateAsync(
            jwksUri,
            _options.RequireHttps,
            _options.AllowPrivateNetworkTargets,
            cancellationToken).ConfigureAwait(false);

        if (rejection != OutboundUrlGuard.Rejection.None)
        {
            // Refused before any socket is opened: the URL came from the client record, so an
            // internal target here is an SSRF attempt or a misconfiguration — never a fetch.
            _logger.LogWarning(
                "Refusing to fetch jwks_uri for client {ClientId}: {Reason}.",
                application.Props.ClientId,
                OutboundUrlGuard.Describe(rejection));
            return [];
        }

        var manager = _managers.GetOrAdd(jwksUri, CreateManager);

        try
        {
            if (forceRefresh) manager.RequestRefresh();

            var set = await manager.GetConfigurationAsync(cancellationToken).ConfigureAwait(false);
            // Copy: the ConfigurationManager keeps this instance cached and reuses it.
            return set?.GetSigningKeys().ToArray() ?? [];
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            // Unreachable or malformed endpoint: no keys, hence no verification, hence the caller
            // rejects the request. Failing closed is the point — never treat "could not check" as valid.
            _logger.LogWarning(
                e,
                "Failed to fetch JWKS for client {ClientId} from {JwksUri}.",
                application.Props.ClientId,
                jwksUri);
            return [];
        }
    }

    private ConfigurationManager<JsonWebKeySet> CreateManager(string jwksUri)
    {
        var http = _httpClientFactory.CreateClient(HttpClientName);
        http.Timeout = _options.FetchTimeout;
        // Caps the buffered body so a hostile endpoint cannot stream an unbounded response at us.
        http.MaxResponseContentBufferSize = _options.MaxDocumentBytes;

        var documentRetriever = new HttpDocumentRetriever(http)
        {
            // Our own guard already enforces the scheme (and knows about the dev override), so
            // this stays off to avoid a second, less informative rejection path.
            RequireHttps = false,
        };

        return new ConfigurationManager<JsonWebKeySet>(jwksUri, new JwksRetriever(), documentRetriever)
        {
            AutomaticRefreshInterval = _options.CacheLifetime,
            RefreshInterval = _options.MinimumRefreshInterval,
        };
    }

    /// <summary>Named <see cref="HttpClient"/> used for client JWKS fetches.</summary>
    internal const string HttpClientName = "redb-identity-client-keys";

    /// <summary>
    /// Minimal <see cref="IConfigurationRetriever{T}"/> for a bare JWKS document.
    /// Microsoft.IdentityModel ships one for OIDC discovery documents but not for a plain key set.
    /// </summary>
    private sealed class JwksRetriever : IConfigurationRetriever<JsonWebKeySet>
    {
        public async Task<JsonWebKeySet> GetConfigurationAsync(
            string address, IDocumentRetriever retriever, CancellationToken cancel)
        {
            var document = await retriever.GetDocumentAsync(address, cancel).ConfigureAwait(false);
            return JsonWebKeySet.Create(document);
        }
    }
}
