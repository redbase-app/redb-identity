using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Core;
using redb.Identity.Core.Configuration;

namespace redb.Identity.Core.OpenIddict;

/// <summary>
/// Application manager that adds RFC 8252 §7.3 loopback redirect handling on top of OpenIddict's
/// exact-match redirect validation.
/// <para>
/// <b>Why this class and not a server handler.</b> <c>ValidateRedirectUriAsync</c> is the single
/// point that decides whether a redirect_uri belongs to a client. OpenIddict's authorization
/// validation calls it, and so does our own error-redirect gate in
/// <c>RedbRouteOpenIddictServerHandler</c>, which must never bounce an error to an unregistered URI
/// (RFC 6749 §4.1.2.1). Widening the rule anywhere else would let those two answers diverge — the
/// request would be rejected as invalid while the error was still redirected to the attacker's URI,
/// which is precisely the open redirect we closed. One rule, one place.
/// </para>
/// </summary>
internal sealed class RedbApplicationManager<TApplication> : OpenIddictApplicationManager<TApplication>
    where TApplication : class
{
    private readonly RedbIdentityOptions _identityOptions;
    private readonly ILogger<RedbApplicationManager<TApplication>> _log;

    public RedbApplicationManager(
        IOpenIddictApplicationCache<TApplication> cache,
        ILogger<OpenIddictApplicationManager<TApplication>> logger,
        IOptionsMonitor<OpenIddictCoreOptions> options,
        IOpenIddictApplicationStoreResolver resolver,
        IOptions<RedbIdentityOptions> identityOptions,
        ILogger<RedbApplicationManager<TApplication>> log)
        : base(cache, logger, options, resolver)
    {
        _identityOptions = identityOptions.Value;
        _log = log;
    }

    /// <summary>
    /// Exact match first — unchanged OpenIddict behaviour, and the answer for every web client.
    /// Only if that fails do we consider the loopback rule, and only for a client that already
    /// registered a loopback redirect. A client registered at <c>https://app.example.com/cb</c> can
    /// never be talked into accepting <c>http://127.0.0.1:1234/cb</c>: it has no loopback URI to
    /// match against, so nothing widens.
    /// </summary>
    public override async ValueTask<bool> ValidateRedirectUriAsync(
        TApplication application, string uri, CancellationToken cancellationToken = default)
    {
        if (await base.ValidateRedirectUriAsync(application, uri, cancellationToken))
            return true;

        if (!_identityOptions.AllowLoopbackRedirectPortWildcard)
            return false;

        // RFC 8252 §7.3 — a native app cannot know its callback port in advance: it asks the OS for
        // an ephemeral one at launch, so the port differs on every run and cannot be registered.
        // The spec's answer is that the port, and ONLY the port, is not compared for loopback
        // redirects. This is what makes `az login`, `gh auth login` and every desktop OAuth client
        // work; without it they cannot use this provider at all.
        if (!TryParseLoopback(uri, out var requested))
            return false;

        var registeredUris = await GetRedirectUrisAsync(application, cancellationToken);
        foreach (var registered in registeredUris)
        {
            if (!TryParseLoopback(registered, out var candidate))
                continue;

            if (!MatchesIgnoringPort(candidate!, requested!))
                continue;

            _log.LogDebug(
                "Loopback redirect accepted per RFC 8252 §7.3: registered {Registered} matched {Requested} (port ignored)",
                registered, uri);
            return true;
        }

        return false;
    }

    /// <summary>
    /// Parses a URI and returns it only if it is a loopback redirect in the strict sense of
    /// RFC 8252 §7.3.
    /// <para>
    /// The host must be the IP literal <c>127.0.0.1</c> or <c>[::1]</c>. <b>"localhost" is
    /// deliberately excluded</b> — §8.3 warns against it: it is a name, so it goes through
    /// resolution, and a poisoned resolver or a hosts-file entry can point it somewhere that is not
    /// the loopback interface. Treating it as loopback would hand port-wildcarding to whatever that
    /// name resolves to. An app that wants the wildcard uses the IP literal, as the spec says.
    /// </para>
    /// <para>
    /// Userinfo (<c>user:pass@</c>) is rejected outright: it has no business in a redirect URI and
    /// is a classic way to make a URI read as one host while pointing at another.
    /// </para>
    /// </summary>
    private static bool TryParseLoopback(string? value, out Uri? uri)
    {
        uri = null;

        if (string.IsNullOrEmpty(value)) return false;
        if (!Uri.TryCreate(value, UriKind.Absolute, out var parsed)) return false;

        if (!string.IsNullOrEmpty(parsed.UserInfo)) return false;

        // The loopback IP literals, and nothing else. Uri normalises [::1] to "[::1]" in Host.
        var isLoopbackLiteral =
            string.Equals(parsed.Host, "127.0.0.1", StringComparison.Ordinal)
            || string.Equals(parsed.Host, "[::1]", StringComparison.Ordinal)
            || string.Equals(parsed.Host, "::1", StringComparison.Ordinal);

        if (!isLoopbackLiteral) return false;

        uri = parsed;
        return true;
    }

    /// <summary>
    /// Equality over everything except the port: scheme, host, path, query and fragment must all
    /// match exactly. §7.3 widens the port and nothing else, so a registration for
    /// <c>http://127.0.0.1/cb</c> does not authorise <c>http://127.0.0.1:5000/evil</c>.
    /// The scheme is compared too, so an <c>http</c> registration never authorises an <c>https</c>
    /// callback or vice versa.
    /// </summary>
    private static bool MatchesIgnoringPort(Uri registered, Uri requested) =>
        string.Equals(registered.Scheme, requested.Scheme, StringComparison.OrdinalIgnoreCase)
        && string.Equals(registered.Host, requested.Host, StringComparison.OrdinalIgnoreCase)
        && string.Equals(registered.AbsolutePath, requested.AbsolutePath, StringComparison.Ordinal)
        && string.Equals(registered.Query, requested.Query, StringComparison.Ordinal)
        && string.Equals(registered.Fragment, requested.Fragment, StringComparison.Ordinal);
}
