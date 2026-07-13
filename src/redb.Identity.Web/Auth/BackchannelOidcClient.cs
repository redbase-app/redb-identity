using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;

namespace redb.Identity.Web.Auth;

/// <summary>
/// Outcome of <see cref="BackchannelOidcClient.LoginAsync"/>.
/// </summary>
public sealed record BackchannelLoginResult(
    bool Success,
    ClaimsPrincipal? Principal,
    string? AccessToken,
    string? RefreshToken,
    string? IdToken,
    DateTimeOffset? ExpiresAt,
    string? Error,
    string? ErrorDescription,
    bool MfaRequired = false,
    MfaInFlightState? MfaState = null,
    bool ConsentRequired = false,
    ConsentInFlightState? ConsentState = null);

/// <summary>
/// Outcome of <see cref="BackchannelOidcClient.VerifyDeviceCodeAsync"/>.
/// </summary>
public sealed record DeviceVerifyResult(bool Success, string? Error, string? ErrorDescription);

/// <summary>
/// BFF-side OIDC client that drives the entire authorization-code + PKCE flow against
/// the Identity host using a server-side <see cref="HttpClient"/>. The browser never
/// touches the host directly — only the BFF does.
///
/// Sequence:
///   1. Generate PKCE verifier/challenge, state, nonce.
///   2. POST host <c>/login</c> with username/password — receive session cookie.
///   3. GET host <c>/connect/authorize</c> carrying that cookie — receive 302 with <c>?code=...</c>.
///   4. POST host <c>/connect/token</c> with code + verifier — receive tokens.
///   5. Validate id_token, fetch userinfo, build ClaimsPrincipal.
/// </summary>
public sealed class BackchannelOidcClient
{
    private readonly HttpClient _http;
    private readonly BackchannelOidcOptions _opts;
    private readonly IConfigurationManager<OpenIdConnectConfiguration> _discovery;
    private readonly ILogger<BackchannelOidcClient> _log;

    public BackchannelOidcClient(
        HttpClient http,
        IOptions<BackchannelOidcOptions> opts,
        IConfigurationManager<OpenIdConnectConfiguration> discovery,
        ILogger<BackchannelOidcClient> log)
    {
        _http = http;
        _opts = opts.Value;
        _discovery = discovery;
        _log = log;
    }

    /// <summary>
    /// Handler for the session HttpClients this class builds by hand (manual cookie handling, no
    /// auto-redirect). These bypass IHttpClientFactory, so the accept-any-cert primary handler
    /// registered app-wide in Program.cs does NOT apply — carry the dev flag through here, or the
    /// host's bundled self-signed cert fails login with "UntrustedRoot".
    /// </summary>
    private HttpClientHandler CreateSessionHandler() => new()
    {
        UseCookies = false,
        AllowAutoRedirect = false,
        ServerCertificateCustomValidationCallback = _opts.AcceptAnyServerCert
            ? HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
            : null,
    };

    public async Task<BackchannelLoginResult> LoginAsync(
        string username, string password, CancellationToken ct = default)
    {
        OpenIdConnectConfiguration config;
        try
        {
            config = await _discovery.GetConfigurationAsync(ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "OIDC discovery failed for {Authority}", _opts.Authority);
            return Fail("oidc_discovery_failed", "Identity provider discovery failed.");
        }

        var (verifier, challenge) = GeneratePkce();
        var state = RandomToken(32);
        var nonce = RandomToken(32);

        // Reconstruct the original /connect/authorize URL — same shape we'd use
        // if we redirected the browser through the standard flow.
        var authorizeUrl = BuildAuthorizeUrl(config.AuthorizationEndpoint, state, nonce, challenge);

        // Step 1: POST /login. Response is 302 (Location=returnUrl) + Set-Cookie session.
        // We do NOT use HttpClient's CookieContainer because the host may set the cookie
        // with the Secure flag while we're talking to it over plain http (dev): the
        // container then silently drops the cookie. Instead we parse Set-Cookie headers
        // ourselves and forward NAME=VALUE on subsequent requests.
        using var handler = CreateSessionHandler();
        using var sessionHttp = new HttpClient(handler) { BaseAddress = _http.BaseAddress };
        var hostCookies = new Dictionary<string, string>(StringComparer.Ordinal);

        var loginForm = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("username", username),
            new KeyValuePair<string, string>("password", password),
            // Use the relative form so the host echoes it back as Location;
            // we only care about the host setting the session cookie here.
            new KeyValuePair<string, string>("returnUrl", "/"),
        });

        var loginResp = await sessionHttp.PostAsync("/login", loginForm, ct).ConfigureAwait(false);
        CollectCookies(loginResp, hostCookies);
        // Expected outcomes:
        //   302 + Set-Cookie redb.identity.session=... → success
        //   200 (HTML form re-render with error)        → bad credentials
        //   302 to MFA path                              → MFA required
        //   429 + JSON {error:"rate_limited"}            → throttled
        if (loginResp.StatusCode == (HttpStatusCode)429)
        {
            var retryAfter = loginResp.Headers.RetryAfter?.Delta?.TotalSeconds
                          ?? loginResp.Headers.RetryAfter?.Date?.Subtract(DateTimeOffset.UtcNow).TotalSeconds;
            return Fail("rate_limited", $"Too many sign-in attempts. Retry in {retryAfter ?? 60:F0}s.");
        }
        if (loginResp.StatusCode != HttpStatusCode.Found && loginResp.StatusCode != HttpStatusCode.SeeOther)
        {
            var body = await SafeReadAsync(loginResp, ct).ConfigureAwait(false);
            _log.LogWarning(
                "Host /login returned {Status} (expected 302). Body preview: {Body}",
                (int)loginResp.StatusCode,
                body.Length > 400 ? body[..400] + "..." : body);
            // Re-rendered login form means the credential check failed.
            return Fail("invalid_credentials", "Username or password is incorrect.");
        }

        var location = loginResp.Headers.Location?.OriginalString ?? "";
        if (location.Contains("/mfa", StringComparison.OrdinalIgnoreCase))
        {
            // Host requires MFA: it has set the encrypted __Host-redb.identity.mfa cookie.
            // Capture every cookie the host issued (state cookie + any preliminary session
            // cookies) so we can post the verification back with the full jar attached.
            var mfaCookieHeader = BuildCookieHeader(hostCookies);
            if (string.IsNullOrEmpty(mfaCookieHeader))
            {
                _log.LogWarning("MFA redirect carried no cookies; cannot continue challenge.");
                return Fail("mfa_no_state", "Multi-factor challenge could not be initialised.");
            }

            var mfaPath = location.StartsWith("http", StringComparison.OrdinalIgnoreCase)
                ? new Uri(location).PathAndQuery
                : location;

            var inflight = new MfaInFlightState(
                HostMfaStateCookie: mfaCookieHeader,
                MfaPath: mfaPath,
                AuthorizeUrl: authorizeUrl,
                Verifier: verifier,
                State: state,
                Nonce: nonce,
                ReturnUrl: null,
                IssuedAt: DateTimeOffset.UtcNow);

            return new BackchannelLoginResult(
                Success: false,
                Principal: null,
                AccessToken: null,
                RefreshToken: null,
                IdToken: null,
                ExpiresAt: null,
                Error: "mfa_required",
                ErrorDescription: "Multi-factor verification required.",
                MfaRequired: true,
                MfaState: inflight);
        }

        // Look for either the bare or __Host- prefixed name.
        if (!hostCookies.Keys.Any(k =>
                k.Equals("redb.identity.session", StringComparison.Ordinal)
                || k.Equals("__Host-redb.identity.session", StringComparison.Ordinal)))
        {
            _log.LogWarning("Login redirect carried no session cookie; received cookies: {Cookies}", string.Join(", ", hostCookies.Keys));
            return Fail("login_no_session", "Login succeeded but no session cookie was issued.");
        }

        // Step 2: follow /connect/authorize with the session cookie attached manually.
        // X-Identity-Delegate-Consent: 1 tells the host's RedirectToConsent processor
        // to emit consent_required as JSON 400 instead of redirecting to the host's
        // HTML consent page. The BFF will render its own /consent UI from that JSON.
        using var authReq = new HttpRequestMessage(HttpMethod.Get, authorizeUrl);
        authReq.Headers.Add("Cookie", BuildCookieHeader(hostCookies));
        authReq.Headers.Add("X-Identity-Delegate-Consent", "1");
        var authorizeResp = await sessionHttp.SendAsync(authReq, ct).ConfigureAwait(false);
        CollectCookies(authorizeResp, hostCookies);

        // consent_required signalled as a JSON 400.
        if (authorizeResp.StatusCode == HttpStatusCode.BadRequest
            && (authorizeResp.Content.Headers.ContentType?.MediaType?
                .Contains("json", StringComparison.OrdinalIgnoreCase) ?? false))
        {
            ConsentRequiredPayload? payload = null;
            try
            {
                payload = await authorizeResp.Content
                    .ReadFromJsonAsync<ConsentRequiredPayload>(cancellationToken: ct)
                    .ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "Failed to parse consent_required JSON payload.");
            }

            if (payload is not null
                && string.Equals(payload.Error, "consent_required", StringComparison.Ordinal)
                && !string.IsNullOrEmpty(payload.ClientId))
            {
                var inflight = new ConsentInFlightState(
                    HostSessionCookieHeader: BuildCookieHeader(hostCookies),
                    AuthorizeUrl: authorizeUrl,
                    Verifier: verifier,
                    State: state,
                    Nonce: nonce,
                    ClientId: payload.ClientId!,
                    AppName: payload.AppName ?? payload.ClientId!,
                    Scopes: payload.Scopes ?? Array.Empty<string>(),
                    UserId: payload.UserId,
                    ReturnUrl: payload.ReturnUrl,
                    IssuedAt: DateTimeOffset.UtcNow);

                return new BackchannelLoginResult(
                    Success: false,
                    Principal: null,
                    AccessToken: null,
                    RefreshToken: null,
                    IdToken: null,
                    ExpiresAt: null,
                    Error: "consent_required",
                    ErrorDescription: "User consent is required for one or more requested scopes.",
                    ConsentRequired: true,
                    ConsentState: inflight);
            }

            return Fail("consent_required_malformed", "Host emitted consent_required but the JSON payload could not be parsed.");
        }

        if (authorizeResp.StatusCode != HttpStatusCode.Found)
        {
            var body = await SafeReadAsync(authorizeResp, ct).ConfigureAwait(false);
            _log.LogWarning("Authorize unexpected status {Status}: {Body}", authorizeResp.StatusCode, body);
            return Fail("authorize_failed", "Authorization endpoint returned an unexpected response.");
        }

        var authLocation = authorizeResp.Headers.Location?.OriginalString ?? "";
        var query = ExtractQuery(authLocation);
        var code = query.GetValueOrDefault("code");
        var returnedState = query.GetValueOrDefault("state");
        if (string.IsNullOrEmpty(code))
        {
            var err = query.GetValueOrDefault("error");
            return Fail(err ?? "authorize_no_code", query.GetValueOrDefault("error_description") ?? "Authorization endpoint did not return a code.");
        }
        if (returnedState != state)
        {
            return Fail("state_mismatch", "Authorization response state did not match the request.");
        }

        // Step 3: exchange code for tokens.
        var tokenForm = new List<KeyValuePair<string, string>>
        {
            new("grant_type", "authorization_code"),
            new("code", code),
            new("redirect_uri", _opts.RedirectUri),
            new("client_id", _opts.ClientId),
            new("code_verifier", verifier),
        };
        if (!string.IsNullOrEmpty(_opts.ClientSecret))
            tokenForm.Add(new("client_secret", _opts.ClientSecret));

        using var tokenReq = new HttpRequestMessage(HttpMethod.Post, config.TokenEndpoint)
        {
            Content = new FormUrlEncodedContent(tokenForm)
        };
        var tokenResp = await _http.SendAsync(tokenReq, ct).ConfigureAwait(false);
        var tokenJson = await tokenResp.Content.ReadFromJsonAsync<TokenResponse>(cancellationToken: ct).ConfigureAwait(false);
        if (tokenJson is null || !tokenResp.IsSuccessStatusCode || string.IsNullOrEmpty(tokenJson.AccessToken))
        {
            return Fail(tokenJson?.Error ?? "token_failed", tokenJson?.ErrorDescription ?? "Token endpoint returned no access_token.");
        }

        // Step 4: validate id_token (signature, issuer, audience, nonce).
        ClaimsPrincipal? principal = null;
        if (!string.IsNullOrEmpty(tokenJson.IdToken))
        {
            principal = ValidateIdToken(tokenJson.IdToken, config, nonce);
            if (principal is null)
            {
                return Fail("id_token_invalid", "id_token validation failed.");
            }
        }
        else
        {
            // No id_token — fall back to a minimal principal from access_token claims.
            principal = new ClaimsPrincipal(new ClaimsIdentity(
                new[] { new Claim(ClaimTypes.Name, username) },
                "BackchannelOidc"));
        }

        // Step 5: enrich with userinfo (preferred_username, email, roles, ...).
        if (!string.IsNullOrEmpty(config.UserInfoEndpoint))
        {
            try
            {
                using var uiReq = new HttpRequestMessage(HttpMethod.Get, config.UserInfoEndpoint);
                uiReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokenJson.AccessToken);
                var uiResp = await _http.SendAsync(uiReq, ct).ConfigureAwait(false);
                if (uiResp.IsSuccessStatusCode)
                {
                    var ui = await uiResp.Content.ReadFromJsonAsync<Dictionary<string, System.Text.Json.JsonElement>>(cancellationToken: ct).ConfigureAwait(false);
                    if (ui is not null)
                        principal = MergeUserinfo(principal, ui);
                }
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "Userinfo fetch failed; proceeding with id_token claims only.");
            }
        }

        var expiresAt = tokenJson.ExpiresIn > 0
            ? DateTimeOffset.UtcNow.AddSeconds(tokenJson.ExpiresIn)
            : (DateTimeOffset?)null;

        return new BackchannelLoginResult(
            Success: true,
            Principal: principal,
            AccessToken: tokenJson.AccessToken,
            RefreshToken: tokenJson.RefreshToken,
            IdToken: tokenJson.IdToken,
            ExpiresAt: expiresAt,
            Error: null,
            ErrorDescription: null);
    }

    private string BuildAuthorizeUrl(string endpoint, string state, string nonce, string challenge)
    {
        var sb = new StringBuilder(endpoint);
        sb.Append('?');
        sb.Append("client_id=").Append(Uri.EscapeDataString(_opts.ClientId));
        sb.Append("&redirect_uri=").Append(Uri.EscapeDataString(_opts.RedirectUri));
        sb.Append("&response_type=code");
        sb.Append("&scope=").Append(Uri.EscapeDataString(string.Join(' ', _opts.Scopes)));
        sb.Append("&state=").Append(Uri.EscapeDataString(state));
        sb.Append("&nonce=").Append(Uri.EscapeDataString(nonce));
        sb.Append("&code_challenge=").Append(Uri.EscapeDataString(challenge));
        sb.Append("&code_challenge_method=S256");
        return sb.ToString();
    }

    private ClaimsPrincipal? ValidateIdToken(string idToken, OpenIdConnectConfiguration config, string expectedNonce)
    {
        try
        {
            var handler = new JsonWebTokenHandler();
            var parameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = config.Issuer,
                ValidateAudience = true,
                ValidAudience = _opts.ClientId,
                ValidateLifetime = true,
                IssuerSigningKeys = config.SigningKeys,
                NameClaimType = "preferred_username",
                RoleClaimType = "roles",
            };
            var result = handler.ValidateTokenAsync(idToken, parameters).GetAwaiter().GetResult();
            if (!result.IsValid) return null;

            // Verify nonce matches the one we sent in the authorize request.
            var nonce = result.Claims.TryGetValue("nonce", out var n) ? n?.ToString() : null;
            if (!string.Equals(nonce, expectedNonce, StringComparison.Ordinal))
            {
                _log.LogWarning("id_token nonce mismatch (expected {Expected}, got {Actual})", expectedNonce, nonce);
                return null;
            }

            // Rebuild ClaimsIdentity explicitly so AuthenticationType is set (required for
            // ClaimsIdentity.IsAuthenticated == true under the cookie scheme) and NameClaimType
            // resolves Identity.Name. Fall back to "name", "preferred_username", or "sub".
            var src = result.ClaimsIdentity;
            string nameClaim = src.HasClaim(c => c.Type == "preferred_username") ? "preferred_username"
                             : src.HasClaim(c => c.Type == "name") ? "name"
                             : "sub";
            var rebuilt = new ClaimsIdentity(src.Claims, "BackchannelOidc", nameClaim, "roles");
            return new ClaimsPrincipal(rebuilt);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "id_token validation threw");
            return null;
        }
    }

    private static ClaimsPrincipal MergeUserinfo(
        ClaimsPrincipal current, Dictionary<string, System.Text.Json.JsonElement> userinfo)
    {
        var identity = current.Identity is ClaimsIdentity ci
            ? new ClaimsIdentity(ci.Claims, ci.AuthenticationType, ci.NameClaimType, ci.RoleClaimType)
            : new ClaimsIdentity("BackchannelOidc", "preferred_username", "roles");

        foreach (var (key, value) in userinfo)
        {
            // Skip duplicates already on the principal (id_token wins).
            if (identity.HasClaim(c => c.Type == key)) continue;

            switch (value.ValueKind)
            {
                case System.Text.Json.JsonValueKind.String:
                    identity.AddClaim(new Claim(key, value.GetString() ?? ""));
                    break;
                case System.Text.Json.JsonValueKind.Number:
                    identity.AddClaim(new Claim(key, value.GetRawText()));
                    break;
                case System.Text.Json.JsonValueKind.True:
                case System.Text.Json.JsonValueKind.False:
                    identity.AddClaim(new Claim(key, value.GetBoolean().ToString().ToLowerInvariant()));
                    break;
                case System.Text.Json.JsonValueKind.Array:
                    foreach (var el in value.EnumerateArray())
                    {
                        identity.AddClaim(new Claim(key, el.ToString() ?? ""));
                    }
                    break;
            }
        }

        return new ClaimsPrincipal(identity);
    }

    private static (string verifier, string challenge) GeneratePkce()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        var verifier = Base64Url(bytes);
        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
        return (verifier, Base64Url(hash));
    }

    private static string RandomToken(int byteLen) => Base64Url(RandomNumberGenerator.GetBytes(byteLen));

    private static string Base64Url(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static Dictionary<string, string> ExtractQuery(string url)
    {
        var dict = new Dictionary<string, string>(StringComparer.Ordinal);
        var qIdx = url.IndexOf('?');
        if (qIdx < 0) return dict;
        var query = url[(qIdx + 1)..];
        foreach (var pair in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = pair.IndexOf('=');
            var k = eq > 0 ? Uri.UnescapeDataString(pair[..eq]) : Uri.UnescapeDataString(pair);
            var v = eq > 0 ? Uri.UnescapeDataString(pair[(eq + 1)..]) : "";
            dict[k] = v;
        }
        return dict;
    }

    private static async Task<string> SafeReadAsync(HttpResponseMessage resp, CancellationToken ct)
    {
        try { return await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false); }
        catch { return ""; }
    }

    /// <summary>
    /// Pulls every <c>Set-Cookie</c> header off the response and stores
    /// <c>NAME=VALUE</c> in the supplied dictionary, ignoring attributes
    /// (Path/Domain/Secure/SameSite/...). This is intentionally lenient — we just
    /// need to echo cookies back to the host on subsequent requests.
    /// </summary>
    private static void CollectCookies(HttpResponseMessage resp, IDictionary<string, string> jar)
    {
        if (!resp.Headers.TryGetValues("Set-Cookie", out var setCookies)) return;
        foreach (var raw in setCookies)
        {
            var semi = raw.IndexOf(';');
            var pair = semi > 0 ? raw[..semi] : raw;
            var eq = pair.IndexOf('=');
            if (eq <= 0) continue;
            var name = pair[..eq].Trim();
            var value = pair[(eq + 1)..].Trim();
            if (string.IsNullOrEmpty(name)) continue;
            // Empty value with Max-Age=0 means delete — drop from jar.
            if (string.IsNullOrEmpty(value)) jar.Remove(name);
            else jar[name] = value;
        }
    }

    private static string BuildCookieHeader(IDictionary<string, string> jar) =>
        string.Join("; ", jar.Select(kv => kv.Key + "=" + kv.Value));

    /// <summary>
    /// Resumes a login flow that was paused on MFA. Posts the user's TOTP/recovery code
    /// to the host MFA endpoint with the previously-captured state cookie attached, then
    /// completes /connect/authorize and /connect/token using the original PKCE material.
    /// </summary>
    public async Task<BackchannelLoginResult> VerifyMfaAsync(
        MfaInFlightState inflight, string code, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(code))
            return Fail("missing_code", "Verification code is required.");

        OpenIdConnectConfiguration config;
        try
        {
            config = await _discovery.GetConfigurationAsync(ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "OIDC discovery failed during MFA verify for {Authority}", _opts.Authority);
            return Fail("oidc_discovery_failed", "Identity provider discovery failed.");
        }

        using var handler = CreateSessionHandler();
        using var sessionHttp = new HttpClient(handler) { BaseAddress = _http.BaseAddress };

        var hostCookies = ParseCookieHeader(inflight.HostMfaStateCookie);

        // POST host /mfa with code + the encrypted state cookie attached.
        var verifyForm = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("code", code),
            new KeyValuePair<string, string>("returnUrl", "/"),
        });
        using var verifyReq = new HttpRequestMessage(HttpMethod.Post, inflight.MfaPath) { Content = verifyForm };
        verifyReq.Headers.Add("Cookie", BuildCookieHeader(hostCookies));

        var verifyResp = await sessionHttp.SendAsync(verifyReq, ct).ConfigureAwait(false);
        CollectCookies(verifyResp, hostCookies);

        if (verifyResp.StatusCode == (HttpStatusCode)429)
            return Fail("locked", "Too many incorrect MFA attempts. Please wait before trying again.");

        if (verifyResp.StatusCode != HttpStatusCode.Found && verifyResp.StatusCode != HttpStatusCode.SeeOther)
        {
            // Host re-rendered the MFA page (200) → bad code.
            return Fail("invalid_code", "The verification code is incorrect or has expired.");
        }

        if (!hostCookies.Keys.Any(k =>
                k.Equals("redb.identity.session", StringComparison.Ordinal)
                || k.Equals("__Host-redb.identity.session", StringComparison.Ordinal)))
        {
            _log.LogWarning("MFA succeeded but no session cookie issued. Cookies: {Cookies}", string.Join(", ", hostCookies.Keys));
            return Fail("mfa_no_session", "MFA succeeded but no session cookie was issued.");
        }

        // Resume /connect/authorize with the now-elevated session cookie.
        using var authReq = new HttpRequestMessage(HttpMethod.Get, inflight.AuthorizeUrl);
        authReq.Headers.Add("Cookie", BuildCookieHeader(hostCookies));
        var authorizeResp = await sessionHttp.SendAsync(authReq, ct).ConfigureAwait(false);
        if (authorizeResp.StatusCode != HttpStatusCode.Found)
        {
            var body = await SafeReadAsync(authorizeResp, ct).ConfigureAwait(false);
            _log.LogWarning("Post-MFA authorize unexpected status {Status}: {Body}", authorizeResp.StatusCode, body);
            return Fail("authorize_failed", "Authorization endpoint returned an unexpected response after MFA.");
        }

        var authLocation = authorizeResp.Headers.Location?.OriginalString ?? "";
        var query = ExtractQuery(authLocation);
        var hostCode = query.GetValueOrDefault("code");
        var returnedState = query.GetValueOrDefault("state");
        if (string.IsNullOrEmpty(hostCode))
        {
            var err = query.GetValueOrDefault("error");
            return Fail(err ?? "authorize_no_code", query.GetValueOrDefault("error_description") ?? "Authorization endpoint did not return a code.");
        }
        if (returnedState != inflight.State)
            return Fail("state_mismatch", "Authorization response state did not match the request.");

        var tokenForm = new List<KeyValuePair<string, string>>
        {
            new("grant_type", "authorization_code"),
            new("code", hostCode),
            new("redirect_uri", _opts.RedirectUri),
            new("client_id", _opts.ClientId),
            new("code_verifier", inflight.Verifier),
        };
        if (!string.IsNullOrEmpty(_opts.ClientSecret))
            tokenForm.Add(new("client_secret", _opts.ClientSecret));

        using var tokenReq = new HttpRequestMessage(HttpMethod.Post, config.TokenEndpoint)
        {
            Content = new FormUrlEncodedContent(tokenForm)
        };
        var tokenResp = await _http.SendAsync(tokenReq, ct).ConfigureAwait(false);
        var tokenJson = await tokenResp.Content.ReadFromJsonAsync<TokenResponse>(cancellationToken: ct).ConfigureAwait(false);
        if (tokenJson is null || !tokenResp.IsSuccessStatusCode || string.IsNullOrEmpty(tokenJson.AccessToken))
            return Fail(tokenJson?.Error ?? "token_failed", tokenJson?.ErrorDescription ?? "Token endpoint returned no access_token.");

        ClaimsPrincipal? principal = null;
        if (!string.IsNullOrEmpty(tokenJson.IdToken))
        {
            principal = ValidateIdToken(tokenJson.IdToken, config, inflight.Nonce);
            if (principal is null)
                return Fail("id_token_invalid", "id_token validation failed.");
        }
        else
        {
            principal = new ClaimsPrincipal(new ClaimsIdentity(
                new[] { new Claim(ClaimTypes.Name, "mfa-user") }, "BackchannelOidc"));
        }

        if (!string.IsNullOrEmpty(config.UserInfoEndpoint))
        {
            try
            {
                using var uiReq = new HttpRequestMessage(HttpMethod.Get, config.UserInfoEndpoint);
                uiReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokenJson.AccessToken);
                var uiResp = await _http.SendAsync(uiReq, ct).ConfigureAwait(false);
                if (uiResp.IsSuccessStatusCode)
                {
                    var ui = await uiResp.Content.ReadFromJsonAsync<Dictionary<string, System.Text.Json.JsonElement>>(cancellationToken: ct).ConfigureAwait(false);
                    if (ui is not null)
                        principal = MergeUserinfo(principal, ui);
                }
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "Userinfo fetch failed after MFA; proceeding with id_token claims only.");
            }
        }

        var expiresAt = tokenJson.ExpiresIn > 0
            ? DateTimeOffset.UtcNow.AddSeconds(tokenJson.ExpiresIn)
            : (DateTimeOffset?)null;

        return new BackchannelLoginResult(
            Success: true,
            Principal: principal,
            AccessToken: tokenJson.AccessToken,
            RefreshToken: tokenJson.RefreshToken,
            IdToken: tokenJson.IdToken,
            ExpiresAt: expiresAt,
            Error: null,
            ErrorDescription: null);
    }

    private static Dictionary<string, string> ParseCookieHeader(string header)
    {
        var dict = new Dictionary<string, string>(StringComparer.Ordinal);
        if (string.IsNullOrEmpty(header)) return dict;
        foreach (var raw in header.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var eq = raw.IndexOf('=');
            if (eq <= 0) continue;
            dict[raw[..eq].Trim()] = raw[(eq + 1)..].Trim();
        }
        return dict;
    }

    private static BackchannelLoginResult Fail(string error, string description) =>
        new(false, null, null, null, null, null, error, description);

    /// <summary>
    /// Resumes a login flow that was paused on the BFF-native consent UI. The end-user
    /// has just granted consent through the BFF /consent page; the consent decision
    /// has already been recorded against the host's authorization store via the host's
    /// session-based /consent form post. This method replays /connect/authorize using
    /// the original PKCE material and the carried-over host session cookie jar, then
    /// completes the token exchange exactly like <see cref="LoginAsync"/>.
    /// </summary>
    public async Task<BackchannelLoginResult> ResumeAfterConsentAsync(
        ConsentInFlightState inflight, CancellationToken ct = default)
    {
        OpenIdConnectConfiguration config;
        try
        {
            config = await _discovery.GetConfigurationAsync(ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "OIDC discovery failed during consent resume for {Authority}", _opts.Authority);
            return Fail("oidc_discovery_failed", "Identity provider discovery failed.");
        }

        using var handler = CreateSessionHandler();
        using var sessionHttp = new HttpClient(handler) { BaseAddress = _http.BaseAddress };

        var hostCookies = ParseCookieHeader(inflight.HostSessionCookieHeader);

        using var authReq = new HttpRequestMessage(HttpMethod.Get, inflight.AuthorizeUrl);
        authReq.Headers.Add("Cookie", BuildCookieHeader(hostCookies));
        // No X-Identity-Delegate-Consent header on resume: consent has been granted,
        // so the host should issue the code straight away. If the host still says
        // consent_required at this point something went wrong during the grant POST.
        var authorizeResp = await sessionHttp.SendAsync(authReq, ct).ConfigureAwait(false);
        CollectCookies(authorizeResp, hostCookies);

        if (authorizeResp.StatusCode != HttpStatusCode.Found)
        {
            var body = await SafeReadAsync(authorizeResp, ct).ConfigureAwait(false);
            _log.LogWarning("Post-consent authorize unexpected status {Status}: {Body}", authorizeResp.StatusCode, body);
            return Fail("authorize_failed", "Authorization endpoint returned an unexpected response after consent.");
        }

        var authLocation = authorizeResp.Headers.Location?.OriginalString ?? "";
        var query = ExtractQuery(authLocation);
        var hostCode = query.GetValueOrDefault("code");
        var returnedState = query.GetValueOrDefault("state");
        if (string.IsNullOrEmpty(hostCode))
        {
            var err = query.GetValueOrDefault("error");
            return Fail(err ?? "authorize_no_code", query.GetValueOrDefault("error_description") ?? "Authorization endpoint did not return a code.");
        }
        if (returnedState != inflight.State)
            return Fail("state_mismatch", "Authorization response state did not match the request.");

        var tokenForm = new List<KeyValuePair<string, string>>
        {
            new("grant_type", "authorization_code"),
            new("code", hostCode),
            new("redirect_uri", _opts.RedirectUri),
            new("client_id", _opts.ClientId),
            new("code_verifier", inflight.Verifier),
        };
        if (!string.IsNullOrEmpty(_opts.ClientSecret))
            tokenForm.Add(new("client_secret", _opts.ClientSecret));

        using var tokenReq = new HttpRequestMessage(HttpMethod.Post, config.TokenEndpoint)
        {
            Content = new FormUrlEncodedContent(tokenForm)
        };
        var tokenResp = await _http.SendAsync(tokenReq, ct).ConfigureAwait(false);
        var tokenJson = await tokenResp.Content.ReadFromJsonAsync<TokenResponse>(cancellationToken: ct).ConfigureAwait(false);
        if (tokenJson is null || !tokenResp.IsSuccessStatusCode || string.IsNullOrEmpty(tokenJson.AccessToken))
            return Fail(tokenJson?.Error ?? "token_failed", tokenJson?.ErrorDescription ?? "Token endpoint returned no access_token.");

        ClaimsPrincipal? principal;
        if (!string.IsNullOrEmpty(tokenJson.IdToken))
        {
            principal = ValidateIdToken(tokenJson.IdToken, config, inflight.Nonce);
            if (principal is null)
                return Fail("id_token_invalid", "id_token validation failed.");
        }
        else
        {
            principal = new ClaimsPrincipal(new ClaimsIdentity(
                new[] { new Claim(ClaimTypes.Name, "consent-user") }, "BackchannelOidc"));
        }

        if (!string.IsNullOrEmpty(config.UserInfoEndpoint))
        {
            try
            {
                using var uiReq = new HttpRequestMessage(HttpMethod.Get, config.UserInfoEndpoint);
                uiReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokenJson.AccessToken);
                var uiResp = await _http.SendAsync(uiReq, ct).ConfigureAwait(false);
                if (uiResp.IsSuccessStatusCode)
                {
                    var ui = await uiResp.Content.ReadFromJsonAsync<Dictionary<string, System.Text.Json.JsonElement>>(cancellationToken: ct).ConfigureAwait(false);
                    if (ui is not null)
                        principal = MergeUserinfo(principal, ui);
                }
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "Userinfo fetch failed after consent; proceeding with id_token claims only.");
            }
        }

        var expiresAt = tokenJson.ExpiresIn > 0
            ? DateTimeOffset.UtcNow.AddSeconds(tokenJson.ExpiresIn)
            : (DateTimeOffset?)null;

        return new BackchannelLoginResult(
            Success: true,
            Principal: principal,
            AccessToken: tokenJson.AccessToken,
            RefreshToken: tokenJson.RefreshToken,
            IdToken: tokenJson.IdToken,
            ExpiresAt: expiresAt,
            Error: null,
            ErrorDescription: null);
    }

    /// <summary>
    /// Posts the user's allow-consent decision to the host's session-based form
    /// <c>/consent</c> endpoint, reusing the captured host session cookie jar. The
    /// host records the authorization (or updates it via union-merge) and the
    /// caller can then call <see cref="ResumeAfterConsentAsync"/> to obtain tokens.
    /// </summary>
    public async Task<bool> RecordConsentGrantAsync(
        ConsentInFlightState inflight, CancellationToken ct = default)
    {
        using var handler = CreateSessionHandler();
        using var sessionHttp = new HttpClient(handler) { BaseAddress = _http.BaseAddress };

        var hostCookies = ParseCookieHeader(inflight.HostSessionCookieHeader);

        var form = new List<KeyValuePair<string, string>>
        {
            // Host's ConsentPageProcessors.PrepareConsentBody expects snake_case
            // field names; user_id is derived from the attached session cookie
            // (ReadSessionCookie → SessionUserIdHeader), not from this form.
            new("client_id", inflight.ClientId),
            new("scopes", string.Join(' ', inflight.Scopes)),
            new("decision", "allow"),
            new("returnUrl", inflight.ReturnUrl ?? inflight.AuthorizeUrl),
        };

        using var req = new HttpRequestMessage(HttpMethod.Post, "/consent")
        {
            Content = new FormUrlEncodedContent(form),
        };
        req.Headers.Add("Cookie", BuildCookieHeader(hostCookies));

        var resp = await sessionHttp.SendAsync(req, ct).ConfigureAwait(false);
        // Host's consent form handler responds with a 302 to the resumed authorize URL
        // on success. Any other status is treated as a failure.
        if (resp.StatusCode != HttpStatusCode.Found && resp.StatusCode != HttpStatusCode.SeeOther)
        {
            var body = await SafeReadAsync(resp, ct).ConfigureAwait(false);
            _log.LogWarning("Host /consent grant unexpected status {Status}: {Body}", resp.StatusCode, body);
            return false;
        }
        return true;
    }

    /// <summary>
    /// BFF-relayed end-user verification for the OAuth 2.0 Device Authorization Grant
    /// (RFC 8628 §3.3). The browser is logged into the BFF (cookie-auth); the BFF has
    /// an OIDC <c>access_token</c> for the user from a prior login. We forward the
    /// <c>user_code</c> + decision ("allow"/"deny") to the host's <c>/connect/device/verify</c>
    /// endpoint with the access_token as a Bearer header — the host's bearer-aware
    /// <see cref="!:HandleVerificationRequestHandler"/> validates the JWT, materialises
    /// the principal, and finishes the grant.
    /// </summary>
    public async Task<DeviceVerifyResult> VerifyDeviceCodeAsync(
        string userCode, string action, string accessToken, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(userCode))
            return new DeviceVerifyResult(false, "missing_user_code", "user_code is required.");
        if (string.IsNullOrWhiteSpace(accessToken))
            return new DeviceVerifyResult(false, "missing_token", "access_token is required.");
        if (action != "allow" && action != "deny")
            return new DeviceVerifyResult(false, "invalid_action", "action must be 'allow' or 'deny'.");

        var form = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("user_code", userCode),
            new KeyValuePair<string, string>("action", action),
        });

        using var req = new HttpRequestMessage(HttpMethod.Post, "/connect/device/verify")
        {
            Content = form,
        };
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        HttpResponseMessage resp;
        try
        {
            resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Device verification HTTP call failed.");
            return new DeviceVerifyResult(false, "transport_error", ex.Message);
        }

        if (resp.IsSuccessStatusCode)
        {
            return new DeviceVerifyResult(true, null, null);
        }

        // Try to parse an OAuth-style {error, error_description} JSON body.
        string? error = null;
        string? desc = null;
        try
        {
            if (resp.Content.Headers.ContentType?.MediaType?.Contains("json", StringComparison.OrdinalIgnoreCase) == true)
            {
                var payload = await resp.Content
                    .ReadFromJsonAsync<Dictionary<string, System.Text.Json.JsonElement>>(cancellationToken: ct)
                    .ConfigureAwait(false);
                if (payload is not null)
                {
                    if (payload.TryGetValue("error", out var e) && e.ValueKind == System.Text.Json.JsonValueKind.String)
                        error = e.GetString();
                    if (payload.TryGetValue("error_description", out var d) && d.ValueKind == System.Text.Json.JsonValueKind.String)
                        desc = d.GetString();
                }
            }
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Failed to parse device verify error payload.");
        }

        return new DeviceVerifyResult(false, error ?? "verify_failed", desc ?? $"Host returned HTTP {(int)resp.StatusCode}.");
    }

    private sealed class ConsentRequiredPayload
    {
        [System.Text.Json.Serialization.JsonPropertyName("error")] public string? Error { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("clientId")] public string? ClientId { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("appName")] public string? AppName { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("scopes")] public string[]? Scopes { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("userId")] public long UserId { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("returnUrl")] public string? ReturnUrl { get; set; }
    }

    private sealed class TokenResponse
    {
        [System.Text.Json.Serialization.JsonPropertyName("access_token")] public string? AccessToken { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("refresh_token")] public string? RefreshToken { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("id_token")] public string? IdToken { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("expires_in")] public int ExpiresIn { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("token_type")] public string? TokenType { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("error")] public string? Error { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("error_description")] public string? ErrorDescription { get; set; }
    }
}
