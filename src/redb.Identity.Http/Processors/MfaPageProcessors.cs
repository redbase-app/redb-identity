using System.Net;
using redb.Identity.Contracts.Mfa;
using redb.Identity.Http.Security;
using redb.Route.Abstractions;
using redb.Route.Core;
using redb.Route.Http;

namespace redb.Identity.Http.Processors;

/// <summary>
/// HTTP processors for MFA verification pages (TOTP code entry, recovery code entry).
/// Follows the same pattern as <see cref="LoginPageProcessors"/>.
/// </summary>
internal static class MfaPageProcessors
{
    /// <summary>
    /// Renders the MFA verification page.
    /// Reads <c>mfa_state</c> from the query string and derives the list of configured
    /// methods server-side by decrypting the state via <see cref="IMfaStateInspector"/>
    /// (B9 / BUG-9). The methods are no longer accepted from a query parameter — that would
    /// echo factor-mix information into the browser history / referer.
    /// When multiple methods are available, renders a selector + JS that calls <c>/mfa/challenge</c>
    /// for SMS/Email; TOTP is shown directly. Single TOTP method falls back to the legacy form.
    /// </summary>
    internal static Task RenderMfaPage(
        IExchange e, CancellationToken ct,
        string mfaPath = "/mfa", IdentityTransportOptions? opts = null,
        IMfaStateInspector? inspector = null)
    {
        opts ??= new IdentityTransportOptions();

        // B3 §4: the encrypted state lives in the __Host-redb.identity.mfa cookie. The
        // MfaCookieIngressProcessor (ReadMfaStateCookie) stashes it in exchange.Properties
        // when the request carries a cookie. Falling back to the query string preserves
        // back-compat for clients still on the pre-B3 ?mfa_state=... transport.
        var mfaState = (e.Properties.TryGetValue("mfa-state-from-cookie", out var fromCookie)
                            ? fromCookie?.ToString()
                            : null)
                       ?? ExtractMfaStateFromQuery(e)
                       ?? "";

        // B9 / BUG-9: derive methods from the encrypted state (server-trusted) instead of
        // the URL (caller-supplied). Falls back to TOTP-only if state is missing/invalid —
        // the verify endpoint will reject the bad state with a clear error anyway.
        // Phase 9e: inspector is supplied by the route builder (BrokeredMfaStateInspector
        // in .tpkg mode, direct MfaStateProtector in test-fixture mode); fall back to
        // per-exchange DI lookup for back-compat.
        string[] methods = Array.Empty<string>();
        if (!string.IsNullOrEmpty(mfaState))
        {
            inspector ??= e.ServiceProvider?.GetService(typeof(IMfaStateInspector)) as IMfaStateInspector;
            var decoded = inspector?.TryGetMethods(mfaState);
            if (decoded is { Length: > 0 } m)
                methods = m.Where(x => x == "totp" || x == "sms" || x == "email").Distinct().ToArray();
        }

        var hasRecovery = true;
        var multipleOrChallenge = methods.Length > 1 || methods.Any(m => m == "sms" || m == "email");

        var cardContent = multipleOrChallenge
            ? BuildMethodSelector(mfaPath, mfaState, methods, hasRecovery, opts)
            : BuildTotpForm(mfaPath, mfaState, hasRecovery, opts);

        e.Out = new Message();
        e.Out.Body = IdentityPageTemplates.WrapPage("Verification Code", cardContent, opts);
        e.Out.Headers[HttpHeaders.ResponseContentType] = "text/html; charset=utf-8";
        e.Out.Headers[HttpHeaders.ResponseCode] = 200;

        return Task.CompletedTask;
    }

    /// <summary>
    /// Renders the MFA recovery code entry form.
    /// Reached via "Use recovery code" link from the TOTP page.
    /// </summary>
    internal static Task RenderMfaRecoveryPage(
        IExchange e, CancellationToken ct,
        string mfaRecoveryPath = "/mfa/recovery", string mfaPath = "/mfa",
        IdentityTransportOptions? opts = null)
    {
        opts ??= new IdentityTransportOptions();

        // B3 §4: prefer cookie-provided state; fall back to legacy query param.
        var mfaState = (e.Properties.TryGetValue("mfa-state-from-cookie", out var fromCookie)
                            ? fromCookie?.ToString()
                            : null)
                       ?? ExtractMfaStateFromQuery(e)
                       ?? "";

        var cardContent = BuildRecoveryForm(mfaRecoveryPath, mfaPath, mfaState, opts);

        e.Out = new Message();
        e.Out.Body = IdentityPageTemplates.WrapPage("Recovery Code", cardContent, opts);
        e.Out.Headers[HttpHeaders.ResponseContentType] = "text/html; charset=utf-8";
        e.Out.Headers[HttpHeaders.ResponseCode] = 200;

        return Task.CompletedTask;
    }

    /// <summary>
    /// Handles the response after TOTP verification attempt.
    /// On success: redirect to returnUrl (session cookie already set by upstream processor).
    /// On failure: re-render the form with an error message.
    /// </summary>
    internal static Task HandleMfaVerifyResponse(
        IExchange e, CancellationToken ct,
        string mfaPath = "/mfa", IdentityTransportOptions? opts = null)
    {
        opts ??= new IdentityTransportOptions();

        var body = (e.HasOut ? e.Out!.Body : e.In.Body) as IDictionary<string, object?>;
        if (body is null)
            return Task.CompletedTask;

        var success = body.TryGetValue("success", out var s) && s is true;
        var returnUrl = body.TryGetValue("returnUrl", out var r) ? r?.ToString() : null;

        if (success && !string.IsNullOrEmpty(returnUrl))
        {
            if (LoginPageProcessors.IsValidReturnUrl(returnUrl))
            {
                e.Out = new Message();
                e.Out.Headers[HttpHeaders.ResponseCode] = 302;
                e.Out.Headers["Location"] = returnUrl;
                if (e.In.Headers.TryGetValue("Set-Cookie", out var cookie))
                    e.Out.Headers["Set-Cookie"] = cookie;
                return Task.CompletedTask;
            }
        }

        if (success)
        {
            e.Out = new Message();
            e.Out.Body = new Dictionary<string, object?> { ["message"] = "MFA verification successful" };
            if (e.In.Headers.TryGetValue("Set-Cookie", out var cookie))
                e.Out.Headers["Set-Cookie"] = cookie;
            return Task.CompletedTask;
        }

        // Failed — re-render form with error
        var mfaState = body.TryGetValue("mfa_state", out var st) ? st?.ToString() ?? "" : "";
        var errorDesc = body.TryGetValue("error_description", out var ed)
            ? ed?.ToString() : "Invalid verification code";

        var cardContent = BuildTotpForm(mfaPath, mfaState, hasRecovery: true, opts, errorDesc);

        e.Out = new Message();
        e.Out.Body = IdentityPageTemplates.WrapPage("Verification Code", cardContent, opts);
        e.Out.Headers[HttpHeaders.ResponseContentType] = "text/html; charset=utf-8";
        e.Out.Headers[HttpHeaders.ResponseCode] = 200;

        return Task.CompletedTask;
    }

    /// <summary>
    /// Handles the response after recovery code verification attempt.
    /// Same redirect/re-render pattern as <see cref="HandleMfaVerifyResponse"/>.
    /// </summary>
    internal static Task HandleMfaRecoveryResponse(
        IExchange e, CancellationToken ct,
        string mfaRecoveryPath = "/mfa/recovery", string mfaPath = "/mfa",
        IdentityTransportOptions? opts = null)
    {
        opts ??= new IdentityTransportOptions();

        var body = (e.HasOut ? e.Out!.Body : e.In.Body) as IDictionary<string, object?>;
        if (body is null)
            return Task.CompletedTask;

        var success = body.TryGetValue("success", out var s) && s is true;
        var returnUrl = body.TryGetValue("returnUrl", out var r) ? r?.ToString() : null;

        if (success && !string.IsNullOrEmpty(returnUrl))
        {
            if (LoginPageProcessors.IsValidReturnUrl(returnUrl))
            {
                e.Out = new Message();
                e.Out.Headers[HttpHeaders.ResponseCode] = 302;
                e.Out.Headers["Location"] = returnUrl;
                if (e.In.Headers.TryGetValue("Set-Cookie", out var cookie))
                    e.Out.Headers["Set-Cookie"] = cookie;
                return Task.CompletedTask;
            }
        }

        if (success)
        {
            e.Out = new Message();
            e.Out.Body = new Dictionary<string, object?> { ["message"] = "Recovery code accepted" };
            if (e.In.Headers.TryGetValue("Set-Cookie", out var cookie))
                e.Out.Headers["Set-Cookie"] = cookie;
            return Task.CompletedTask;
        }

        // Failed — re-render form with error
        var mfaState = body.TryGetValue("mfa_state", out var st) ? st?.ToString() ?? "" : "";
        var errorDesc = body.TryGetValue("error_description", out var ed)
            ? ed?.ToString() : "Invalid recovery code";

        var cardContent = BuildRecoveryForm(mfaRecoveryPath, mfaPath, mfaState, opts, errorDesc);

        e.Out = new Message();
        e.Out.Body = IdentityPageTemplates.WrapPage("Recovery Code", cardContent, opts);
        e.Out.Headers[HttpHeaders.ResponseContentType] = "text/html; charset=utf-8";
        e.Out.Headers[HttpHeaders.ResponseCode] = 200;

        return Task.CompletedTask;
    }

    // ── HTML builders ──

    private static string BuildTotpForm(
        string mfaPath, string mfaState, bool hasRecovery,
        IdentityTransportOptions opts, string? error = null)
    {
        var errorHtml = string.IsNullOrEmpty(error)
            ? ""
            : $"""<p class="error">{WebUtility.HtmlEncode(error)}</p>""";

        // B3 §4: mfa_state lives in the __Host-redb.identity.mfa cookie, never in URLs.
        var recoveryLink = hasRecovery
            ? $"""<p style="text-align:center;margin-top:1rem;font-size:0.85rem;"><a href="{WebUtility.HtmlEncode(mfaPath)}/recovery" style="color:{opts.Branding.PrimaryColor};">Use a recovery code</a></p>"""
            : "";
        _ = mfaState; // state travels in the cookie; kept in signature for form re-render on error

        return $$"""
            <h1>Verification Code</h1>
            <p style="text-align:center;color:#64748b;margin-bottom:1.5rem;">Enter the 6-digit code from your authenticator app</p>
            {{errorHtml}}
            <form method="POST" action="{{WebUtility.HtmlEncode(mfaPath)}}">
                <label for="code">Code</label>
                <input type="text" id="code" name="code" required autocomplete="one-time-code"
                       inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autofocus
                       style="text-align:center;font-size:1.5rem;letter-spacing:0.3em;" />
                <button type="submit" class="btn btn-primary">Verify</button>
            </form>
            {{recoveryLink}}
            """;
    }

    private static string BuildRecoveryForm(
        string mfaRecoveryPath, string mfaPath, string mfaState,
        IdentityTransportOptions opts, string? error = null)
    {
        var errorHtml = string.IsNullOrEmpty(error)
            ? ""
            : $"""<p class="error">{WebUtility.HtmlEncode(error)}</p>""";

        // B3 §4: no mfa_state in URLs / form inputs — cookie carries it.
        _ = mfaState;
        return $$"""
            <h1>Recovery Code</h1>
            <p style="text-align:center;color:#64748b;margin-bottom:1.5rem;">Enter one of your recovery codes</p>
            {{errorHtml}}
            <form method="POST" action="{{WebUtility.HtmlEncode(mfaRecoveryPath)}}">
                <label for="recovery_code">Recovery Code</label>
                <input type="text" id="recovery_code" name="recovery_code" required
                       autocomplete="off" placeholder="XXXX-XXXX" autofocus
                       style="text-align:center;font-size:1.2rem;letter-spacing:0.1em;" />
                <button type="submit" class="btn btn-primary">Verify</button>
            </form>
            <p style="text-align:center;margin-top:1rem;font-size:0.85rem;">
                <a href="{{WebUtility.HtmlEncode(mfaPath)}}" style="color:{{opts.Branding.PrimaryColor}};">Back to authenticator code</a>
            </p>
            """;
    }

    /// <summary>
    /// Builds a method-selector view: lets the user pick TOTP / SMS / Email.
    /// TOTP is verified inline; SMS/Email triggers an AJAX call to <c>/mfa/challenge</c>
    /// which sends the OTP and returns a new <c>mfa_state</c>; the form then swaps to OTP entry.
    /// </summary>
    private static string BuildMethodSelector(
        string mfaPath, string mfaState, string[] methods, bool hasRecovery,
        IdentityTransportOptions opts)
    {
        var primary = opts.Branding.PrimaryColor;
        var hasSms = methods.Contains("sms");
        var hasEmail = methods.Contains("email");
        var hasTotp = methods.Contains("totp");

        var buttons = new System.Text.StringBuilder();
        if (hasTotp)
        {
            buttons.Append($"""<button type="button" class="btn btn-secondary" data-method="totp" style="margin-bottom:0.5rem;">Authenticator app (TOTP)</button>""");
        }
        if (hasSms)
        {
            buttons.Append($"""<button type="button" class="btn btn-secondary" data-method="sms" style="margin-bottom:0.5rem;">Send code via SMS</button>""");
        }
        if (hasEmail)
        {
            buttons.Append($"""<button type="button" class="btn btn-secondary" data-method="email" style="margin-bottom:0.5rem;">Send code via Email</button>""");
        }

        // B3 §4: no mfa_state in URLs — the __Host-redb.identity.mfa cookie carries it.
        var recoveryLink = hasRecovery
            ? $"""<p style="text-align:center;margin-top:1rem;font-size:0.85rem;"><a href="{WebUtility.HtmlEncode(mfaPath)}/recovery" style="color:{primary};">Use a recovery code</a></p>"""
            : "";

        var challengePath = mfaPath.TrimEnd('/') + "/challenge";
        var encodedMfaPath = WebUtility.HtmlEncode(mfaPath);
        var encodedChallengePath = WebUtility.HtmlEncode(challengePath);
        _ = mfaState; // retained in signature for future form re-render; state travels via cookie

        return $$"""
            <h1>Verification Required</h1>
            <p style="text-align:center;color:#64748b;margin-bottom:1.5rem;">Choose a verification method</p>
            <div id="mfa-error" class="error" style="display:none;"></div>

            <div id="mfa-method-picker" style="display:flex;flex-direction:column;gap:0.5rem;">
                {{buttons}}
            </div>

            <form id="mfa-totp-form" method="POST" action="{{encodedMfaPath}}" style="display:none;">
                <p id="mfa-totp-hint" style="text-align:center;color:#64748b;">Enter the 6-digit code from your authenticator app</p>
                <label for="code-totp">Code</label>
                <input type="text" id="code-totp" name="code" required autocomplete="one-time-code"
                       inputmode="numeric" pattern="[0-9]{6}" maxlength="6"
                       style="text-align:center;font-size:1.5rem;letter-spacing:0.3em;" />
                <button type="submit" class="btn btn-primary">Verify</button>
            </form>

            <form id="mfa-otp-form" method="POST" action="{{encodedMfaPath}}" style="display:none;">
                <p id="mfa-otp-hint" style="text-align:center;color:#64748b;"></p>
                <label for="code-otp">Code</label>
                <input type="text" id="code-otp" name="code" required autocomplete="one-time-code"
                       inputmode="numeric" pattern="[0-9]{6}" maxlength="6"
                       style="text-align:center;font-size:1.5rem;letter-spacing:0.3em;" />
                <button type="submit" class="btn btn-primary">Verify</button>
            </form>

            {{recoveryLink}}

            <script>
            (function() {
                var picker = document.getElementById('mfa-method-picker');
                var totpForm = document.getElementById('mfa-totp-form');
                var otpForm = document.getElementById('mfa-otp-form');
                var otpHint = document.getElementById('mfa-otp-hint');
                var errBox = document.getElementById('mfa-error');

                function showError(msg) { errBox.textContent = msg; errBox.style.display = 'block'; }
                function hideError() { errBox.style.display = 'none'; }

                picker.addEventListener('click', function(ev) {
                    var btn = ev.target.closest('button[data-method]');
                    if (!btn) return;
                    ev.preventDefault();
                    hideError();
                    var method = btn.getAttribute('data-method');
                    if (method === 'totp') {
                        picker.style.display = 'none';
                        totpForm.style.display = 'block';
                        document.getElementById('code-totp').focus();
                        return;
                    }
                    btn.disabled = true;
                    var fd = new FormData();
                    fd.append('method', method);
                    // B3 §4: mfa_state travels in the __Host-redb.identity.mfa cookie; no
                    // need to forward it through the fetch body. The challenge response
                    // refreshes the cookie via Set-Cookie for the subsequent verify POST.
                    fetch({{System.Text.Json.JsonSerializer.Serialize(challengePath)}}, { method: 'POST', body: fd, credentials: 'same-origin' })
                      .then(function(r) { return r.json(); })
                      .then(function(j) {
                          btn.disabled = false;
                          if (!j.success) {
                              var msg = j.error === 'rate_limited'
                                  ? 'Too many requests. Try again in ' + (j.retry_after || 60) + 's.'
                                  : (j.error === 'delivery_failed' ? 'Failed to send code. Try again.' : (j.error || 'Request failed'));
                              showError(msg);
                              return;
                          }
                          otpHint.textContent = 'Code sent to ' + (j.masked_destination || 'your device');
                          picker.style.display = 'none';
                          otpForm.style.display = 'block';
                          document.getElementById('code-otp').focus();
                      })
                      .catch(function() { btn.disabled = false; showError('Network error'); });
                });
            })();
            </script>
            """;
    }

    /// <summary>
    /// Legacy-compat helper: extracts <c>mfa_state</c> from the raw query string. Used
    /// only as a fallback when the cookie is absent (e.g. direct link during rollout).
    /// </summary>
    private static string? ExtractMfaStateFromQuery(IExchange e)
    {
        var query = e.In.GetHeader<string>(HttpHeaders.Query);
        if (string.IsNullOrEmpty(query)) return null;
        foreach (var part in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eqIdx = part.IndexOf('=');
            if (eqIdx <= 0) continue;
            if (part[..eqIdx] == "mfa_state")
                return Uri.UnescapeDataString(part[(eqIdx + 1)..]);
        }
        return null;
    }
}
