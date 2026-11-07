using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using redb.Identity.Client.Backchannel;
using redb.Identity.Contracts.Sessions;
using redb.Identity.Contracts.Users;
using redb.Identity.Web.Auth;
using redb.Identity.Web.Services;

namespace redb.Identity.Web.Endpoints;

/// <summary>
/// Browser-facing authentication endpoints. The browser only ever talks to the BFF;
/// credentials are submitted here as a regular form POST and the BFF performs the
/// OIDC code+PKCE handshake against the Identity host server-to-server.
/// </summary>
public static class AuthEndpoints
{
    public static void MapAuthEndpoints(this IEndpointRouteBuilder app)
    {
        // Antiforgery is required: Login.razor injects the hidden __RequestVerificationToken
        // field. Removing the .DisableAntiforgery() call closes F-1.1 from Phase-2 review.
        app.MapPost("/api/auth/login", LoginAsync)
            .AllowAnonymous();

        app.MapPost("/api/auth/logout", LogoutAsync);

        // MFA verification: user is bounced to /mfa-challenge after credentials, posts the
        // verification code back here. State for the in-flight OIDC exchange lives in the
        // signed identity.web.mfa cookie managed by MfaChallengeStateProtector.
        app.MapPost("/api/auth/mfa/verify", MfaVerifyAsync)
            .AllowAnonymous();

        app.MapGet("/api/auth/mfa/cancel", (HttpContext ctx, MfaChallengeStateProtector protector) =>
        {
            protector.ClearCookie(ctx);
            return Results.Redirect("/login?error=mfa_cancelled");
        }).AllowAnonymous();

        // N-2 native consent: user grants/denies through BFF /consent UI.
        // Allow → POST host /consent with captured session cookie, resume authorize,
        // exchange tokens, sign-in. Deny → wipe state cookie, redirect /login.
        app.MapPost("/api/auth/consent/allow", ConsentAllowAsync)
            .AllowAnonymous();
        app.MapGet("/api/auth/consent/cancel", (HttpContext ctx, ConsentChallengeStateProtector protector) =>
        {
            protector.ClearCookie(ctx);
            return Results.Redirect("/login?error=consent_denied");
        }).AllowAnonymous();

        // Back-compat shim: the standard MS OIDC handler challenge points here. We just
        // bounce to the Blazor login page so existing links keep working.
        app.MapGet("/account/login", (HttpContext ctx, string? returnUrl) =>
        {
            var target = "/login";
            if (!string.IsNullOrEmpty(returnUrl))
                target += "?returnUrl=" + Uri.EscapeDataString(returnUrl);
            return Results.Redirect(target);
        }).AllowAnonymous();

        // N-3: federation challenge entry point. Login.razor renders one POST form per
        // configured provider that targets this endpoint with antiforgery + returnUrl.
        // The handler issues a standard OIDC Challenge() against the host but stashes
        // the providerId in AuthenticationProperties.Items["external_provider"]; the
        // OnRedirectToIdentityProvider event in Program.cs wraps the resulting
        // /connect/authorize URL in host's /connect/external-login?provider=...&returnUrl=...
        // so the host drives the IdP round-trip and resumes authorize from its callback.
        // Standard OIDC correlation/nonce/PKCE cookies are minted by the middleware and
        // survive the round-trip — the response still lands on /signin-oidc with the
        // original state value.
        // N-4 (Session C): browser-driven password recovery. Both endpoints are anonymous
        // — the host is the only place that performs the anti-enumeration / single-use
        // checks. The BFF only translates the HTML form POST into a server-to-server call
        // through IBackchannelIdentityClient and redirects back to the appropriate page.
        app.MapPost("/api/auth/password/forgot", PasswordForgotAsync).AllowAnonymous();
        app.MapPost("/api/auth/password/reset", PasswordResetAsync).AllowAnonymous();

        // N4-6: browser-driven e-mail verification.
        //   /send  \u2014 authenticated; the BFF forwards the call to /me/verify-email/send
        //            using the cookie-stored access_token via the typed IIdentityClient.
        //   /confirm \u2014 anonymous; the BFF posts to /account/verify-email/confirm through
        //            the backchannel client (the host bypasses bearer validation on this
        //            prefix). Both endpoints translate HTML form posts into structured
        //            JSON requests and redirect the user back to the appropriate page.
        app.MapPost("/api/auth/account/verify-email/send", VerifyEmailSendAsync);
        app.MapPost("/api/auth/account/verify-email/confirm", VerifyEmailConfirmAsync).AllowAnonymous();

        // N4-7: browser-driven strict change-of-e-mail.
        //   /request — authenticated; forwards to /me/change-email/request via the typed
        //              IIdentityClient (cookie-stored access_token).
        //   /confirm — anonymous; posts to /account/change-email/confirm through the
        //              backchannel client (host bypasses bearer validation on the
        //              account-prefixed routes).
        app.MapPost("/api/auth/account/change-email/request", ChangeEmailRequestAsync);
        app.MapPost("/api/auth/account/change-email/confirm", ChangeEmailConfirmAsync).AllowAnonymous();

        app.MapPost("/auth/federation/{providerId}/start", FederationStartAsync)
            .AllowAnonymous();

        // N-5: end-user device verification (RFC 8628 §3.3, BFF-relayed).
        // Authenticated. The page /device collects user_code + Allow/Deny; we forward
        // the decision to host /connect/device/verify with the cookie-stored access_token
        // as Bearer. The host's HandleVerificationRequestHandler validates the JWT and
        // resolves the principal, so no password is involved.
        app.MapPost("/api/auth/device/verify", DeviceVerifyAsync);

        // N-3 (sub-step N3-7): browser-driven self-service account registration.
        // The Razor /register page submits an antiforgery-protected form here; we
        // proxy the call to the host via the backchannel client (anonymous prefix),
        // and on success immediately sign the new user in through ROPC so the next
        // navigation lands them inside the authenticated shell.
        app.MapPost("/api/auth/register", RegisterAsync).AllowAnonymous();
    }

    private static IResult FederationStartAsync(
        string providerId,
        [FromForm] string? returnUrl,
        HttpContext ctx)
    {
        if (string.IsNullOrWhiteSpace(providerId))
            return RedirectToLoginWithError(returnUrl, "invalid_provider");

        // Defensive: only accept slugs that match the same shape we accept server-side
        // (mirrors CreateFederationProviderRequest.ProviderId regex). Prevents callers
        // from injecting URL-unsafe payload that would survive into the host query.
        if (!System.Text.RegularExpressions.Regex.IsMatch(providerId, "^[a-z0-9][a-z0-9_-]{0,63}$"))
            return RedirectToLoginWithError(returnUrl, "invalid_provider");

        var safeReturn = !string.IsNullOrEmpty(returnUrl) && IsLocalUrl(returnUrl) ? returnUrl : "/";
        var props = new AuthenticationProperties { RedirectUri = safeReturn };
        // Picked up by OnRedirectToIdentityProvider (Program.cs) to rewrite the authorize
        // URL into a host /connect/external-login wrapper.
        props.Items["external_provider"] = providerId;
        return Results.Challenge(props, new[] { OpenIdConnectDefaults.AuthenticationScheme });
    }

    private static async Task<IResult> LoginAsync(
        [FromForm] string username,
        [FromForm] string password,
        [FromForm] string? returnUrl,
        BackchannelOidcClient client,
        MfaChallengeStateProtector mfaProtector,
        ConsentChallengeStateProtector consentProtector,
        HttpContext ctx,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
        {
            return RedirectToLoginWithError(returnUrl, "missing_credentials");
        }

        var result = await client.LoginAsync(username, password, ct);

        if (result.MfaRequired && result.MfaState is not null)
        {
            // Stash returnUrl into the MFA state cookie so we can resume the original
            // navigation after verification.
            var withReturn = result.MfaState with { ReturnUrl = returnUrl };
            mfaProtector.WriteCookie(ctx, withReturn);
            return Results.Redirect("/mfa-challenge");
        }

        if (result.ConsentRequired && result.ConsentState is not null)
        {
            // Stash returnUrl into the consent state cookie so we can resume the original
            // navigation after the user allows/denies on the BFF /consent page.
            var withReturn = result.ConsentState with { ReturnUrl = returnUrl ?? result.ConsentState.ReturnUrl };
            consentProtector.WriteCookie(ctx, withReturn);
            return Results.Redirect("/consent");
        }

        if (!result.Success || result.Principal is null)
        {
            // N6-6: when the host throttles us, extract the retry-after seconds from
            // the descriptive error text and forward it as a structured query param
            // so /login can render a live countdown + disabled button.
            int? retryAfter = null;
            if (result.Error == "rate_limited" && !string.IsNullOrEmpty(result.ErrorDescription))
            {
                var m = System.Text.RegularExpressions.Regex.Match(
                    result.ErrorDescription, @"Retry in (\d+)");
                if (m.Success && int.TryParse(m.Groups[1].Value, out var s))
                    retryAfter = s;
            }
            return RedirectToLoginWithError(returnUrl, result.Error ?? "login_failed", result.ErrorDescription, retryAfter);
        }

        var props = new AuthenticationProperties
        {
            IsPersistent = true,
            ExpiresUtc = result.ExpiresAt,
        };
        if (result.AccessToken is not null)
            AuthenticationTokenExtensions.StoreTokens(props, BuildTokens(result));

        // W6-0: no whitelist mapping — the cookie is admitted unless the cluster-wide
        // blacklist (RevokedSidsCache) lists this sid/sub.

        await ctx.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, result.Principal, props);

        var target = string.IsNullOrEmpty(returnUrl) ? "/" : returnUrl;
        if (!IsLocalUrl(target)) target = "/";
        return Results.Redirect(target);
    }

    private static async Task<IResult> MfaVerifyAsync(
        [FromForm] string code,
        BackchannelOidcClient client,
        MfaChallengeStateProtector mfaProtector,
        HttpContext ctx,
        CancellationToken ct)
    {
        var inflight = mfaProtector.ReadCookie(ctx);
        if (inflight is null)
            return Results.Redirect("/login?error=mfa_expired");

        if (string.IsNullOrWhiteSpace(code))
            return Results.Redirect("/mfa-challenge?error=missing_code");

        var result = await client.VerifyMfaAsync(inflight, code, ct);
        if (!result.Success || result.Principal is null)
        {
            // Keep the state cookie alive on transient invalid_code so the user can retry;
            // wipe it on terminal failures.
            if (result.Error is "locked" or "mfa_no_session" or "state_mismatch" or "oidc_discovery_failed")
                mfaProtector.ClearCookie(ctx);
            return Results.Redirect("/mfa-challenge?error=" + Uri.EscapeDataString(result.Error ?? "invalid_code"));
        }

        mfaProtector.ClearCookie(ctx);

        var props = new AuthenticationProperties
        {
            IsPersistent = true,
            ExpiresUtc = result.ExpiresAt,
        };
        if (result.AccessToken is not null)
            AuthenticationTokenExtensions.StoreTokens(props, BuildTokens(result));

        await ctx.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, result.Principal, props);

        var target = string.IsNullOrEmpty(inflight.ReturnUrl) ? "/" : inflight.ReturnUrl;
        if (!IsLocalUrl(target)) target = "/";
        return Results.Redirect(target);
    }

    private static async Task<IResult> ConsentAllowAsync(
        BackchannelOidcClient client,
        ConsentChallengeStateProtector consentProtector,
        HttpContext ctx,
        CancellationToken ct)
    {
        var inflight = consentProtector.ReadCookie(ctx);
        if (inflight is null)
            return Results.Redirect("/login?error=consent_expired");

        // Record the grant against the host (writes/merges Authorization row via the
        // host's session-based /consent form handler).
        var granted = await client.RecordConsentGrantAsync(inflight, ct);
        if (!granted)
        {
            consentProtector.ClearCookie(ctx);
            return Results.Redirect("/login?error=consent_grant_failed");
        }

        // Replay /connect/authorize and complete the token exchange.
        var result = await client.ResumeAfterConsentAsync(inflight, ct);
        if (!result.Success || result.Principal is null)
        {
            consentProtector.ClearCookie(ctx);
            return RedirectToLoginWithError(inflight.ReturnUrl, result.Error ?? "consent_resume_failed", result.ErrorDescription);
        }

        consentProtector.ClearCookie(ctx);

        var props = new AuthenticationProperties
        {
            IsPersistent = true,
            ExpiresUtc = result.ExpiresAt,
        };
        if (result.AccessToken is not null)
            AuthenticationTokenExtensions.StoreTokens(props, BuildTokens(result));

        await ctx.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, result.Principal, props);

        var target = string.IsNullOrEmpty(inflight.ReturnUrl) ? "/" : inflight.ReturnUrl;
        if (!IsLocalUrl(target)) target = "/";
        return Results.Redirect(target);
    }

    private static async Task<IResult> LogoutAsync(
        HttpContext ctx,
        IBackchannelIdentityClient backchannel,
        IRevokedSidsCache cache,
        CancellationToken ct)
    {
        var sid = ctx.User?.FindFirst("sid")?.Value;
        var sub = ctx.User?.FindFirst("sub")?.Value;

        if (!string.IsNullOrEmpty(sid) || !string.IsNullOrEmpty(sub))
        {
            var expiresAt = DateTimeOffset.UtcNow.AddHours(8); // ~ cookie lifetime upper bound.
            try
            {
                var entry = await backchannel.AddRevokedSidAsync(sid, sub, clientId: null, expiresAt, ct);
                // Apply locally for immediate effect on this replica (other replicas pick it up on poll).
                cache.Apply(new[] { entry });
            }
            catch (Exception ex)
            {
                // Logout must always succeed locally — backchannel publish failure logged but not surfaced.
                ctx.RequestServices.GetService<ILoggerFactory>()
                    ?.CreateLogger("AuthEndpoints").LogWarning(ex,
                        "Failed to publish revoked-sid for sid={Sid} sub={Sub}; local logout proceeds.", sid, sub);
            }
        }

        await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return Results.Redirect("/signed-out");
    }

    private static IEnumerable<AuthenticationToken> BuildTokens(BackchannelLoginResult r)
    {
        if (r.AccessToken is not null)
            yield return new AuthenticationToken { Name = "access_token", Value = r.AccessToken };
        if (r.RefreshToken is not null)
            yield return new AuthenticationToken { Name = "refresh_token", Value = r.RefreshToken };
        if (r.IdToken is not null)
            yield return new AuthenticationToken { Name = "id_token", Value = r.IdToken };
        if (r.ExpiresAt is { } exp)
            yield return new AuthenticationToken { Name = "expires_at", Value = exp.ToString("O") };
    }

    /// <summary>
    /// N-5 BFF-relayed device verification (RFC 8628 §3.3). Requires an authenticated
    /// session. Pulls the cookie-stored access_token and forwards it as a Bearer header
    /// alongside the form-encoded <c>user_code</c> + <c>action</c> to the host's
    /// <c>/connect/device/verify</c> endpoint, then redirects the user to a result page.
    /// </summary>
    private static async Task<IResult> DeviceVerifyAsync(
        [FromForm] string user_code,
        [FromForm] string action,
        BackchannelOidcClient client,
        HttpContext ctx,
        CancellationToken ct)
    {
        if (ctx.User?.Identity?.IsAuthenticated != true)
        {
            var ret = "/device" + (string.IsNullOrEmpty(user_code) ? "" : "?user_code=" + Uri.EscapeDataString(user_code));
            return Results.Redirect("/login?returnUrl=" + Uri.EscapeDataString(ret));
        }

        if (string.IsNullOrWhiteSpace(user_code))
            return Results.Redirect("/device?error=missing_user_code");

        var normalizedAction = string.Equals(action, "deny", StringComparison.OrdinalIgnoreCase) ? "deny" : "allow";

        var accessToken = await ctx.GetTokenAsync(CookieAuthenticationDefaults.AuthenticationScheme, "access_token");
        if (string.IsNullOrEmpty(accessToken))
        {
            // Cookie outlived the access_token (no refresh token, or refresh failed).
            // Bounce the user through login so we can mint a fresh bearer before resuming.
            var ret = "/device?user_code=" + Uri.EscapeDataString(user_code);
            return Results.Redirect("/login?returnUrl=" + Uri.EscapeDataString(ret));
        }

        var result = await client.VerifyDeviceCodeAsync(user_code, normalizedAction, accessToken, ct);
        if (!result.Success)
        {
            var qs = "/device?user_code=" + Uri.EscapeDataString(user_code)
                   + "&error=" + Uri.EscapeDataString(result.Error ?? "verify_failed");
            if (!string.IsNullOrEmpty(result.ErrorDescription))
                qs += "&error_detail=" + Uri.EscapeDataString(result.ErrorDescription);
            return Results.Redirect(qs);
        }

        return Results.Redirect("/device/done?action=" + normalizedAction);
    }

    private static IResult RedirectToLoginWithError(string? returnUrl, string error, string? detail = null, int? retryAfter = null)
    {
        var target = "/login?error=" + Uri.EscapeDataString(error);
        if (!string.IsNullOrEmpty(detail))
            target += "&error_detail=" + Uri.EscapeDataString(detail);
        if (retryAfter is { } ra && ra > 0)
            target += "&retry_after=" + ra;
        if (!string.IsNullOrEmpty(returnUrl))
            target += "&returnUrl=" + Uri.EscapeDataString(returnUrl);
        return Results.Redirect(target);
    }

    private static bool IsLocalUrl(string url) =>
        !string.IsNullOrEmpty(url)
        && url.StartsWith('/')
        && (url.Length == 1 || (url[1] != '/' && url[1] != '\\'));

    private static async Task<IResult> PasswordForgotAsync(
        [FromForm] string email,
        HttpContext ctx,
        IBackchannelIdentityClient backchannel,
        IOptionsMonitor<OpenIdConnectOptions> oidcOptions,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(email))
            return Results.Redirect("/forgot-password?error=missing_email");

        // The host enforces a per-client URL whitelist; reuse the BFF's own /reset-password
        // page as the caller URL. The host must have it on ApplicationProps.PasswordResetUris
        // for the OIDC client this BFF uses — a host-side configuration concern.
        var req = ctx.Request;
        var callerResetUrl = $"{req.Scheme}://{req.Host.Value}/reset-password";
        var clientId = oidcOptions.Get(OpenIdConnectDefaults.AuthenticationScheme).ClientId ?? "";

        try
        {
            await backchannel.ForgotPasswordAsync(new PasswordForgotRequest
            {
                Email = email,
                ClientId = clientId,
                CallerResetUrl = callerResetUrl
            }, ct);
        }
        catch (Exception ex)
        {
            // Anti-enumeration: never propagate transport failures to the UI — the user-
            // visible response is always the same "if an account exists…" copy.
            ctx.RequestServices.GetService<ILoggerFactory>()
                ?.CreateLogger("AuthEndpoints.PasswordForgot")
                .LogWarning(ex, "Backchannel password-forgot failed; UI still shows generic success.");
        }

        return Results.Redirect("/forgot-password?sent=1");
    }

    private static async Task<IResult> PasswordResetAsync(
        [FromForm] string token,
        [FromForm] string jti,
        [FromForm] string newPassword,
        [FromForm] string confirmPassword,
        IBackchannelIdentityClient backchannel,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(token) || string.IsNullOrWhiteSpace(jti)
            || string.IsNullOrWhiteSpace(newPassword) || string.IsNullOrWhiteSpace(confirmPassword))
        {
            return RedirectToResetWithError(jti, token, "missing_fields");
        }
        if (!string.Equals(newPassword, confirmPassword, StringComparison.Ordinal))
        {
            return RedirectToResetWithError(jti, token, "password_mismatch");
        }

        var result = await backchannel.ResetPasswordAsync(new PasswordResetRequest
        {
            Jti = jti,
            Token = token,
            NewPassword = newPassword
        }, ct);

        if (!result.Success)
        {
            var err = string.IsNullOrEmpty(result.Error) ? "invalid_token" : result.Error;
            return RedirectToResetWithError(jti, token, err);
        }

        return Results.Redirect("/login?error=&info=password_reset");
    }

    private static IResult RedirectToResetWithError(string? jti, string? token, string error)
    {
        var target = "/reset-password?error=" + Uri.EscapeDataString(error);
        if (!string.IsNullOrEmpty(jti)) target += "&jti=" + Uri.EscapeDataString(jti);
        if (!string.IsNullOrEmpty(token)) target += "&token=" + Uri.EscapeDataString(token);
        return Results.Redirect(target);
    }

    // ── N4-6: e-mail verification ─────────────────────────────────────────

    private static async Task<IResult> VerifyEmailSendAsync(
        HttpContext ctx,
        redb.Identity.Client.IIdentityClient identity,
        IOptionsMonitor<OpenIdConnectOptions> oidcOptions,
        CancellationToken ct)
    {
        // Authenticated endpoint \u2014 the user must already be signed in (cookie). The typed
        // IIdentityClient is wired with HttpContextAccessTokenProvider so the call to
        // /me/verify-email/send rides the cookie-stored access_token.
        if (ctx.User?.Identity is not System.Security.Claims.ClaimsIdentity { IsAuthenticated: true })
            return Results.Redirect("/login");

        var req = ctx.Request;
        var callerVerifyUrl = $"{req.Scheme}://{req.Host.Value}/verify-email";
        var clientId = oidcOptions.Get(OpenIdConnectDefaults.AuthenticationScheme).ClientId ?? "";

        try
        {
            await identity.VerifyEmailSendAsync(new EmailVerifySendRequest
            {
                ClientId = clientId,
                CallerVerifyUrl = callerVerifyUrl
            }, ct);
        }
        catch (Exception ex)
        {
            ctx.RequestServices.GetService<ILoggerFactory>()
                ?.CreateLogger("AuthEndpoints.VerifyEmailSend")
                .LogWarning(ex, "Backchannel verify-email-send failed; UI still shows generic success.");
        }

        return Results.Redirect("/profile?info=verify_email_sent");
    }

    private static async Task<IResult> VerifyEmailConfirmAsync(
        [FromForm] string token,
        [FromForm] string jti,
        IBackchannelIdentityClient backchannel,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(token) || string.IsNullOrWhiteSpace(jti))
            return Results.Redirect("/verify-email?error=missing_fields");

        var result = await backchannel.VerifyEmailConfirmAsync(new EmailVerifyConfirmRequest
        {
            Jti = jti,
            Token = token
        }, ct);

        if (!result.Success)
        {
            var err = string.IsNullOrEmpty(result.Error) ? "invalid_token" : result.Error;
            return Results.Redirect($"/verify-email?error={Uri.EscapeDataString(err)}");
        }

        return Results.Redirect("/verify-email?confirmed=1");
    }

    // ── N4-7: strict change-of-e-mail ──────────────────────────────────────────

    private static async Task<IResult> ChangeEmailRequestAsync(
        HttpContext ctx,
        [FromForm] string newEmail,
        redb.Identity.Client.IIdentityClient identity,
        IOptionsMonitor<OpenIdConnectOptions> oidcOptions,
        CancellationToken ct)
    {
        // Authenticated endpoint — the user must already be signed in (cookie). The typed
        // IIdentityClient is wired with HttpContextAccessTokenProvider so the call to
        // /me/change-email/request rides the cookie-stored access_token.
        if (ctx.User?.Identity is not System.Security.Claims.ClaimsIdentity { IsAuthenticated: true })
            return Results.Redirect("/login");

        if (string.IsNullOrWhiteSpace(newEmail))
            return Results.Redirect("/me/profile?error=change_email_missing");

        var req = ctx.Request;
        var callerConfirmUrl = $"{req.Scheme}://{req.Host.Value}/change-email";
        var clientId = oidcOptions.Get(OpenIdConnectDefaults.AuthenticationScheme).ClientId ?? "";

        try
        {
            await identity.ChangeEmailRequestAsync(new ChangeEmailRequestRequest
            {
                NewEmail = newEmail,
                ClientId = clientId,
                CallerConfirmUrl = callerConfirmUrl,
            }, ct);
        }
        catch (Exception ex)
        {
            // Surface a generic 'request_failed' marker so the profile page can show a
            // soft warning without leaking whether the address was taken vs. some other
            // server-side reason. Granular failure is in the host audit log.
            ctx.RequestServices.GetService<ILoggerFactory>()
                ?.CreateLogger("AuthEndpoints.ChangeEmailRequest")
                .LogWarning(ex, "Backchannel change-email-request failed; UI shows generic info banner.");
            return Results.Redirect("/me/profile?error=change_email_failed");
        }

        return Results.Redirect("/me/profile?info=change_email_sent");
    }

    private static async Task<IResult> ChangeEmailConfirmAsync(
        [FromForm] string token,
        [FromForm] string jti,
        IBackchannelIdentityClient backchannel,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(token) || string.IsNullOrWhiteSpace(jti))
            return Results.Redirect("/change-email?error=missing_fields");

        var result = await backchannel.ChangeEmailConfirmAsync(new ChangeEmailConfirmRequest
        {
            Jti = jti,
            Token = token,
        }, ct);

        if (!result.Success)
        {
            var err = string.IsNullOrEmpty(result.Error) ? "invalid_token" : result.Error;
            return Results.Redirect($"/change-email?error={Uri.EscapeDataString(err)}");
        }

        return Results.Redirect("/change-email?confirmed=1");
    }

    // ── N-3 (sub-step N3-7): self-service account registration ──

    private static async Task<IResult> RegisterAsync(
        [FromForm] string login,
        [FromForm] string email,
        [FromForm] string password,
        [FromForm] string confirmPassword,
        [FromForm] string? displayName,
        IBackchannelIdentityClient backchannel,
        BackchannelOidcClient oidcClient,
        HttpContext ctx,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(login)
            || string.IsNullOrWhiteSpace(email)
            || string.IsNullOrWhiteSpace(password)
            || string.IsNullOrWhiteSpace(confirmPassword))
        {
            return RedirectToRegisterWithError(login, email, displayName, "missing_fields");
        }
        if (!string.Equals(password, confirmPassword, StringComparison.Ordinal))
        {
            return RedirectToRegisterWithError(login, email, displayName, "password_mismatch");
        }

        RegisterAccountResponse result;
        try
        {
            result = await backchannel.RegisterAccountAsync(new RegisterAccountRequest
            {
                Login = login,
                Email = email,
                Password = password,
                DisplayName = string.IsNullOrWhiteSpace(displayName) ? null : displayName,
            }, ct);
        }
        catch (Exception ex)
        {
            ctx.RequestServices.GetService<ILoggerFactory>()
                ?.CreateLogger("AuthEndpoints.Register")
                .LogWarning(ex, "Backchannel register call failed; redirecting with generic error.");
            return RedirectToRegisterWithError(login, email, displayName, "registration_failed");
        }

        if (!result.Success)
        {
            var code = string.IsNullOrEmpty(result.Error) ? "registration_failed" : result.Error;
            return RedirectToRegisterWithError(login, email, displayName, code, result.ErrorDescription);
        }

        // Auto sign-in via ROPC — the new credentials are guaranteed valid because we
        // just minted them. On failure we redirect to /login with an informational hint;
        // the account already exists, so the user can simply sign in manually.
        var loginResult = await oidcClient.LoginAsync(login, password, ct);
        if (!loginResult.Success || loginResult.Principal is null)
        {
            return Results.Redirect("/login?info=registered");
        }

        var props = new AuthenticationProperties
        {
            IsPersistent = true,
            ExpiresUtc = loginResult.ExpiresAt,
        };
        if (loginResult.AccessToken is not null)
            AuthenticationTokenExtensions.StoreTokens(props, BuildTokens(loginResult));

        await ctx.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, loginResult.Principal, props);
        return Results.Redirect("/?welcome=1");
    }

    private static IResult RedirectToRegisterWithError(
        string? login, string? email, string? displayName,
        string error, string? detail = null)
    {
        var target = "/register?error=" + Uri.EscapeDataString(error);
        if (!string.IsNullOrEmpty(detail))
            target += "&error_detail=" + Uri.EscapeDataString(detail);
        if (!string.IsNullOrEmpty(login))
            target += "&login=" + Uri.EscapeDataString(login);
        if (!string.IsNullOrEmpty(email))
            target += "&email=" + Uri.EscapeDataString(email);
        if (!string.IsNullOrEmpty(displayName))
            target += "&displayName=" + Uri.EscapeDataString(displayName);
        return Results.Redirect(target);
    }
}
