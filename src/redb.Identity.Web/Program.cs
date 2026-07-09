using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Options;
using redb.Identity.Client;
using redb.Identity.Client.Auth;
using redb.Identity.Client.Backchannel;
using redb.Identity.Web.Auth;
using redb.Identity.Web.Bootstrap;
using redb.Identity.Web.Components;
using redb.Identity.Web.Configuration;
using redb.Identity.Web.Endpoints;
using redb.Identity.Web.Services;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

// --- Logging ---
builder.Host.UseSerilog((ctx, cfg) => cfg
    .ReadFrom.Configuration(ctx.Configuration)
    .WriteTo.Console()
    .WriteTo.File("Logs/identity-web-.log", rollingInterval: RollingInterval.Day));

// --- Options ---
builder.Services.Configure<IdentityWebOptions>(builder.Configuration.GetSection("Identity"));
builder.Services.Configure<BootstrapOptions>(builder.Configuration.GetSection("Bootstrap"));
builder.Services.Configure<SecurityHeadersOptions>(builder.Configuration.GetSection("Identity:Web:SecurityHeaders"));
builder.Services.Configure<IdentityWebLinksOptions>(builder.Configuration.GetSection("Identity:Web:Links"));
var idOpts = builder.Configuration.GetSection("Identity").Get<IdentityWebOptions>()
    ?? throw new InvalidOperationException("Missing 'Identity' configuration section");

// --- Razor + Blazor Server ---
builder.Services.AddRazorComponents().AddInteractiveServerComponents();
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<ToastService>();
builder.Services.AddScoped<UndoToastService>();

// --- Identity Client SDK (BFF → management API) ---
builder.Services.AddIdentityClient(opts =>
{
    opts.BaseUrl = new Uri(idOpts.ApiBaseUrl);
});
builder.Services.AddSingleton<IAccessTokenProvider, HttpContextAccessTokenProvider>();

// --- Backchannel OIDC client: BFF performs the entire authorization-code+PKCE
// flow server-to-server so the browser never sees the Identity host. ---
builder.Services.Configure<BackchannelOidcOptions>(o =>
{
    o.Authority = idOpts.Authority;
    o.ClientId = idOpts.ClientId;
    var secret = idOpts.ClientSecret;
    if (!string.IsNullOrEmpty(secret) && !secret.StartsWith("set-via-", StringComparison.OrdinalIgnoreCase))
        o.ClientSecret = secret;
    if (idOpts.Scopes is { Length: > 0 } sc)
        o.Scopes = sc;
});
builder.Services.AddHttpClient<BackchannelOidcClient>((sp, http) =>
{
    var opts = sp.GetRequiredService<IOptions<BackchannelOidcOptions>>().Value;
    http.BaseAddress = new Uri(opts.Authority);
});

// MFA in-flight state cookie protector (carries the encrypted host MFA cookie +
// the original PKCE material across the /mfa-challenge round-trip).
builder.Services.AddSingleton<MfaChallengeStateProtector>();

// N-2 native consent: similar in-flight cookie that carries the host session
// cookie jar + original authorize parameters across the BFF /consent UI round-trip.
builder.Services.AddSingleton<ConsentChallengeStateProtector>();

// N7-3: admin impersonation overlay cookie protector.
builder.Services.AddSingleton<ImpersonationStateProtector>();

// --- BCL infrastructure ---
// W6-0: cluster-correct back-channel logout. Each replica polls
// /api/v1/identity/revoked-sids/since for the cluster-wide blacklist and
// refuses cookies whose sid/sub is present.
builder.Services.AddSingleton<IRevokedSidsCache, RevokedSidsCache>();
builder.Services.AddBackchannelIdentityClient(o =>
{
    o.BaseUrl = new Uri(idOpts.ApiBaseUrl);
    o.ClientId = idOpts.BackchannelClient.ClientId;
    o.ClientSecret = idOpts.BackchannelClient.ClientSecret;
    o.Scopes = idOpts.BackchannelClient.Scopes;
});
builder.Services.AddHostedService<RevokedSidsPollHostedService>();

builder.Services.AddSingleton<IConfigurationManager<OpenIdConnectConfiguration>>(_ =>
{
    var metadata = !string.IsNullOrWhiteSpace(idOpts.MetadataAddress)
        ? idOpts.MetadataAddress
        : $"{idOpts.Authority.TrimEnd('/')}/.well-known/openid-configuration";
    return new ConfigurationManager<OpenIdConnectConfiguration>(
        metadata,
        new OpenIdConnectConfigurationRetriever(),
        new HttpDocumentRetriever { RequireHttps = idOpts.RequireHttpsMetadata });
});

// --- Bootstrap seeder (HostedService, no-op if disabled) ---
builder.Services.AddHttpClient("Bootstrap");
builder.Services.AddHostedService<BootstrapAdminSeeder>();

// --- Cookie + OIDC ---
if (builder.Environment.IsDevelopment())
{
    IdentityModelEventSource.ShowPII = true;
}

builder.Services.AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        // Challenge via the cookie scheme — its LoginPath redirects unauthenticated
        // users to the BFF's own /login Blazor page (backchannel flow). The OIDC
        // handler is still registered below for back-compat / direct test access.
        options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    })
    .AddCookie(options =>
    {
        options.Cookie.Name = "identity.web.session";
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.ExpireTimeSpan = TimeSpan.FromHours(8);
        options.SlidingExpiration = true;
        options.LoginPath = "/login";
        options.AccessDeniedPath = "/login";

        // BCL: drop cookie if the session sid/sub appears in the cluster-wide
        // revoked-sids blacklist (W6-0). Replaces the previous single-instance
        // whitelist (InMemorySidIndex).
        options.Events.OnValidatePrincipal = async ctx =>
        {
            var sid = ctx.Principal?.FindFirst("sid")?.Value;
            var sub = ctx.Principal?.FindFirst("sub")?.Value;
            if (sid is null && sub is null) return;
            var cache = ctx.HttpContext.RequestServices.GetRequiredService<IRevokedSidsCache>();
            if (cache.IsRevoked(sid, sub))
            {
                ctx.RejectPrincipal();
                await ctx.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            }
        };
    })
    .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
    {
        options.Authority = idOpts.Authority;
        if (!string.IsNullOrWhiteSpace(idOpts.MetadataAddress))
            options.MetadataAddress = idOpts.MetadataAddress;
        options.RequireHttpsMetadata = idOpts.RequireHttpsMetadata;
        options.ClientId = idOpts.ClientId;
        // Public OIDC client (PKCE-only). Send client_secret only when explicitly configured
        // with a real value — appsettings.Development.json carries a placeholder
        // "set-via-user-secrets-or-env" that would otherwise be transmitted as the secret
        // and rejected by OpenIddict with invalid_client.
        var secret = idOpts.ClientSecret;
        if (!string.IsNullOrEmpty(secret)
            && !secret.StartsWith("set-via-", StringComparison.OrdinalIgnoreCase))
        {
            options.ClientSecret = secret;
        }
        options.ResponseType = OpenIdConnectResponseType.Code;
        // Use query response_mode: the host (127.0.0.1) and the BFF (localhost) are
        // different sites, so a form_post POST back to /signin-oidc is cross-site and
        // browsers strip SameSite=Lax correlation/nonce cookies → "Correlation failed".
        // A top-level GET redirect (query mode) preserves Lax cookies on safe navigation.
        options.ResponseMode = "query";
        options.UsePkce = true;
        options.SaveTokens = true;
        options.GetClaimsFromUserInfoEndpoint = true;
        options.MapInboundClaims = false;
        // Disable Pushed Authorization Requests (RFC 9126) — host advertises the endpoint via OpenIddict
        // discovery doc but PAR isn't wired/working end-to-end yet. Fall back to plain redirect to /connect/authorize.
        options.PushedAuthorizationBehavior = Microsoft.AspNetCore.Authentication.OpenIdConnect.PushedAuthorizationBehavior.Disable;

        options.Scope.Clear();
        foreach (var s in idOpts.Scopes) options.Scope.Add(s);

        options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;

        options.TokenValidationParameters = new TokenValidationParameters
        {
            NameClaimType = "preferred_username",
            RoleClaimType = "roles",
        };

        options.Events.OnTokenValidated = ctx =>
        {
            // W6-0: no whitelist mapping needed — blacklist (RevokedSidsCache) handles
            // backchannel logout. Hook retained for future correlation logging.
            return Task.CompletedTask;
        };

        // N-3: federation — when the challenge originated from a federation button on
        // the BFF's /login page, the calling endpoint stashes `external_provider` in
        // AuthenticationProperties.Items. Intercept the standard /connect/authorize
        // redirect and wrap it in host's /connect/external-login, which lets the host
        // drive the IdP round-trip and then resume the original authorize request from
        // its returnUrl. The OIDC middleware's correlation/nonce/PKCE cookies survive
        // the round-trip unchanged because the response still comes back to the original
        // redirect_uri (/signin-oidc) with the original state.
        options.Events.OnRedirectToIdentityProvider = ctx =>
        {
            if (ctx.Properties.Items.TryGetValue("external_provider", out var providerId)
                && !string.IsNullOrWhiteSpace(providerId))
            {
                var authorizeUrl = ctx.ProtocolMessage.CreateAuthenticationRequestUrl();
                var authority = idOpts.Authority.TrimEnd('/');
                ctx.ProtocolMessage.IssuerAddress =
                    $"{authority}/connect/external-login"
                    + $"?provider={Uri.EscapeDataString(providerId)}"
                    + $"&returnUrl={Uri.EscapeDataString(authorizeUrl)}";
                // CreateAuthenticationRequestUrl() will be called again by the middleware
                // when it actually issues the 302 — at that point IssuerAddress is the
                // external-login URL and the original authorize parameters live in the
                // appended query string from our wrap. Clear the protocol message params
                // so the middleware does not re-append them to the new IssuerAddress.
                ctx.ProtocolMessage.Parameters.Clear();
            }
            return Task.CompletedTask;
        };

        options.Events.OnRemoteFailure = ctx =>
        {
            // N6-3: classify OIDC failures so /Error can show a meaningful
            // reason code instead of an opaque "oidc-failure" string. The
            // OpenIdConnectProtocolException carries the protocol-level
            // error (e.g. invalid_request, access_denied) which we surface
            // as the reason; the human-readable message becomes the detail.
            var failure = ctx.Failure;
            var reason = "oidc-failure";
            var detail = failure?.Message;
            if (failure is OpenIdConnectProtocolException oie)
            {
                // Use the exception type name as a stable, log-friendly tag.
                reason = oie.GetType().Name;
            }

            var target = "/Error?reason=" + Uri.EscapeDataString(reason);
            if (!string.IsNullOrEmpty(detail))
                target += "&detail=" + Uri.EscapeDataString(detail.Length > 400 ? detail[..400] : detail);
            ctx.Response.Redirect(target);
            ctx.HandleResponse();
            return Task.CompletedTask;
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("identity.manage", p => p
        .RequireAuthenticatedUser()
        .RequireClaim("scope", "identity:manage"));

    // N7-1 — granular admin policies. Each accepts the master "identity:manage"
    // scope OR its specific granular scope, so existing full-admin tokens still
    // pass every gate. Nav items / pages should prefer the granular policy to
    // hide UI for which the user has no scope.
    static void AddGranular(Microsoft.AspNetCore.Authorization.AuthorizationOptions opts, string name, string scope)
    {
        opts.AddPolicy(name, p => p
            .RequireAuthenticatedUser()
            .RequireAssertion(ctx =>
            {
                foreach (var c in ctx.User.FindAll("scope"))
                {
                    if (c.Value == "identity:manage" || c.Value == scope) return true;
                }
                return false;
            }));
    }

    AddGranular(options, "identity.read",                "identity:read");
    AddGranular(options, "identity.users.manage",        "identity:users.manage");
    AddGranular(options, "identity.sessions.manage",     "identity:sessions.manage");
    AddGranular(options, "identity.audit.read",          "identity:audit.read");
    AddGranular(options, "identity.applications.manage", "identity:applications.manage");
    AddGranular(options, "identity.impersonate",         "identity:impersonate");
});

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

// Production-grade response security headers (CSP/HSTS/XFO/Permissions-Policy/...).
// Closes F-2.5 from Phase-2 critical review. Configure via Identity:Web:SecurityHeaders.
app.UseMiddleware<SecurityHeadersMiddleware>();

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseSerilogRequestLogging();

app.UseAuthentication();
app.UseAuthorization();

app.UseAntiforgery();

// Backchannel auth endpoints: /login form posts to /api/auth/login, BFF handles
// OIDC handshake server-to-server, returns Set-Cookie + 302 to returnUrl.
app.MapAuthEndpoints();
app.MapImpersonationEndpoints();

app.MapGet("/health", () => Results.Ok(new { status = "ok", time = DateTimeOffset.UtcNow }))
   .AllowAnonymous();

app.MapBackchannelLogoutSink();

app.MapRazorComponents<App>().AddInteractiveServerRenderMode();

try
{
    Log.Information("Starting redb.Identity.Web on {Urls}", string.Join(", ", app.Urls));
    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Host terminated unexpectedly");
}
finally
{
    Log.CloseAndFlush();
}

// Required by redb.Identity.Web.Tests (WebApplicationFactory<Program>)
public partial class Program { }
