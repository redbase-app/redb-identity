using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Validation;
using redb.Core.Models.Entities;
using redb.Core.Security;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.DataProtection;
using redb.Identity.DataProtection;
using redb.Identity.Contracts.Cors;
using redb.Identity.Core.Routes.Processors;
using redb.Identity.Core.Models;
using redb.Identity.Core.OpenIddict;
using redb.Identity.Core.Health;
using redb.Identity.Core.Security;
using redb.Identity.Core.Serialization;
using redb.Identity.Core.Services;
using redb.Identity.Core.Stores;
using redb.Route.Extensions;
using redb.Tsak.Core.Contracts;
using redb.Identity.Core.Routes;

namespace redb.Identity.Core;

public static class RedbIdentityServiceExtensions
{
    /// <summary>
    /// Registers the full redb Identity Server: OpenIddict Core (stores) + Server (pipeline + flows + keys).
    /// This is the single production entry point. Tests may call this with options configured for test scenarios.
    /// </summary>
    public static IServiceCollection AddRedbIdentityServer(
        this IServiceCollection services,
        RedbIdentityOptions options)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(options);

        // Ensure TimeProvider is registered for non-tpkg DI paths (IdentityModuleHost
        // already registers it explicitly; this covers direct AddRedbIdentityServer use).
        services.TryAddSingleton(TimeProvider.System);

        // Register locked Identity codec profiles (SCIM, Problem Details) into the
        // route context's IDataFormatRegistry at engine-start time. OAuth/OIDC/DCR
        // profile is intentionally not registered — it is used directly by processors
        // so app-level ConfigureJsonCodec cannot reshape the OAuth wire format.
        services.AddSingleton<IRouteContextConfigurator, IdentityCodecProfilesConfigurator>();

        // Apply configurable input-length limits used by the validation helpers.
        Routes.Processors.IdentityProcessorHelpers.Configure(options.Validation);

        // H10 — register the password policy options + default validator. The validator
        // resolves IPasswordHistoryStore / IBreachedPasswordChecker as optional deps from
        // the same scope, so Phase 2/5 plug in without re-registering anything here.
        services.AddSingleton(options.PasswordPolicy);
        services.AddSingleton<Security.IPasswordHistoryStore, Security.PropsPasswordHistoryStore>();
        services.AddScoped<Security.IPasswordPolicyValidator>(sp =>
            new Security.DefaultPasswordPolicyValidator(
                sp.GetRequiredService<Configuration.PasswordPolicyOptions>(),
                sp.GetService<Security.IPasswordHistoryStore>(),
                sp.GetService<Security.IBreachedPasswordChecker>()));

        services.AddOpenIddict()
            .AddCore(core =>
            {
                core.UseRedbStores();
                // Disable OpenIddict's built-in entity cache (OpenIddictApplicationCache<>,
                // OpenIddictAuthorizationCache<>, etc.). Those caches are registered as
                // Singletons and capture a scoped IOpenIddictXxxStore on first resolve,
                // which transitively captive-captures the underlying scoped IRedbService
                // (and its single NpgsqlConnection). Under concurrent load the captive
                // connection then races with itself and throws
                // NpgsqlOperationInProgressException ("A command is already in progress"
                // / "connection is already in state 'Copy'"). Disabling the cache makes
                // managers call the store directly through the current request scope, so
                // each request gets its own IRedbService/connection from the DI scope
                // factory (host bridge or root SP). The cost is a few extra SELECTs per
                // OAuth flow which is negligible against PROPS query overhead.
                core.DisableEntityCaching();
            })
            .AddServer(server =>
            {
                server.SetIssuer(options.Issuer);

                // Endpoint URIs (relative — OpenIddict resolves against issuer)
                server.SetTokenEndpointUris("/connect/token");
                server.SetAuthorizationEndpointUris("/connect/authorize");
                server.SetUserInfoEndpointUris("/connect/userinfo");
                server.SetIntrospectionEndpointUris("/connect/introspect");
                server.SetRevocationEndpointUris("/connect/revoke");
                server.SetConfigurationEndpointUris("/.well-known/openid-configuration");
                server.SetJsonWebKeySetEndpointUris("/.well-known/jwks");

                // Grant types
                server.AllowClientCredentialsFlow();
                server.AllowAuthorizationCodeFlow();
                server.AllowRefreshTokenFlow();
                server.RequireProofKeyForCodeExchange();
                // OAuth 2.1 / RFC 7636 §4.2: forbid `plain`, allow only S256.
                server.Configure(o =>
                {
                    o.CodeChallengeMethods.Clear();
                    o.CodeChallengeMethods.Add(OpenIddictConstants.CodeChallengeMethods.Sha256);
                });

                // Device Code Flow (RFC 8628)
                if (options.Features.EnableDeviceCodeFlow)
                {
                    server.SetDeviceAuthorizationEndpointUris("/connect/deviceauthorization");
                    server.SetEndUserVerificationEndpointUris("/connect/device/verify");
                    server.AllowDeviceAuthorizationFlow();
                }

                // Pushed Authorization Requests (RFC 9126 / Z6)
                if (options.Features.EnablePushedAuthorization)
                {
                    server.SetPushedAuthorizationEndpointUris("/connect/par");
                    if (options.RequirePushedAuthorizationRequests)
                        server.RequirePushedAuthorizationRequests();
                }

                // ROPC: grant_type=password (opt-in)
                if (options.EnablePasswordFlow)
                    server.AllowPasswordFlow();

                // Token Exchange: grant_type=urn:ietf:params:oauth:grant-type:token-exchange (opt-in, RFC 8693)
                if (options.EnableTokenExchange)
                    server.AllowCustomFlow("urn:ietf:params:oauth:grant-type:token-exchange");

                // Token lifetimes
                server.SetAccessTokenLifetime(options.AccessTokenLifetime);
                server.SetRefreshTokenLifetime(options.RefreshTokenLifetime);
                server.SetRefreshTokenReuseLeeway(options.RefreshTokenReuseLeeway);
                server.SetAuthorizationCodeLifetime(options.AuthorizationCodeLifetime);
                server.SetIdentityTokenLifetime(options.IdentityTokenLifetime);

                if (options.Features.EnableDeviceCodeFlow)
                    server.SetDeviceCodeLifetime(options.DeviceCodeLifetime);

                // Signing & encryption credentials
                if (options.SigningCredentials.Count > 0)
                {
                    foreach (var cred in options.SigningCredentials)
                        server.AddSigningCredentials(cred);
                }
                else if (options.AllowEphemeralKeys)
                {
                    server.AddEphemeralSigningKey();
                }
                else if (options.UsePropsSigningKeyStore)
                {
                    // A3: credentials are appended from the PROPS store via a deferred
                    // IPostConfigureOptions<OpenIddictServerOptions> below. Nothing to do here.
                }
                else
                {
                    throw new InvalidOperationException(
                        "redb.Identity: no signing credentials configured and AllowEphemeralKeys=false. " +
                        "Ephemeral keys split the JWKS across cluster replicas and invalidate every live " +
                        "token on restart — they are blocked in production. " +
                        "Either populate RedbIdentityOptions.SigningCredentials with persistent keys, " +
                        "enable UsePropsSigningKeyStore=true for the A3 persistent PROPS store, " +
                        "or set RedbIdentityOptions.AllowEphemeralKeys=true for Development / test scenarios.");
                }

                if (options.EncryptionCredentials.Count > 0)
                {
                    foreach (var cred in options.EncryptionCredentials)
                        server.AddEncryptionCredentials(cred);
                }
                else if (options.AllowEphemeralKeys)
                {
                    server.AddEphemeralEncryptionKey();
                }
                else if (options.UsePropsSigningKeyStore)
                {
                    // A3: appended from PROPS store below.
                }
                else if (!options.DisableAccessTokenEncryption)
                {
                    // Encryption is only required when access-token encryption is enabled. If the
                    // operator has explicitly disabled it (DisableAccessTokenEncryption=true) we do
                    // not force them to provision encryption keys.
                    throw new InvalidOperationException(
                        "redb.Identity: no encryption credentials configured and AllowEphemeralKeys=false. " +
                        "Either populate RedbIdentityOptions.EncryptionCredentials, set " +
                        "DisableAccessTokenEncryption=true to opt out of token encryption entirely, " +
                        "enable UsePropsSigningKeyStore=true for the A3 persistent PROPS store, " +
                        "or set AllowEphemeralKeys=true for Development / test scenarios.");
                }

                if (options.DisableAccessTokenEncryption)
                    server.DisableAccessTokenEncryption();

                // Register scopes
                server.RegisterScopes(
                    OpenIddictConstants.Scopes.OpenId,
                    OpenIddictConstants.Scopes.Profile,
                    OpenIddictConstants.Scopes.Email,
                    OpenIddictConstants.Scopes.Phone,
                    OpenIddictConstants.Scopes.Address,
                    OpenIddictConstants.Scopes.OfflineAccess,
                    options.ManagementScope,
                    options.AccountScope,
                    "groups",
                    "roles");

                // N7-1 — register granular admin scopes so OpenIddict accepts them in
                // /connect/token requests. The per-path GranularScopeGuardProcessor in
                // the HTTP facade enforces which routes accept which scope at runtime.
                // Tokens carrying Manage retain full access (master scope).
                server.RegisterScopes(redb.Identity.Contracts.Configuration.IdentityScopes.GranularAdmin);

                // SCIM scope (RFC 7644)
                if (options.Features.EnableScim)
                    server.RegisterScopes(options.ScimScope);

                // B0.1: Register any custom scopes that are gated by group membership
                // via RestrictScopeByGroupMembershipHandler. They must be advertised
                // here so OpenIddict accepts them in /connect/token requests; the
                // handler then enforces the group requirement at sign-in time.
                if (options.ScopeRequiredGroups is { Count: > 0 } gated)
                {
                    foreach (var gatedScope in gated.Keys)
                    {
                        if (!string.IsNullOrWhiteSpace(gatedScope))
                            server.RegisterScopes(gatedScope);
                    }
                }

                // D1: Register claims advertised in /.well-known/openid-configuration
                // (claims_supported field). Without this OpenIddict emits an empty list
                // which fails OIDC Discovery 1.0 §3 conformance.
                server.RegisterClaims(
                    OpenIddictConstants.Claims.Subject,
                    OpenIddictConstants.Claims.Issuer,
                    OpenIddictConstants.Claims.Audience,
                    OpenIddictConstants.Claims.ExpiresAt,
                    OpenIddictConstants.Claims.IssuedAt,
                    OpenIddictConstants.Claims.Nonce,
                    OpenIddictConstants.Claims.AuthenticationTime,
                    OpenIddictConstants.Claims.AuthenticationMethodReference,
                    OpenIddictConstants.Claims.AuthorizedParty,
                    OpenIddictConstants.Claims.JwtId,
                    OpenIddictConstants.Claims.Name,
                    OpenIddictConstants.Claims.PreferredUsername,
                    OpenIddictConstants.Claims.Email,
                    OpenIddictConstants.Claims.EmailVerified,
                    OpenIddictConstants.Claims.PhoneNumber,
                    OpenIddictConstants.Claims.PhoneNumberVerified,
                    OpenIddictConstants.Claims.Role,
                    OpenIddictConstants.Claims.Scope,
                    "groups",
                    "sid");

                // Register the redb.Route host adapter
                server.UseRedbRoute();
            })
            .AddValidation(validation =>
            {
                // Server-local token validation (shares signing/encryption keys with the server)
                validation.UseLocalServer();
                validation.UseDataProtection();

                // Custom handler: inject bearer token for programmatic validation
                // (runs early in the pipeline, before built-in extraction handlers)
                validation.AddEventHandler<OpenIddictValidationEvents.ProcessAuthenticationContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        if (context.Transaction.Properties.TryGetValue(
                                ManagementBearerAuthProcessor.TokenPropertyKey, out var rawToken)
                            && rawToken is string token)
                        {
                            context.AccessToken = token;
                            context.ExtractAccessToken = false;
                        }

                        return default;
                    })
                    .SetOrder(int.MinValue + 500)
                    .Build());

                // Batch 14 — bearer rejection for disabled / soft-deleted users.
                // JWT bearer tokens stay cryptographically valid until exp, but if the
                // underlying user has been DELETE'd (soft-delete sets _enabled=false)
                // the bearer must stop authorizing protected endpoints immediately.
                validation.AddEventHandler(redb.Identity.Core.Services.DisabledUserRejectionHandler.Descriptor);

                // **Batch 12 diagnostic.** Class-based handler dumps key picture on
                // every rejected validation so we can see which layer holds the stale
                // snapshot after rotate. Registered via DI for proper IOptionsMonitor access.
                validation.AddEventHandler(redb.Identity.Core.Keys.JwksRefreshDiagnosticHandler.Descriptor);
            });

        services.AddSingleton<redb.Identity.Core.Services.DisabledUserRejectionHandler>();
        services.AddSingleton<redb.Identity.Core.Keys.JwksRefreshDiagnosticHandler>();

        // Identity options (used by RouteBuilder for timer interval, retention, etc.)
        services.AddSingleton(Options.Create(options));

        // Login service (credential verification)
        services.TryAddScoped<LoginService>();

        // User profile service (loads Core + OIDC + groups, builds ClaimsPrincipal)
        services.TryAddScoped<IUserProfileService, UserProfileService>();

        // C15 / per-route CORS: registry of allowed origins derived from registered OAuth
        // clients' redirect URIs. Singleton (in-memory cache, invalidated by management ops).
        // The HTTP transport's resolver wraps this for browser CORS preflights.
        // IMPORTANT: the registry takes IServiceScopeFactory (NOT IOpenIddictApplicationManager
        // directly) — capturing the Scoped manager into a Singleton would transitively pin a
        // single IRedbService / NpgsqlConnection across all CORS preflights and surface as
        // "A command is already in progress" under any concurrent test/request load.
        services.TryAddSingleton<IRegisteredClientOriginRegistry>(sp =>
            new RegisteredClientOriginRegistry(
                sp.GetRequiredService<IServiceScopeFactory>(),
                additionalOriginsCsv: null));

        // F1: per-module health probe surfaced under "module:identity" in the aggregated
        // /api/health/{startup,live,ready} endpoints exposed by redb.Tsak.
        // Singleton — internal scope created per probe to honour IRedbService scoped lifetime.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IModuleHealthContributor, IdentityHealthContributor>());

        // DataProtection (used by federation state, MFA setup tokens, etc.).
        // SessionTicketService lives in redb.Identity.Http (HTTP-cookie-only concern)
        // and is registered there.
        services.AddDataProtection()
            .PersistKeysToRedb()
            .ProtectKeysWithRedbIdentity(options);

        // Federation state protector (DataProtection-based state encrypt/decrypt)
        // C6: nonce store backs one-time-use enforcement; backend selected via FederationState.Backend.
        switch (options.FederationState.Backend?.ToLowerInvariant())
        {
            case "redis":
                var fedRedisCs = options.FederationState.RedisConnectionString
                    ?? options.RateLimit.RedisConnectionString;
                if (string.IsNullOrWhiteSpace(fedRedisCs))
                    throw new InvalidOperationException(
                        "FederationState.Backend='redis' requires FederationState.RedisConnectionString " +
                        "(or a fallback RateLimit.RedisConnectionString).");
                services.TryAddSingleton<IFederationStateNonceStore>(_ =>
                {
                    var factory = new redb.Route.Redis.RedisConnectionFactory
                    {
                        ConnectionString = fedRedisCs!,
                    };
                    return new RedisFederationStateNonceStore(factory, options.FederationState.RedisKeyPrefix);
                });
                break;
            case "memory":
            case null:
            case "":
                services.TryAddSingleton<IFederationStateNonceStore>(sp =>
                    new InMemoryFederationStateNonceStore(sp.GetService<TimeProvider>()));
                break;
            default:
                throw new InvalidOperationException(
                    $"FederationState.Backend='{options.FederationState.Backend}' is not recognised. " +
                    "Use 'memory' or 'redis'.");
        }
        services.TryAddSingleton<FederationStateProtector>(sp =>
            new FederationStateProtector(
                sp.GetRequiredService<IDataProtectionProvider>(),
                sp.GetService<TimeProvider>(),
                sp.GetService<IFederationStateNonceStore>(),
                options.FederationState));

        // Z4 (RFC 9449): DPoP replay-store backend selection + validator.
        // Memory is the default; cluster deployments must opt-in to redis or redb.
        // NB: the OpenIddict handlers (ValidateDpopProofHandler, AttachDpopConfirmationClaimHandler)
        // are registered unconditionally in RedbRouteOpenIddictServerBuilderExtensions, so the
        // validator + replay store MUST always be resolvable from DI even when DPoP is disabled —
        // the handlers no-op at runtime by checking _options.Enabled.
        switch (options.Dpop.ReplayStore.Backend?.ToLowerInvariant())
        {
            case "redis":
                var dpopRedisCs = options.Dpop.ReplayStore.RedisConnectionString
                    ?? options.RateLimit.RedisConnectionString;
                if (options.Dpop.Enabled && string.IsNullOrWhiteSpace(dpopRedisCs))
                    throw new InvalidOperationException(
                        "Dpop.ReplayStore.Backend='redis' requires Dpop.ReplayStore.RedisConnectionString " +
                        "(or a fallback RateLimit.RedisConnectionString).");
                if (!string.IsNullOrWhiteSpace(dpopRedisCs))
                {
                    services.TryAddSingleton<IDpopReplayStore>(_ =>
                    {
                        var factory = new redb.Route.Redis.RedisConnectionFactory
                        {
                            ConnectionString = dpopRedisCs!,
                        };
                        return new RedisDpopReplayStore(factory, options.Dpop.ReplayStore.RedisKeyPrefix);
                    });
                }
                else
                {
                    services.TryAddSingleton<IDpopReplayStore>(sp =>
                        new MemoryDpopReplayStore(
                            sp.GetService<TimeProvider>(),
                            options.Dpop.ReplayStore.MemorySweepInterval));
                }
                break;
            case "redb":
                services.TryAddSingleton<IDpopReplayStore, RedbDpopReplayStore>();
                break;
            case "memory":
            case null:
            case "":
                services.TryAddSingleton<IDpopReplayStore>(sp =>
                    new MemoryDpopReplayStore(
                        sp.GetService<TimeProvider>(),
                        options.Dpop.ReplayStore.MemorySweepInterval));
                break;
            default:
                throw new InvalidOperationException(
                    $"Dpop.ReplayStore.Backend='{options.Dpop.ReplayStore.Backend}' is not recognised. " +
                    "Use 'memory', 'redis' or 'redb'.");
        }
        services.TryAddSingleton<DpopProofValidator>();

        // C8: Backchannel logout — signed logout_token JWT + best-effort POST fan-out to RPs.
        // Uses the OpenIddict signing keys (so RPs validate via the same JWKS as id_tokens).
        services.AddHttpClient("redb-identity-backchannel-logout");
        services.TryAddSingleton<LogoutTokenBuilder>();
        services.TryAddScoped<BackchannelLogoutDispatcher>();

        // MFA protectors (DataProtection-based encrypt/decrypt for TOTP secrets and MFA state)
        services.TryAddSingleton<MfaSecretProtector>();
        services.TryAddSingleton<MfaStateProtector>();
        // Expose MfaStateProtector via the minimal Contracts surface so transport facades
        // (HTTP, gRPC, …) can render MFA-method selectors without referencing Core.
        services.TryAddSingleton<redb.Identity.Contracts.Mfa.IMfaStateInspector>(
            sp => sp.GetRequiredService<MfaStateProtector>());

        // H8 (DoD §4 gap (e)): encrypts PROPS-stored federation provider client secrets.
        services.TryAddSingleton<FederationProviderSecretProtector>();

        // B5: setup-token protector — encrypts candidate secret/destination during MFA setup.
        services.TryAddSingleton<MfaSetupTokenProtector>();

        // B4: server-wide pepper for recovery-code hashing.
        services.TryAddSingleton<RecoveryCodePepperProvider>();

        // MFA method implementations + orchestrator
        // Multiple methods registered via TryAddEnumerable so they all get injected as IEnumerable<IMfaMethod>.
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IMfaMethod, TotpMfaMethod>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IMfaMethod, SmsMfaMethod>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IMfaMethod, EmailMfaMethod>());
        services.TryAddScoped<MfaService>();

        // H3-SSO device auto-fill: bounded memory-cached User-Agent parser. Registers
        // IHttpUserAgentParserProvider as singleton; subsequent calls reuse cached
        // HttpUserAgentInformation by UA string. Size cap prevents unbounded growth
        // under adversarial unique-UA floods.
        if (!services.Any(d => d.ServiceType == typeof(MyCSharp.HttpUserAgentParser.Providers.IHttpUserAgentParserProvider)))
        {
            MyCSharp.HttpUserAgentParser.MemoryCache.DependencyInjection
                .HttpUserAgentParserMemoryCacheServiceCollectionExtensions
                .AddHttpUserAgentMemoryCachedParser(services, o =>
                {
                    o.CacheEntryOptions.SlidingExpiration = TimeSpan.FromHours(6);
                    o.CacheOptions.SizeLimit = 2048;
                });
        }

        // B3: server-side OTP store — SMS/Email MFA codes persisted as MfaOtpProps
        // (SHA-256 hashed, single-use under LockForUpdate). Singleton; resolves IRedbService
        // via IServiceScopeFactory per call (identical pattern to PropsSigningKeyStore / A1).
        services.TryAddSingleton<Mfa.IServerSideOtpStore, Mfa.PropsServerSideOtpStore>();

        // N-4 (Session C): server-side password-reset token store — single-use reset tokens
        // persisted as PasswordResetTokenProps (peppered SHA-256, single-use under
        // LockForUpdate). Singleton; mirrors PropsServerSideOtpStore. Reuses the existing
        // RecoveryCodePepperProvider for the server-wide pepper.
        services.TryAddSingleton<PasswordReset.IPasswordResetTokenStore, PasswordReset.RedbPasswordResetTokenStore>();

        // N-4 (Session C, N4-6): server-side e-mail-verification token store. Mirror of
        // RedbPasswordResetTokenStore with e-mail-snapshot binding for double-change race
        // protection. Registered unconditionally so the verify route can resolve it when
        // RedbIdentityOptions.EmailVerification.Enabled flips on at runtime.
        services.TryAddSingleton<EmailVerification.IEmailVerificationTokenStore, EmailVerification.RedbEmailVerificationTokenStore>();

        // N-4 (Session E, N4-7): server-side change-of-e-mail token store. Mirror of
        // RedbEmailVerificationTokenStore with extra fields (NewEmail + CurrentEmail) and
        // a pre-issue housekeeping pass that invalidates prior unconsumed tokens for the
        // same user when ChangeEmailOptions.InvalidatePreviousTokensOnRequest is true.
        services.TryAddSingleton<ChangeEmail.IChangeEmailTokenStore, ChangeEmail.RedbChangeEmailTokenStore>();

        // N-4 (Session C): default inline e-mail template registry. Hosts MAY replace
        // this with their own branded templates by registering an IEmailTemplateRegistry
        // singleton BEFORE calling AddRedbIdentityServer. The default ships English +
        // Russian copy for the "password-reset" template.
        services.TryAddSingleton<IEmailTemplateRegistry, InlineEmailTemplateRegistry>();
        // N-4: e-mail dispatch channel is INTENTIONALLY not registered by default.
        // Production hosts must register a concrete IEmailNotificationChannel (SMTP /
        // SendGrid / SES); test fixtures register InMemoryEmailNotificationChannel.
        // PasswordForgotProcessor gracefully degrades (logs + silently drops) when no
        // channel is registered.
        //
        // When Smtp.Enabled = true the redb.Route.Mail-backed channel is auto-registered
        // here (TryAdd — host opt-out by registering a different channel BEFORE calling
        // AddRedbIdentityServer). The matching SMTP route is wired by IdentityCoreRouteBuilder.
        if (options.Smtp.Enabled)
        {
            services.TryAddSingleton<IEmailNotificationChannel, SmtpEmailNotificationChannel>();
        }

        // MFA-3: WebAuthn (FIDO2 / Passkey) wiring. Validates RpId/Origins fail-fast at
        // startup so a misconfigured deployment never reaches first-credential-registration
        // with broken settings (changing RpId after credentials exist invalidates every one).
        // Singleton challenge store mirrors the OTP-store pattern.
        if (options.WebAuthn.Enabled)
        {
            options.WebAuthn.Validate();
            services.TryAddSingleton<Mfa.IWebAuthnChallengeStore, Mfa.PropsWebAuthnChallengeStore>();
            services.TryAddSingleton(options.WebAuthn);

            // IOptions<IdentityWebAuthnOptions> for IOptions-aware consumers.
            services.AddSingleton<Microsoft.Extensions.Options.IOptions<Configuration.IdentityWebAuthnOptions>>(
                Microsoft.Extensions.Options.Options.Create(options.WebAuthn));

            // IFido2 — pure crypto verifier, singleton. Origins/RpId fixed at startup;
            // changing them after deployment requires app restart (and credentials may
            // be invalidated, see IdentityWebAuthnOptions docs).
            services.TryAddSingleton<Fido2NetLib.IFido2>(_ =>
            {
                var rpName = string.IsNullOrWhiteSpace(options.WebAuthn.RpName)
                    ? options.WebAuthn.RpId!
                    : options.WebAuthn.RpName!;
                var cfg = new Fido2NetLib.Fido2Configuration
                {
                    ServerDomain = options.WebAuthn.RpId!,
                    ServerName = rpName,
                    Origins = new HashSet<string>(options.WebAuthn.Origins, StringComparer.Ordinal),
                    Timeout = (uint)options.WebAuthn.TimeoutMs,
                };
                // metadataService = null when MDS3 is disabled \u2014 supported by Fido2NetLib.
                return new Fido2NetLib.Fido2(cfg, metadataService: null!);
            });

            // Register WebAuthn as a "method" so MfaService.ResolveWebAuthnMethod() finds it.
            // It satisfies BOTH IMfaMethod (degenerate, throws if invoked through OTP path)
            // AND IWebAuthnMfaMethod (the real surface).
            services.TryAddEnumerable(
                ServiceDescriptor.Singleton<IMfaMethod, WebAuthnMfaMethod>());
            services.TryAddSingleton<IWebAuthnMfaMethod>(sp =>
            {
                // Find the same singleton instance registered as IMfaMethod so resolution is
                // consistent (no two parallel instances with divergent caches).
                foreach (var m in sp.GetServices<IMfaMethod>())
                    if (m is IWebAuthnMfaMethod web) return web;
                throw new InvalidOperationException(
                    "WebAuthn IMfaMethod implementation was not registered.");
            });

            // Wire MfaService.AttachWebAuthn at first scope activation. We can't pass the
            // dependency through the constructor without breaking every existing test that
            // constructs MfaService directly, so we replace the bare TryAddScoped<MfaService>
            // registration with a factory that activates the instance and then attaches the
            // WebAuthn collaborators before returning it.
            services.RemoveAll<MfaService>();
            services.AddScoped<MfaService>(sp =>
            {
                var instance = ActivatorUtilities.CreateInstance<MfaService>(sp);
                var store = sp.GetRequiredService<Mfa.IWebAuthnChallengeStore>();
                var opts = sp.GetRequiredService<Configuration.IdentityWebAuthnOptions>();
                instance.AttachWebAuthn(store, opts);
                return instance;
            });
        }

        // Federation providers (OIDC redirect-based auth)
        if (options.Features.EnableFederation && options.FederationProviders.Count > 0)
        {
            services.AddHttpClient("redb-identity-federation");

            // Skip providers that still carry placeholder credentials so users
            // never hit Google's "OAuth client was not found" 401 / Microsoft's
            // equivalent and mistake config for a server bug. The provider
            // reappears the moment the operator fills in real values (no
            // restart beyond config reload).
            static bool IsPlaceholder(string? v)
                => string.IsNullOrWhiteSpace(v)
                   || v.Contains("REPLACE_ME", StringComparison.OrdinalIgnoreCase);

            foreach (var providerConfig in options.FederationProviders)
            {
                if (IsPlaceholder(providerConfig.ClientId) || IsPlaceholder(providerConfig.Authority))
                    continue;

                // H8: dispatch on Kind. Default ("oidc") preserves the v0 behavior so existing
                // appsettings keep working. "github" wires the OAuth2-only provider.
                services.AddSingleton<IFederatedAuthProvider>(sp =>
                {
                    var kind = (providerConfig.Kind ?? "oidc").Trim().ToLowerInvariant();
                    var http = sp.GetRequiredService<IHttpClientFactory>();
                    return kind switch
                    {
                        "github" => new GitHubFederatedAuthProvider(providerConfig, http),
                        "oidc" or "" or null => new OidcFederatedAuthProvider(providerConfig, http),
                        _ => throw new InvalidOperationException(
                            $"Unknown federation provider kind '{kind}' for ProviderId='{providerConfig.ProviderId}'. Expected: oidc | github."),
                    };
                });
            }
        }

        // C1: Rate-limit store. Picks the in-memory or Redis backend based on configuration.
        // The store is only registered when RateLimit.Enabled is true; otherwise the route
        // builder skips wiring the rate-limit processors entirely (Camel-style conditional
        // pipeline composition — see IdentityCoreRouteBuilder).
        //
        // For the Redis backend we reuse redb.Route.Redis's RedisConnectionFactory + the
        // RedisComponent registered in InitRoute — keeps connection management consistent
        // with the rest of the redb ecosystem (claim-check repository, redis: route URIs).
        if (options.RateLimit.Enabled)
        {
            switch (options.RateLimit.Backend?.ToLowerInvariant())
            {
                case "redis":
                    if (string.IsNullOrWhiteSpace(options.RateLimit.RedisConnectionString))
                        throw new InvalidOperationException(
                            "RateLimit.Backend='redis' requires RateLimit.RedisConnectionString.");
                    services.TryAddSingleton<IRateLimitStore>(sp =>
                    {
                        var factory = new redb.Route.Redis.RedisConnectionFactory
                        {
                            ConnectionString = options.RateLimit.RedisConnectionString!,
                        };
                        return new RedisRateLimitStore(
                            factory,
                            options.RateLimit.RedisKeyPrefix,
                            sp.GetService<TimeProvider>() ?? TimeProvider.System);
                    });
                    break;
                case "memory":
                case null:
                case "":
                    services.TryAddSingleton<IRateLimitStore>(sp =>
                        new InMemoryRateLimitStore(sp.GetService<TimeProvider>() ?? TimeProvider.System));
                    break;
                default:
                    throw new InvalidOperationException(
                        $"RateLimit.Backend='{options.RateLimit.Backend}' is not recognised. " +
                        "Use 'memory' or 'redis'.");
            }
        }

        return services;
    }

    /// <summary>
    /// Registers redb-backed OpenIddict stores for applications, authorizations, scopes, and tokens.
    /// Usage: <c>services.AddOpenIddict().AddCore(options => options.UseRedbStores());</c>
    /// </summary>
    public static OpenIddictCoreBuilder UseRedbStores(this OpenIddictCoreBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        // Set entity types so OpenIddict managers know the concrete types
        builder.SetDefaultApplicationEntity<RedbObject<ApplicationProps>>();
        builder.SetDefaultAuthorizationEntity<RedbObject<AuthorizationProps>>();
        builder.SetDefaultScopeEntity<RedbObject<ScopeProps>>();
        builder.SetDefaultTokenEntity<RedbObject<TokenProps>>();

        // Register store implementations (default store resolvers discover these via DI)
        builder.Services.TryAddScoped(
            typeof(IOpenIddictApplicationStore<RedbObject<ApplicationProps>>),
            typeof(RedbApplicationStore));
        builder.Services.TryAddScoped(
            typeof(IOpenIddictAuthorizationStore<RedbObject<AuthorizationProps>>),
            typeof(RedbAuthorizationStore));
        builder.Services.TryAddScoped(
            typeof(IOpenIddictScopeStore<RedbObject<ScopeProps>>),
            typeof(RedbScopeStore));
        builder.Services.TryAddScoped(
            typeof(IOpenIddictTokenStore<RedbObject<TokenProps>>),
            typeof(RedbTokenStore));

        // A3: PROPS signing key store + OpenIddict credential post-configuration (opt-in via
        // RedbIdentityOptions.UsePropsSigningKeyStore). Registration is unconditional so the
        // store can be resolved by tooling / admin APIs; the OpenIddict integration itself
        // is gated by the option.
        builder.Services.TryAddSingleton<redb.Identity.Core.Keys.ISigningKeyStore,
                                        redb.Identity.Core.Keys.PropsSigningKeyStore>();
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<
            IPostConfigureOptions<OpenIddictServerOptions>,
            redb.Identity.Core.Keys.PropsSigningKeyStoreOpenIddictPostConfigure>());

        // F3: Meter-based telemetry. Singleton; picked up by host-side OTEL pipeline via
        // AddMeter("RedbIdentity"). Safe to register unconditionally — zero cost if no
        // exporter is wired.
        builder.Services.TryAddSingleton<redb.Identity.Core.Metrics.IdentityMetrics>();

        // C12: password hashing. Register a MultiFormatPasswordHasher that hashes new
        // passwords with the configured primary algorithm (Argon2id by default) and
        // transparently verifies legacy BCrypt / legacy SHA256+salt hashes. LoginService
        // and UserProviderBase resolve IPasswordHasher from DI; registering it here
        // replaces the default SimplePasswordHasher baked into PostgresUserProvider's
        // parameterless ctor path.
        builder.Services.TryAddSingleton<IPasswordHasher>(sp =>
        {
            var opts = sp.GetRequiredService<IOptions<RedbIdentityOptions>>().Value.PasswordHashing;
            var argon2 = new redb.Identity.Core.Security.Argon2idPasswordHasher(
                memoryKib: opts.Argon2id.MemoryKib,
                iterations: opts.Argon2id.Iterations,
                parallelism: opts.Argon2id.Parallelism,
                saltBytes: opts.Argon2id.SaltBytes,
                hashBytes: opts.Argon2id.HashBytes,
                logger: sp.GetService<ILogger<redb.Identity.Core.Security.Argon2idPasswordHasher>>());
            var bcrypt = new BcryptPasswordHasher(workFactor: opts.Bcrypt.WorkFactor);

            if (opts.Algorithm == Configuration.PasswordHashAlgorithm.Bcrypt)
            {
                // BCrypt selected as primary: return plain bcrypt so new hashes use bcrypt.
                // Legacy Argon2id hashes written by a previous Argon2id-primary configuration
                // will not verify under this setting — expected, since operators picking
                // bcrypt have explicitly chosen that trade-off.
                return bcrypt;
            }

            return new redb.Identity.Core.Security.MultiFormatPasswordHasher(argon2, bcrypt);
        });

        // Seed default password for the well-known 'admin' user from the base redb
        // SQL seed (_users.id=1, login='admin', password=''). Idempotent — only writes
        // when the stored password is empty. Configurable via RedbIdentityOptions.SeedAdmin.
        // Wired as transient — InitRoute.main resolves it and registers via
        // context.AddLifecycleListener (Tsak modules have no IHost, so IHostedService
        // would never run).
        builder.Services.AddTransient<redb.Identity.Core.Services.SeedAdminPasswordHostedService>();

        // Seed canonical OIDC client (default 'identity-web') so the bundled Web BFF
        // can complete /connect/authorize on a fresh install. Idempotent — skips when
        // a client with the same ClientId already exists. Configurable via
        // RedbIdentityOptions.SeedWebClient. Same lifecycle pattern as SeedAdmin.
        builder.Services.AddTransient<redb.Identity.Core.Services.SeedWebClientHostedService>();

        // W6-0: backchannel client_credentials service account seeder. Opt-in via
        // RedbIdentityOptions.SeedBackchannelClient.Enabled=true. Web BFF uses this
        // account to publish/poll the revoked-sids list for cluster-wide BCL.
        builder.Services.AddTransient<redb.Identity.Core.Services.SeedBackchannelClientHostedService>();

        return builder;
    }

    // PersistKeysToRedb extension moved to redb.Identity.DataProtection (Phase 9a).
    // Use redb.Identity.DataProtection.RedbDataProtectionBuilderExtensions.PersistKeysToRedb.

    /// <summary>
    /// C10 — wires at-rest encryption for the DataProtection key-ring based on
    /// <see cref="DataProtectionOptions"/>. Variants (priority order):
    /// custom KMS factory → certificate (PFX path > thumbprint) → AES-GCM master key.
    /// <para>If <see cref="DataProtectionOptions.RequireAtRestEncryption"/> is <c>true</c>
    /// and <see cref="RedbIdentityOptions.AllowEphemeralKeys"/> is <c>false</c> and none of
    /// the variants is configured, throws.</para>
    /// </summary>
    public static IDataProtectionBuilder ProtectKeysWithRedbIdentity(
        this IDataProtectionBuilder builder, RedbIdentityOptions options)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(options);

        var dp = options.DataProtection;

        // Variant Б — KMS / Vault hook. Highest priority because it's the most explicit
        // configuration the operator can supply.
        if (dp.CustomEncryptorFactory is not null)
        {
            var factory = dp.CustomEncryptorFactory;
            builder.Services.AddSingleton<IConfigureOptions<KeyManagementOptions>>(
                sp => new ConfigureNamedOptions<KeyManagementOptions>(Options.DefaultName,
                    o => o.XmlEncryptor = factory(sp)));
            return builder;
        }

        // Variant А — X.509 certificate. PFX-on-disk wins over thumbprint when both are set
        // (operator presumably picked PFX deliberately).
        if (dp.Certificate.IsConfigured)
        {
            var cert = CertificateLoader.Load(dp.Certificate);
            // ProtectKeysWithCertificate registers BOTH the encryptor and the decryptor —
            // decryption needs a cert with private key, which is why we pre-load it here
            // (the thumbprint overload only works against the local cert store).
            builder.ProtectKeysWithCertificate(cert);
            return builder;
        }

        // Variant В — AES-GCM master key. Smallest deployments / dev.
        if (!string.IsNullOrWhiteSpace(dp.MasterKey))
        {
            byte[] keyBytes;
            try { keyBytes = Convert.FromBase64String(dp.MasterKey!); }
            catch (FormatException ex)
            {
                throw new InvalidOperationException(
                    "DataProtection.MasterKey must be base64-encoded.", ex);
            }
            if (keyBytes.Length != 32)
                throw new InvalidOperationException(
                    $"DataProtection.MasterKey must decode to exactly 32 bytes (AES-256); got {keyBytes.Length}.");

            var keyProvider = new RedbMasterKeyProvider(keyBytes);
            builder.Services.AddSingleton(keyProvider);
            builder.Services.AddSingleton<IConfigureOptions<KeyManagementOptions>>(
                sp => new ConfigureNamedOptions<KeyManagementOptions>(Options.DefaultName,
                    o => o.XmlEncryptor = new RedbAesGcmXmlEncryptor(keyProvider)));
            return builder;
        }

        // Production gate: nothing configured.
        if (dp.RequireAtRestEncryption && !options.AllowEphemeralKeys)
        {
            throw new InvalidOperationException(
                "DataProtection key-ring is unprotected at rest. Configure ONE of: " +
                "RedbIdentityOptions.DataProtection.MasterKey (32-byte base64), " +
                ".DataProtection.Certificate.Thumbprint, .DataProtection.Certificate.PfxPath, " +
                "or .DataProtection.CustomEncryptorFactory. " +
                "Disable this check only for local development by setting " +
                "DataProtection.RequireAtRestEncryption=false (or AllowEphemeralKeys=true).");
        }

        // Permitted: dev / ephemeral. Key-ring stays in PROPS in plaintext.
        return builder;
    }
}
