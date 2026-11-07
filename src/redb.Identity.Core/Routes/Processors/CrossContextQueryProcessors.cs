using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using redb.Identity.Contracts.Cors;
using redb.Identity.Contracts.Endpoints;
using redb.Identity.Contracts.Mfa;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.Core;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// Phase 9d cross-context broker processors. Serve <c>direct-vm://identity-cors-check</c>,
/// <c>direct-vm://identity-validate-post-logout</c> and <c>direct-vm://identity-mfa-methods-from-state</c>
/// — all read-only queries the HTTP transport facade issues from its own RouteContext.
/// <para>
/// Each processor accepts either the strongly-typed Contracts DTO directly or an
/// <see cref="IDictionary{TKey,TValue}"/> with the same property names. The broker on
/// the Http side serializes via the Route default body convertor, which preserves the
/// dictionary form when going through <c>direct-vm</c>.
/// </para>
/// </summary>
internal sealed class CorsCheckProcessor : IProcessor
{
    private readonly IServiceProvider _sp;
    public CorsCheckProcessor(IServiceProvider sp) => _sp = sp;

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var origin = ExtractOrigin(exchange.In.Body);
        bool allowed = false;

        if (!string.IsNullOrEmpty(origin))
        {
            using var scope = _sp.CreateScope();
            var registry = scope.ServiceProvider.GetService<redb.Identity.Contracts.Cors.IRegisteredClientOriginRegistry>();
            if (registry is not null)
                allowed = await registry.IsAllowedAsync(origin, ct).ConfigureAwait(false);
        }

        exchange.Out = new Message(new CorsCheckResponse { Allowed = allowed });
    }

    private static string? ExtractOrigin(object? body) => body switch
    {
        CorsCheckRequest typed => typed.Origin,
        IDictionary<string, object?> dict when dict.TryGetValue("Origin", out var v) => v?.ToString(),
        IDictionary<string, object?> dict when dict.TryGetValue("origin", out var v) => v?.ToString(),
        _ => null,
    };
}

internal sealed class ValidatePostLogoutRedirectProcessor : IProcessor
{
    private readonly IServiceProvider _sp;
    public ValidatePostLogoutRedirectProcessor(IServiceProvider sp) => _sp = sp;

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var uri = ExtractUri(exchange.In.Body);
        bool allowed = false;

        if (!string.IsNullOrEmpty(uri))
        {
            using var scope = _sp.CreateScope();
            var manager = scope.ServiceProvider.GetService<IOpenIddictApplicationManager>();
            if (manager is not null)
            {
                await foreach (var _ in manager.FindByPostLogoutRedirectUriAsync(uri, ct).ConfigureAwait(false))
                {
                    allowed = true;
                    break;
                }
            }
        }

        exchange.Out = new Message(new ValidatePostLogoutRedirectResponse { Allowed = allowed });
    }

    private static string? ExtractUri(object? body) => body switch
    {
        ValidatePostLogoutRedirectRequest typed => typed.RedirectUri,
        IDictionary<string, object?> dict when dict.TryGetValue("RedirectUri", out var v) => v?.ToString(),
        IDictionary<string, object?> dict when dict.TryGetValue("redirect_uri", out var v) => v?.ToString(),
        _ => null,
    };
}

internal sealed class MfaMethodsFromStateProcessor : IProcessor
{
    private readonly IServiceProvider _sp;
    public MfaMethodsFromStateProcessor(IServiceProvider sp) => _sp = sp;

    public Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var token = ExtractState(exchange.In.Body);
        var response = new MfaMethodsFromStateResponse();

        if (!string.IsNullOrEmpty(token))
        {
            using var scope = _sp.CreateScope();
            var protector = scope.ServiceProvider.GetService<MfaStateProtector>();
            var state = protector?.Unprotect(token);
            if (state is not null && state.Methods is { Length: > 0 } m)
            {
                response.Success = true;
                response.Methods = m;
            }
        }

        exchange.Out = new Message(response);
        return Task.CompletedTask;
    }

    private static string? ExtractState(object? body) => body switch
    {
        MfaMethodsFromStateRequest typed => typed.MfaState,
        IDictionary<string, object?> dict when dict.TryGetValue("MfaState", out var v) => v?.ToString(),
        IDictionary<string, object?> dict when dict.TryGetValue("mfa_state", out var v) => v?.ToString(),
        _ => null,
    };
}
