using redb.Identity.Contracts.Routes;
using redb.Identity.Contracts.SigningKeys;
using redb.Identity.Core.Keys;
using redb.Route.Abstractions;
using redb.Route.Core;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// Admin /signing-keys lifecycle endpoint backing — list, rotate, retire.
/// <list type="bullet">
///   <item><c>operation="list"</c> → returns the full audit trail (active + retired).</item>
///   <item><c>operation="rotate"</c> → mints a fresh active key of the given kind, demotes
///   any currently-active keys of the same kind. New tokens are signed under the new key
///   after the OpenIddict options cache refreshes (process restart, or future
///   IOptionsMonitor wiring).</item>
///   <item><c>operation="retire"</c> → sets NotAfter to "now" for the supplied kid; the
///   key disappears from JWKS on the next request and tokens signed under it stop
///   validating.</item>
/// </list>
/// Wired into <c>identity-manage-signing-keys</c> in the route builder; gated by
/// <c>identity:applications.manage</c> (master <c>identity:manage</c> also passes) via the
/// granular scope guard in the HTTP facade.
/// </summary>
internal sealed class SigningKeysManagementProcessor : IProcessor
{
    private readonly ISigningKeyStore _store;

    public SigningKeysManagementProcessor(ISigningKeyStore store)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
    }

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var op = exchange.In.GetHeader<string>("operation") ?? "list";
        switch (op)
        {
            case "list":
                await List(exchange, ct).ConfigureAwait(false);
                return;
            case "rotate":
                await Rotate(exchange, ct).ConfigureAwait(false);
                return;
            case "retire":
                await Retire(exchange, ct).ConfigureAwait(false);
                return;
            default:
                SetError(exchange, "validation_error", $"Unknown operation '{op}'. Expected one of: list, rotate, retire.");
                return;
        }
    }

    private async Task List(IExchange exchange, CancellationToken ct)
    {
        var keys = await _store.ListAllIncludingRetiredAsync(ct).ConfigureAwait(false);
        var now = DateTimeOffset.UtcNow;
        var response = new SigningKeyListResponse
        {
            Keys = keys.Select(k => new SigningKeyResponse
            {
                Kid = k.Kid,
                Kind = k.KeyKind,
                Algorithm = k.Algorithm,
                NotBefore = k.NotBefore,
                NotAfter = k.NotAfter,
                IsActive = k.IsActive,
                InJwks = k.NotAfter > now,
            }).ToList(),
        };
        exchange.Out ??= new Message();
        exchange.Out.Body = response;
    }

    private async Task Rotate(IExchange exchange, CancellationToken ct)
    {
        var kind = ResolveKind(exchange);
        var material = await _store.RotateAsync(kind, ct).ConfigureAwait(false);
        var response = new SigningKeyResponse
        {
            Kid = material.Kid,
            Kind = material.KeyKind,
            Algorithm = material.Algorithm,
            NotBefore = material.NotBefore,
            NotAfter = material.NotAfter,
            IsActive = material.IsActive,
            InJwks = true,
        };
        exchange.Out ??= new Message();
        exchange.Out.Body = response;

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.SigningKeyRotated;
        exchange.Properties["identity-event-data"] = new { Kid = material.Kid, Kind = material.KeyKind };
    }

    private async Task Retire(IExchange exchange, CancellationToken ct)
    {
        var kid = exchange.In.GetHeader<string>("kid")
                  ?? (exchange.In.Body is Dictionary<string, object?> dict
                        && dict.TryGetValue("kid", out var k) ? k?.ToString() : null);
        if (string.IsNullOrEmpty(kid))
        {
            SetError(exchange, "validation_error", "kid is required for retire");
            return;
        }
        var ok = await _store.RetireAsync(kid, ct).ConfigureAwait(false);
        if (!ok)
        {
            SetError(exchange, "not_found", $"No signing key with kid '{kid}'.");
            return;
        }
        exchange.Out ??= new Message();
        exchange.Out.Body = new { success = true, kid };

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.SigningKeyRetired;
        exchange.Properties["identity-event-data"] = new { Kid = kid };
    }

    private static string ResolveKind(IExchange exchange)
    {
        // Body may be either RotateSigningKeyRequest or a raw dictionary; accept either.
        if (exchange.In.Body is RotateSigningKeyRequest rot && !string.IsNullOrEmpty(rot.Kind))
            return rot.Kind!;
        if (exchange.In.Body is Dictionary<string, object?> dict
            && dict.TryGetValue("kind", out var v) && v is string s && !string.IsNullOrEmpty(s))
            return s;
        return "signing";
    }

    private static void SetError(IExchange exchange, string error, string description)
        => IdentityProcessorHelpers.SetError(exchange, error, description);
}
