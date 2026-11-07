using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Identity.Contracts.Registration;
using redb.Identity.Core.Models;
using redb.Identity.Core.Module;
using redb.Route.Abstractions;
using redb.Route.RedbCore.Extensions;
using redb.Identity.Contracts.Routes;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// Z2 (RFC 7592): Client configuration endpoint — <c>GET/PUT/DELETE /connect/register/{client_id}</c>.
/// <para>
/// Dispatches on the <c>operation</c> header (<c>read</c>, <c>update</c>, <c>delete</c>). The
/// <c>client_id</c> header is populated by the HTTP facade from the route segment. Authorizes
/// via the bearer <c>registration_access_token</c> issued at DCR time and stored as SHA-256
/// hash on <see cref="ApplicationProps.RegistrationAccessTokenHash"/>.
/// </para>
/// <para>
/// Returns RFC 7592-compliant errors: <c>invalid_token</c> (401), <c>invalid_client_id</c> (404),
/// <c>invalid_client_metadata</c> (400).
/// </para>
/// </summary>
internal sealed class ClientRegistrationManagementProcessor : IProcessor
{
    private readonly IRouteContext _context;
    private readonly string? _redbName;

    public ClientRegistrationManagementProcessor(IRouteContext context, string? redbName = null)
    {
        _context = context;
        _redbName = redbName;
    }

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var operation = exchange.In.GetHeader<string>("operation");
        var clientId = exchange.In.GetHeader<string>("client_id");

        if (string.IsNullOrEmpty(clientId))
        {
            SetError(exchange, "invalid_request", "Missing client_id", 400);
            return;
        }

        // Resolve bearer RAT from request. Headers are stripped by ExtractBearerToken upstream;
        // direct-vm tests may pass raw Authorization.
        var presentedToken = exchange.In.GetHeader<string>("access_token");
        if (string.IsNullOrEmpty(presentedToken))
        {
            var auth = exchange.In.GetHeader<string>("Authorization");
            if (auth is not null && auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                presentedToken = auth[7..];
        }

        if (string.IsNullOrEmpty(presentedToken))
        {
            SetError(exchange, "invalid_token", "Missing registration_access_token", 401);
            return;
        }

        var manager = _context.GetIdentityService<IOpenIddictApplicationManager>(exchange);

        var app = await manager.FindByClientIdAsync(clientId, ct) as RedbObject<ApplicationProps>;
        if (app is null)
        {
            SetError(exchange, "invalid_client_id", "Unknown client_id", 404);
            return;
        }

        var storedHash = app.Props.RegistrationAccessTokenHash;
        if (string.IsNullOrEmpty(storedHash))
        {
            // Client was created via admin API, not DCR — RFC 7592 §3 mgmt endpoint does not apply.
            SetError(exchange, "invalid_token", "Client not eligible for registration management", 401);
            return;
        }

        var presentedHash = ComputeSha256Hex(presentedToken);
        if (!FixedTimeHexEquals(presentedHash, storedHash))
        {
            SetError(exchange, "invalid_token", "Registration access token mismatch", 401);
            return;
        }

        switch (operation)
        {
            case "read":
                await Read(app, exchange);
                break;
            case "update":
                await Update(manager, app, exchange, ct);
                break;
            case "delete":
                await Delete(manager, app, exchange, ct);
                break;
            default:
                SetError(exchange, "invalid_request", $"Unsupported operation '{operation}'", 400);
                break;
        }
    }

    private static Task Read(RedbObject<ApplicationProps> app, IExchange exchange)
    {
        var response = MapToResponse(app);
        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = SerializeResponse(response);
        exchange.Out.Headers["redbHttp.ResponseCode"] = 200;
        return Task.CompletedTask;
    }

    private async Task Update(
        IOpenIddictApplicationManager manager,
        RedbObject<ApplicationProps> app,
        IExchange exchange,
        CancellationToken ct)
    {
        if (exchange.In.Body is not DynamicRegistrationRequest request)
        {
            // Mirror DCR processor — also accept JSON bytes / string bodies from HTTP facade.
            DynamicRegistrationRequest? parsed = null;
            try
            {
                parsed = exchange.In.Body switch
                {
                    byte[] bytes => JsonSerializer.Deserialize<DynamicRegistrationRequest>(bytes),
                    string json => JsonSerializer.Deserialize<DynamicRegistrationRequest>(json),
                    _ => null
                };
            }
            catch (JsonException) { parsed = null; }

            if (parsed is null)
            {
                SetError(exchange, "invalid_client_metadata", "Request body must be a JSON registration object", 400);
                return;
            }
            request = parsed;
        }

        // Apply mutable metadata fields — identity (client_id, client_secret, RAT hash) is untouched.
        if (request.ClientName is not null) app.name = request.ClientName;
        if (request.RedirectUris is { Length: > 0 }) app.Props.RedirectUris = request.RedirectUris;
        if (request.PostLogoutRedirectUris is { Length: > 0 })
            app.Props.PostLogoutRedirectUris = request.PostLogoutRedirectUris;

        var redb = _context.GetRedbService(_redbName, exchange);
        await redb.SaveAsync(app).ConfigureAwait(false);

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = SerializeResponse(MapToResponse(app));
        exchange.Out.Headers["redbHttp.ResponseCode"] = 200;

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.ClientUpdated;
        exchange.Properties["identity-event-data"] = new { ClientId = app.Props.ClientId, Source = "dynamic_registration" };
    }

    private async Task Delete(
        IOpenIddictApplicationManager manager,
        RedbObject<ApplicationProps> app,
        IExchange exchange,
        CancellationToken ct)
    {
        await manager.DeleteAsync(app, ct);

        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Headers["redbHttp.ResponseCode"] = 204;

        exchange.Properties["identity-event-type"] = IdentityAuditEventIds.ClientDeleted;
        exchange.Properties["identity-event-data"] = new { ClientId = app.Props.ClientId, Source = "dynamic_registration" };
    }

    private static DynamicRegistrationResponse MapToResponse(RedbObject<ApplicationProps> app)
    {
        var perms = app.Props.Permissions ?? Array.Empty<string>();
        var grantTypes = perms.Where(p => p.StartsWith("gt:", StringComparison.Ordinal))
            .Select(p => p[3..]).ToArray();
        var responseTypes = perms.Where(p => p.StartsWith("rst:", StringComparison.Ordinal))
            .Select(p => p[4..]).ToArray();
        var scopes = perms.Where(p => p.StartsWith("scp:", StringComparison.Ordinal))
            .Select(p => p[4..]).ToArray();

        return new DynamicRegistrationResponse
        {
            ClientId = app.Props.ClientId ?? "",
            ClientName = app.name,
            RedirectUris = app.Props.RedirectUris,
            PostLogoutRedirectUris = app.Props.PostLogoutRedirectUris,
            ApplicationType = app.Props.ApplicationType,
            TokenEndpointAuthMethod = app.Props.ClientType == "public" ? "none" : "client_secret_basic",
            GrantTypes = grantTypes.Length > 0 ? grantTypes : null,
            ResponseTypes = responseTypes.Length > 0 ? responseTypes : null,
            Scope = scopes.Length > 0 ? string.Join(' ', scopes) : null
            // client_secret / registration_access_token are NEVER returned in GET — they were one-time at creation.
        };
    }

    private static IDictionary<string, object?> SerializeResponse(DynamicRegistrationResponse response)
    {
        // Round-trip through the same JSON options as the DCR processor to guarantee
        // RFC 7591/7592 snake_case wire format and to drop null/empty fields.
        var opts = new JsonSerializerOptions
        {
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
        };
        var json = JsonSerializer.Serialize(response, opts);
        return JsonSerializer.Deserialize<Dictionary<string, object?>>(json)!;
    }

    private static void SetError(IExchange exchange, string error, string description, int statusCode)    {
        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = new Dictionary<string, object?>
        {
            ["error"] = error,
            ["error_description"] = description
        };
        exchange.Out.Headers["redbHttp.ResponseCode"] = statusCode;
    }

    private static string ComputeSha256Hex(string plaintext)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(plaintext));
        var sb = new StringBuilder(bytes.Length * 2);
        foreach (var b in bytes) sb.Append(b.ToString("x2"));
        return sb.ToString();
    }

    /// <summary>Fixed-time equality for hex strings — defeats timing side-channels on RAT verification.</summary>
    private static bool FixedTimeHexEquals(string a, string b)
    {
        if (a.Length != b.Length) return false;
        return CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(a),
            Encoding.ASCII.GetBytes(b));
    }
}
