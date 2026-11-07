// IdentityClient is a sealed partial class. Domain-specific methods live in:
//   IdentityClient.Users.cs        — users CRUD + group memberships
//   IdentityClient.Groups.cs       — groups tree, members
//   IdentityClient.Applications.cs — OIDC applications
//   IdentityClient.Scopes.cs       — scopes
//   IdentityClient.ClaimMappers.cs — claim mappers + claim scopes
//   IdentityClient.Federation.cs   — federation providers
//   IdentityClient.Sessions.cs     — admin sessions endpoint
//   IdentityClient.Tokens.cs       — admin tokens endpoint
//   IdentityClient.Mfa.cs          — admin MFA operations
//   IdentityClient.Audit.cs        — audit log
//   IdentityClient.Account.cs      — /me/* (profile, sessions, mfa, password, federated, consents)
//   IdentityClient.Token.cs        — /connect/{token,introspect,revoke,userinfo}
//   IdentityClient.Scim.cs         — /scim/v2/{Users,Groups,Bulk,ServiceProviderConfig}

using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;

namespace redb.Identity.Client;

public sealed partial class IdentityClient : IIdentityClient
{
    private readonly HttpClient _http;
    private readonly IdentityClientOptions _opts;
    private readonly JsonSerializerOptions _json;

    public IdentityClient(HttpClient http, IOptions<IdentityClientOptions> opts)
    {
        _http = http;
        _opts = opts.Value;
        _json = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            PropertyNameCaseInsensitive = true,
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            Converters = { new JsonStringEnumConverter() }
        };
    }
}
