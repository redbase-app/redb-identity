using System.Diagnostics;
using System.Text.Json;
using Google.Protobuf.WellKnownTypes;
using Grpc.Core;
using Grpc.Net.Client;
using redb.Identity.Grpc.Management.V1;
using redb.Identity.Grpc.V1;

// A look at the gRPC facade of a running redb.Identity.
//
//   dotnet run                      → talks to localhost:5011, admin API on localhost:5002
//   dotnet run -- --grpc host:port --http https://host:port
//
// Nothing to install and no container: the two published .proto files are compiled into this project the
// way any consumer would compile them.

var grpcAddress = Args.Value(args, "--grpc") ?? "http://localhost:5011";
var httpAddress = Args.Value(args, "--http") ?? "https://localhost:5002";
if (!grpcAddress.StartsWith("http", StringComparison.OrdinalIgnoreCase))
    grpcAddress = "http://" + grpcAddress;

Ui.Title("redb.Identity — gRPC facade");
Ui.Kv("gRPC", grpcAddress);
Ui.Kv("HTTP (admin API, used to register a demo client)", httpAddress);

using var channel = GrpcChannel.ForAddress(grpcAddress);
var identity = new Identity.IdentityClient(channel);

try
{
    // ── 1. Is it serving? ────────────────────────────────────
    // The standard health address, the one Kubernetes and Envoy probe. It carries no payload worth
    // showing, so what is interesting here is the latency: this is the floor cost of a call.
    await Ui.Step("Health", "grpc.health.v1.Health/Check", async () =>
    {
        var invoker = channel.CreateCallInvoker();
        var raw = Marshallers.Create<byte[]>(b => b, b => b);
        var method = new Method<byte[], byte[]>(
            MethodType.Unary, "grpc.health.v1.Health", "Check", raw, raw);

        var reply = await invoker.AsyncUnaryCall(method, null, new CallOptions(), []);
        // HealthCheckResponse { ServingStatus status = 1 }, SERVING = 1 → two bytes.
        var serving = reply is [0x08, 0x01];
        return serving ? "SERVING" : $"not serving ({BitConverter.ToString(reply)})";
    });

    // ── 2. Discovery ─────────────────────────────────────────
    // Passed through from Core untouched. Note the endpoints it advertises: they are HTTP addresses,
    // because those are the real ones — the facade does not rewrite them into gRPC addresses that do
    // not exist.
    await Ui.Step("Discovery", "OIDC document, straight from Core", async () =>
    {
        var response = await identity.DiscoveryAsync(new DiscoveryRequest());
        var fields = response.Document.Fields;
        Ui.Detail("issuer", fields["issuer"].StringValue);
        Ui.Detail("token_endpoint", fields["token_endpoint"].StringValue);
        Ui.Detail("scopes_supported", $"{fields["scopes_supported"].ListValue.Values.Count} scopes");
        return $"{fields.Count} fields";
    });

    // ── 3. A client, registered over HTTP ────────────────────
    // The whole claim of the facade in one step: this client is created through the HTTP transport and
    // used through the gRPC one. One issuer, one registry, one token store.
    (string ClientId, string ClientSecret) client = default;
    await Ui.Step("Register", "a demo client over HTTP (DCR)", async () =>
    {
        client = await Dcr.RegisterAsync(httpAddress);
        Ui.Detail("client_id", client.ClientId);
        Ui.Detail("scope", Dcr.Scope);
        return "registered";
    });

    // ── 4. A token, over gRPC ────────────────────────────────
    string accessToken = "";
    await Ui.Step("Token", "client_credentials over gRPC", async () =>
    {
        var response = await identity.TokenAsync(new TokenRequest
        {
            GrantType = "client_credentials",
            ClientId = client.ClientId,
            ClientSecret = client.ClientSecret,
            Scope = Dcr.Scope,
        });

        Ui.Detail("token_type", response.TokenType);
        Ui.Detail("expires_in", $"{response.ExpiresIn}s");
        Ui.Detail("access_token", response.AccessToken[..24] + "…");
        accessToken = response.AccessToken;
        return "issued";
    });

    // ── 5. Introspection ─────────────────────────────────────
    await Ui.Step("Introspect", "the token we just minted", async () =>
    {
        var response = await identity.IntrospectAsync(new IntrospectRequest
        {
            Token = accessToken,
            ClientId = client.ClientId,
            ClientSecret = client.ClientSecret,
        });

        Ui.Detail("active", response.Active.ToString().ToLowerInvariant());
        Ui.Detail("client_id", response.ClientId);
        Ui.Detail("scope", response.Scope);
        return response.Active ? "active" : "INACTIVE";
    });

    // ── 6. A refusal ─────────────────────────────────────────
    // An OAuth error must arrive as a gRPC status, not as a successful call carrying an error document —
    // no generated client inspects the body of an OK reply. The machine-readable code travels in a
    // trailer, because a non-OK reply has its payload discarded by the protocol itself.
    await Ui.Step("Refusal", "the same client with a wrong secret", async () =>
    {
        try
        {
            await identity.TokenAsync(new TokenRequest
            {
                GrantType = "client_credentials",
                ClientId = client.ClientId,
                ClientSecret = "not-the-secret",
            });
            return "!! a wrong secret produced a token";
        }
        catch (RpcException ex)
        {
            Ui.Detail("status", ex.StatusCode.ToString());
            Ui.Detail("trailer error", ex.Trailers.GetValue("error") ?? "(none)");
            Ui.Detail("message", ex.Status.Detail);
            return ex.StatusCode.ToString();
        }
    });

    // ── 7. The management gate ───────────────────────────────
    var users = new Users.UsersClient(channel);

    await Ui.Step("Gate", "an admin operation with no token", async () =>
    {
        try
        {
            await users.ListAsync(Mgmt.Request(new { offset = 0, count = 1 }));
            return "!! it ran without credentials";
        }
        catch (RpcException ex)
        {
            Ui.Detail("status", ex.StatusCode.ToString());
            Ui.Detail("trailer error", ex.Trailers.GetValue("error") ?? "(none)");
            return "refused, not executed";
        }
    });

    await Ui.Step("Gate", "the same operation with the token", async () =>
    {
        var response = await users.ListAsync(
            Mgmt.Request(new { offset = 0, count = 3 }),
            Mgmt.Bearer(accessToken));

        Ui.Detail("result", Mgmt.Summarize(response.Result));
        return "admitted";
    });

    Ui.Done();
    return 0;
}
catch (RpcException ex) when (ex.StatusCode == StatusCode.Unavailable)
{
    Ui.Fail($"nothing is listening on {grpcAddress}.",
        "Start the Tsak worker (redb.Tsak/src/redb.Tsak.Worker) and check that the identity.grpc context",
        "reported its endpoints as operational in Logs/log-<date>.txt.");
    return 1;
}
catch (Exception ex)
{
    Ui.Fail(ex.Message);
    return 1;
}

static class Args
{
    public static string? Value(string[] args, string name)
    {
        var i = Array.IndexOf(args, name);
        return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
    }
}

/// <summary>Registers a throwaway client through the HTTP facade, so the gRPC leg has something to use.</summary>
static class Dcr
{
    /// <summary>
    /// Granular scopes on purpose: the master <c>identity:manage</c> is deliberately not obtainable
    /// through dynamic registration, and the granular branch is the interesting one anyway — it is the
    /// scope table that both transports share.
    /// </summary>
    public const string Scope = "identity:users:read identity:users:write";

    public static async Task<(string ClientId, string ClientSecret)> RegisterAsync(string httpAddress)
    {
        // The dev server uses a self-signed certificate; this is a local viewer, not a security boundary.
        using var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator,
        };
        using var http = new HttpClient(handler);

        var body = JsonSerializer.Serialize(new
        {
            client_name = "grpc-viewer",
            grant_types = new[] { "client_credentials" },
            scope = Scope,
        });

        using var content = new StringContent(body, System.Text.Encoding.UTF8, "application/json");
        using var response = await http.PostAsync($"{httpAddress.TrimEnd('/')}/connect/register", content);
        var payload = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException($"DCR failed ({(int)response.StatusCode}): {payload}");

        var json = JsonDocument.Parse(payload).RootElement;
        return (json.GetProperty("client_id").GetString()!, json.GetProperty("client_secret").GetString()!);
    }
}

/// <summary>Helpers for the management contract, whose payloads are open <c>Struct</c>s.</summary>
static class Mgmt
{
    public static ManagementRequest Request(object arguments) => new()
    {
        Arguments = Struct.Parser.ParseJson(JsonSerializer.Serialize(arguments)),
    };

    public static Metadata Bearer(string token) => new() { { "authorization", "Bearer " + token } };

    /// <summary>One line about an open-shaped reply — enough to see something came back.</summary>
    public static string Summarize(Value? result)
    {
        if (result is null) return "(empty)";
        return result.KindCase switch
        {
            Value.KindOneofCase.StructValue =>
                string.Join(", ", result.StructValue.Fields.Select(f => $"{f.Key}={Short(f.Value)}")),
            Value.KindOneofCase.ListValue => $"{result.ListValue.Values.Count} items",
            _ => result.ToString(),
        };
    }

    private static string Short(Value v) => v.KindCase switch
    {
        Value.KindOneofCase.ListValue => $"[{v.ListValue.Values.Count}]",
        Value.KindOneofCase.StructValue => "{…}",
        Value.KindOneofCase.StringValue => v.StringValue,
        Value.KindOneofCase.NumberValue => v.NumberValue.ToString("0.##"),
        Value.KindOneofCase.BoolValue => v.BoolValue.ToString().ToLowerInvariant(),
        _ => "null",
    };
}

/// <summary>Console output. Timings are printed because they are the point: these are real milliseconds.</summary>
static class Ui
{
    private static int _step;

    public static void Title(string text)
    {
        Console.WriteLine();
        Write(ConsoleColor.Cyan, $"  {text}");
        Write(ConsoleColor.DarkGray, $"  {new string('─', text.Length + 2)}");
        Console.WriteLine();
    }

    public static void Kv(string key, string value)
    {
        Console.Write("  ");
        Write(ConsoleColor.DarkGray, $"{key}: ", newline: false);
        Console.WriteLine(value);
    }

    public static async Task<T> Step<T>(string name, string what, Func<Task<T>> action)
    {
        Console.WriteLine();
        Write(ConsoleColor.White, $"  {++_step}. {name}", newline: false);
        Write(ConsoleColor.DarkGray, $"  — {what}");

        var sw = Stopwatch.StartNew();
        var result = await action();
        sw.Stop();

        Console.Write("     ");
        Write(ConsoleColor.Green, $"{result}", newline: false);
        Write(ConsoleColor.DarkGray, $"   {sw.Elapsed.TotalMilliseconds:N1} ms");
        return result;
    }

    public static void Detail(string key, string value)
    {
        Console.Write("     ");
        Write(ConsoleColor.DarkGray, $"{key,-18}", newline: false);
        Console.WriteLine(value);
    }

    public static void Done()
    {
        Console.WriteLine();
        Write(ConsoleColor.Green, "  All steps completed.");
        Write(ConsoleColor.DarkGray,
            "  Each figure above is one round trip: client → facade → direct-vm → Core → back.");
        Console.WriteLine();
    }

    public static void Fail(params string[] lines)
    {
        Console.WriteLine();
        foreach (var line in lines) Write(ConsoleColor.Red, "  " + line);
        Console.WriteLine();
    }

    private static void Write(ConsoleColor color, string text, bool newline = true)
    {
        var previous = Console.ForegroundColor;
        Console.ForegroundColor = color;
        if (newline) Console.WriteLine(text); else Console.Write(text);
        Console.ForegroundColor = previous;
    }
}
