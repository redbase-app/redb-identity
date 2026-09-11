using System.Diagnostics;
using System.Net.Sockets;
using System.Text.Json;
using FluentAssertions;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Grpc;

/// <summary>
/// F4 — the published contract, exercised by a stack that shares no code with ours: an
/// <c>@grpc/grpc-js</c> client generated from <c>identity.v1.proto</c> the way any consumer would generate
/// it, running in another process inside a container (see <c>C:\Work\yaml\grpc</c>).
/// <para>
/// This is what the loopback tests cannot show. They use our own byte marshallers against our own
/// listener, so a contract that disagreed with itself consistently would still pass. Here a foreign
/// implementation parses the <c>.proto</c> we publish and has to accept the bytes we send — including the
/// trailers, which is where a non-OK reply keeps the only machine-readable thing it has left.
/// </para>
/// <para>
/// GATED: each test no-ops unless the container answers on 127.0.0.1:18100, so the normal suite stays
/// green without Docker. Run <c>docker compose up -d</c> in <c>C:\Work\yaml\grpc</c> first. The gate is
/// deliberately loud in one direction only — a missing container skips, a broken contract fails.
/// </para>
/// </summary>
[Trait("Category", "Interop")]
[Collection("PostgresCollection")]
public class GrpcIdentityInteropTests : IClassFixture<GrpcInteropIdentityFixture>
{
    private const int ContainerPort = 18100;   // the compose-mapped grpc-js host, our proof it is running
    private readonly GrpcInteropIdentityFixture _fixture;

    public GrpcIdentityInteropTests(GrpcInteropIdentityFixture fixture) => _fixture = fixture;

    [Fact]
    public void A_foreign_client_gets_a_token_from_the_published_contract()
    {
        if (!ContainerIsUp()) return;

        var result = Call("Token", new
        {
            grant_type = "client_credentials",
            client_id = GrpcIdentityFixture.ClientId,
            client_secret = GrpcIdentityFixture.ClientSecret,
            scope = GrpcIdentityFixture.GrantedScope,
        });

        result.GetProperty("ok").GetBoolean().Should().BeTrue("{0}", result);
        var token = result.GetProperty("value");
        token.GetProperty("access_token").GetString().Should().NotBeNullOrEmpty();
        token.GetProperty("token_type").GetString().Should().Be("Bearer");
    }

    [Fact]
    public void A_foreign_client_reads_the_refusal_as_a_status_and_a_trailer()
    {
        if (!ContainerIsUp()) return;

        var result = Call("Token", new
        {
            grant_type = "client_credentials",
            client_id = GrpcIdentityFixture.ClientId,
            client_secret = "not-the-secret",
        });

        result.GetProperty("ok").GetBoolean().Should().BeFalse("a wrong secret must not yield a token");
        result.GetProperty("status").GetString().Should().Be("UNAUTHENTICATED");

        // The payload of a non-OK reply is discarded by the protocol itself, so this trailer is the only
        // place the caller can learn *which* refusal it was.
        result.GetProperty("trailers").GetProperty("error").GetString().Should().Be("invalid_client");
    }

    [Fact]
    public void A_foreign_client_reads_the_discovery_document()
    {
        if (!ContainerIsUp()) return;

        // A Struct field decoded by a foreign runtime: proves the overflow shape is real protobuf and not
        // something only our own codec agrees with.
        var result = Call("Discovery", new { });

        result.GetProperty("ok").GetBoolean().Should().BeTrue("{0}", result);
        var fields = result.GetProperty("value").GetProperty("document").GetProperty("fields");
        fields.GetProperty("issuer").GetProperty("stringValue").GetString()
            .Should().Be($"http://localhost:{_fixture.Port}/");

        // The document keeps advertising the server.s HTTP addresses. Rewriting them for gRPC callers
        // would hand them endpoints that do not exist.
        fields.GetProperty("token_endpoint").GetProperty("stringValue").GetString()
            .Should().EndWith("/connect/token");

        // A list inside the Struct, decoded by a runtime that never saw our codec.
        fields.GetProperty("scopes_supported").GetProperty("listValue").GetProperty("values")
            .EnumerateArray().Should().NotBeEmpty();
    }

    // ── helpers ───────────────────────────────────────────────

    /// <summary>
    /// Runs the container's client against our facade and returns its JSON verdict. The request travels
    /// on stdin: `docker exec` hands argv straight to the process with no shell, and Windows argument
    /// splitting eats the quotes out of a JSON literal before the container ever sees it.
    /// </summary>
    private JsonElement Call(string method, object request)
    {
        var info = new ProcessStartInfo("docker")
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var argument in new[]
                 {
                     "exec", "-i", "grpc-echo", "node", "identity-client.js",
                     $"host.docker.internal:{_fixture.Port}", method,
                 })
        {
            info.ArgumentList.Add(argument);
        }

        using var process = Process.Start(info)!;
        process.StandardInput.Write(JsonSerializer.Serialize(request));
        process.StandardInput.Close();

        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit(60_000);

        var line = stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .LastOrDefault(l => l.TrimStart().StartsWith('{'));

        line.Should().NotBeNull($"client produced no verdict. stdout={stdout} stderr={stderr}");
        return JsonDocument.Parse(line!).RootElement.Clone();
    }


    private static bool ContainerIsUp()
    {
        try
        {
            using var probe = new TcpClient();
            return probe.ConnectAsync("127.0.0.1", ContainerPort).Wait(TimeSpan.FromSeconds(1));
        }
        catch { return false; }
    }
}
