using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using FluentAssertions;
using Grpc.Core;
using Google.Protobuf;
using Grpc.Net.Client;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using redb.Route.Abstractions;
using redb.Route.Core;
using Xunit;

namespace redb.Identity.Tests.Grpc;

/// <summary>
/// F0 — the gRPC facade module boots: its config binder reads the Tsak-merged section, its module host
/// builds a child container, its route builder mounts a listener, and the port answers a real gRPC client.
/// <para>
/// Everything except Tsak's own ALC loading is exercised here: <c>InitRoute.main</c> is called exactly the
/// way the worker calls it. What this cannot cover is the packaging path — that is verified by loading the
/// <c>.tpkg</c> in a worker (see <c>doc/gRPC/CHECKLIST.md</c>, F0).
/// </para>
/// </summary>
public class GrpcFacadeModuleTests : IAsyncLifetime
{
    private ServiceProvider _sp = null!;
    private RouteContext _context = null!;
    private int _port;

    public Task InitializeAsync()
    {
        _port = GetFreePort();

        var services = new ServiceCollection();
        services.AddLogging();
        _sp = services.BuildServiceProvider();

        _context = new RouteContext(_sp, "identity.grpc-test");

        // What Tsak hands a module: the merged 5-layer configuration as a nested dictionary. Using the
        // real property name means the binder is exercised, not bypassed.
        _context.SetProperty<IDictionary<string, object?>>("IdentityTransport", new Dictionary<string, object?>
        {
            ["Grpc"] = new Dictionary<string, object?>
            {
                ["Host"] = "127.0.0.1",
                ["PublicPort"] = _port,
            },
        });

        return Task.CompletedTask;
    }

    public async Task DisposeAsync()
    {
        await _context.DisposeAsync();
        await _sp.DisposeAsync();
    }

    [Fact]
    public async Task Module_boots_and_mounts_every_operation_as_its_own_route()
    {
        redb.Identity.Grpc.InitRoute.main(_context);
        await _context.Start();

        // One method address = one route. That is the whole point of the design: each operation gets its
        // own id, policies, metrics and lifecycle instead of hiding inside one Choice().
        _context.Routes.Select(r => r.RouteId).Should().Contain(
        [
            "grpc-identity-token",
            "grpc-identity-introspect",
            "grpc-identity-revoke",
            "grpc-identity-userinfo",
            "grpc-identity-discovery",
            "grpc-identity-jwks",
            "grpc-identity-envelope",
        ]);
    }

    [Fact]
    public async Task Envelope_without_an_operation_says_what_it_expects()
    {
        redb.Identity.Grpc.InitRoute.main(_context);
        await _context.Start();

        // The fallback path is keyed by an `operation` header. Answering with the list of known
        // operations beats a bare InvalidArgument the caller has to guess about.
        var act = async () => await CallAsync("/redb.route.grpc.RedbService/Process");

        var ex = await act.Should().ThrowAsync<RpcException>();
        ex.Which.StatusCode.Should().Be(StatusCode.InvalidArgument);
        ex.Which.Status.Detail.Should().Contain("operation").And.Contain("token");
    }


    [Fact]
    public async Task The_module_registers_the_management_surface_too()
    {
        // What every other test in this file could not see: they call the protocol addresses, and those
        // were registered. The management builder was not, so forty admin operations existed, were fully
        // covered by their own tests, and were unreachable in any real deployment — while InitRoute's log
        // line still announced a management port. A live worker showed `identity.grpc` starting with 7
        // endpoints instead of 47. This asserts the wiring, not the behaviour behind it.
        redb.Identity.Grpc.InitRoute.main(_context);
        await _context.Start();

        var routeIds = _context.Routes.Select(r => r.RouteId).ToList();

        routeIds.Should().Contain("grpc-identity-token", "the protocol surface must stay registered");
        routeIds.Should().Contain("grpc-identity-manage-users-list",
            "the management surface must be registered by the module, not only by the tests");

        routeIds.Count(id => id.StartsWith("grpc-identity-manage-", StringComparison.Ordinal))
            .Should().Be(40, "all five groups ship, or the count says which are missing");
    }

    [Fact]
    public async Task Unknown_method_address_is_unimplemented()
    {
        redb.Identity.Grpc.InitRoute.main(_context);
        await _context.Start();

        var act = async () => await CallAsync("/identity.v1.Identity/Nope");

        (await act.Should().ThrowAsync<RpcException>())
            .Which.StatusCode.Should().Be(StatusCode.Unimplemented);
    }

    [Fact]
    public async Task Envelope_with_an_unknown_operation_is_unimplemented()
    {
        redb.Identity.Grpc.InitRoute.main(_context);
        await _context.Start();

        var envelope = new redb.Route.Grpc.Proto.RedbMessage();
        envelope.Headers.Add("operation", "nope");

        RpcException? failure = null;
        byte[]? reply = null;
        try
        {
            reply = await CallAsync("/redb.route.grpc.RedbService/Process", envelope.ToByteArray(),
                new Metadata { { "operation", "nope" } });
        }
        catch (RpcException ex) { failure = ex; }

        failure.Should().NotBeNull("the server instead answered: {0}",
            reply is null ? "(nothing)" : Convert.ToHexString(reply));
        failure!.StatusCode.Should().Be(StatusCode.Unimplemented);
    }

    [Fact]
    public async Task Health_probe_answers_serving()
    {
        redb.Identity.Grpc.InitRoute.main(_context);
        await _context.Start();

        // grpc.health.v1.Health/Check — what Kubernetes, Consul and Envoy probe.
        var reply = await CallAsync("/grpc.health.v1.Health/Check");

        // HealthCheckResponse { status = SERVING } → field 1, varint 1.
        reply.Should().Equal((byte)0x08, (byte)0x01);
    }

    [Fact]
    public async Task Config_binder_reads_the_tsak_section()
    {
        // The listener came up on the port the merged config declared, not on the 5001 default — which is
        // the only externally visible proof that the binder ran.
        redb.Identity.Grpc.InitRoute.main(_context);
        await _context.Start();

        IsReachable("127.0.0.1", _port).Should().BeTrue();
    }

    /// <summary>Calls a method address with an empty message and returns the reply bytes.</summary>
    private async Task<byte[]> CallAsync(string methodPath, byte[]? payload = null, Metadata? metadata = null)
    {
        using var channel = GrpcChannel.ForAddress($"http://127.0.0.1:{_port}");

        var slash = methodPath.LastIndexOf('/');
        var marshaller = Marshallers.Create(b => (byte[])b, b => b);
        var method = new Method<byte[], byte[]>(
            MethodType.Unary, methodPath[1..slash], methodPath[(slash + 1)..], marshaller, marshaller);

        return await channel.CreateCallInvoker()
            .AsyncUnaryCall(method, null, metadata is null ? new CallOptions() : new CallOptions(metadata), payload ?? Array.Empty<byte>());
    }

    private static bool IsReachable(string host, int port)
    {
        using var client = new TcpClient();
        try
        {
            return client.ConnectAsync(host, port).Wait(TimeSpan.FromSeconds(2)) && client.Connected;
        }
        catch
        {
            return false;
        }
    }

    private static int GetFreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }
}
