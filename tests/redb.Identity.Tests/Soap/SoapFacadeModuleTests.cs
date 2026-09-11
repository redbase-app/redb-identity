using System.Net;
using System.Net.Sockets;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using redb.Route.Core;
using Xunit;

namespace redb.Identity.Tests.Soap;

/// <summary>
/// Ф1 — the WS-Trust facade module boots: its config binder reads the Tsak-merged section, its module
/// host builds a child container, and its route builder mounts the STS listener.
/// <para>
/// <c>InitRoute.main</c> is called exactly the way the worker calls it, so everything but Tsak's own ALC
/// loading is exercised. The packaging path is verified by loading the <c>.tpkg</c> in a worker — see
/// <c>doc/SOAP/CHECKLIST.md</c>.
/// </para>
/// </summary>
public class SoapFacadeModuleTests : IAsyncLifetime
{
    private ServiceProvider _sp = null!;
    private RouteContext _context = null!;
    private int _port;

    private static int GetFreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    public Task InitializeAsync()
    {
        _port = GetFreePort();

        var services = new ServiceCollection();
        services.AddLogging();
        _sp = services.BuildServiceProvider();

        _context = new RouteContext(_sp, "identity.soap-test");
        return Task.CompletedTask;
    }

    public async Task DisposeAsync()
    {
        await _context.DisposeAsync();
        await _sp.DisposeAsync();
    }

    /// <summary>
    /// What Tsak hands a module: the merged 5-layer configuration as a nested dictionary. Using the real
    /// property name means the binder is exercised rather than bypassed.
    /// </summary>
    private void Configure(params (string Key, object? Value)[] soapSettings)
    {
        var soap = new Dictionary<string, object?>
        {
            ["Host"] = "127.0.0.1",
            ["Port"] = _port,
        };
        foreach (var (key, value) in soapSettings) soap[key] = value;

        _context.SetProperty<IDictionary<string, object?>>("IdentityTransport",
            new Dictionary<string, object?> { ["Soap"] = soap });
    }

    [Fact]
    public async Task Module_boots_and_mounts_the_sts_route()
    {
        // TLS is mandatory for this facade; a test has no certificate, so it takes the documented way out
        // — the same one an operator behind a terminating proxy takes.
        Configure(("Ssl", false), ("AllowPlaintext", true));

        Identity.Soap.InitRoute.main(_context);
        await _context.Start();

        // One route, not four: WS-Trust puts every operation on one address and tells them apart by the
        // WS-Addressing Action. The endpoint count in a worker log is therefore 1 for this module.
        _context.Routes.Select(r => r.RouteId).Should().Contain("soap-identity-sts");
    }

    /// <summary>
    /// The refusal is the feature. <c>UsernameToken</c> carries the client secret in clear text, so an STS
    /// on plain HTTP publishes credentials to anyone on the path — and a warning in a log is read after
    /// the fact, when the credentials have already travelled.
    /// </summary>
    [Fact]
    public async Task Without_tls_the_facade_refuses_to_start()
    {
        Configure(("Ssl", false));

        Identity.Soap.InitRoute.main(_context);
        var boot = async () => await _context.Start();

        (await boot.Should().ThrowAsync<InvalidOperationException>())
            .WithMessage("*refuses to start without TLS*");
    }

    /// <summary>
    /// A typo in the client-certificate mode must not read as «no certificate»: that would turn mTLS off
    /// on an endpoint whose operator believes it is on, and nothing anywhere would say so.
    /// </summary>
    [Fact]
    public async Task An_unknown_client_certificate_mode_is_refused()
    {
        Configure(("AllowPlaintext", true), ("Ssl", false), ("ClientCertificateMode", "Required"));

        Identity.Soap.InitRoute.main(_context);
        var boot = async () => await _context.Start();

        (await boot.Should().ThrowAsync<InvalidOperationException>())
            .WithMessage("*ClientCertificateMode*");
    }
}
