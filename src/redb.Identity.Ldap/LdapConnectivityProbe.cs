using System.Net;
using System.Net.Sockets;

namespace redb.Identity.Ldap;

/// <summary>
/// Bounded TCP/DNS pre-flight probe for LDAP endpoints.
/// <para>
/// LdapForNet's <c>OperationTimeout</c> bounds only the LDAP-protocol exchange
/// AFTER the socket is established. It does not cap DNS resolution nor the
/// underlying TCP <c>connect()</c>, so an unreachable host (firewalled IP,
/// black-holed route, NXDOMAIN behind a slow resolver) lets the OS-level SYN
/// retransmit timeout dominate latency — on Windows that is ~21 s for a routed
/// but silent destination, and 5–10 s for typical NXDOMAIN.
/// </para>
/// <para>
/// This probe runs <see cref="Dns.GetHostAddressesAsync(string, CancellationToken)"/>
/// + <see cref="TcpClient.ConnectAsync(IPAddress, int, CancellationToken)"/>
/// inside a single bounded <see cref="CancellationTokenSource"/> and converts
/// any timeout/cancellation into a <see cref="TimeoutException"/>, so the
/// caller fails fast instead of blocking the request thread.
/// </para>
/// </summary>
internal static class LdapConnectivityProbe
{
    /// <summary>
    /// Verifies that <paramref name="host"/>:<paramref name="port"/> is
    /// reachable within <paramref name="timeoutSeconds"/>. The socket is
    /// closed immediately after a successful connect — the real LDAP client
    /// opens its own connection. Throws <see cref="TimeoutException"/> on
    /// timeout, <see cref="SocketException"/> on hard refusal, or propagates
    /// <paramref name="ct"/> cancellation.
    /// </summary>
    /// <remarks>
    /// A no-op when <paramref name="timeoutSeconds"/> ≤ 0 — callers that
    /// wish to disable the probe (e.g. in environments where every LDAP host
    /// blocks ICMP/SYN scans but LDAP itself is fine) can set the option to 0.
    /// </remarks>
    public static async Task ProbeAsync(
        string host, int port, int timeoutSeconds, CancellationToken ct)
    {
        if (timeoutSeconds <= 0) return;
        if (string.IsNullOrWhiteSpace(host))
            throw new ArgumentException("Host is required.", nameof(host));

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));

        try
        {
            IPAddress[] addresses;
            if (IPAddress.TryParse(host, out var literal))
            {
                addresses = [literal];
            }
            else
            {
                addresses = await Dns.GetHostAddressesAsync(host, cts.Token)
                    .ConfigureAwait(false);
                if (addresses.Length == 0)
                    throw new SocketException((int)SocketError.HostNotFound);
            }

            // First-address strategy — matches what TcpClient(host, port) does
            // internally. If the host is multi-homed and the first IP is
            // dead, we will report a timeout; this matches LdapForNet's own
            // behaviour and keeps the probe deterministic.
            using var tcp = new TcpClient(addresses[0].AddressFamily) { NoDelay = true };
            await tcp.ConnectAsync(addresses[0], port, cts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new TimeoutException(
                $"LDAP connectivity probe timed out after {timeoutSeconds}s for {host}:{port}");
        }
    }
}
