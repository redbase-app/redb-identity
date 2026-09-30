using System.Text.RegularExpressions;
using FluentAssertions;
using Xunit;

namespace redb.Identity.Tests.Architecture;

/// <summary>
/// Every HTTP route strips the reserved inbound headers before it does anything else.
/// <para>
/// The HTTP consumer copies every request header into the exchange verbatim, while processors downstream
/// trust a handful of names as if a facade had set them — <c>session_user_id</c> becomes the principal,
/// <c>user_id</c> / <c>ip_address</c> / <c>user_agent</c> sign the audit log. The facade's answer is
/// <c>PropagateCorrelationId</c>, whose first act is to remove those names, documented as "the first
/// processor on every HTTP route — so no route can forget it". It was a promise kept by hand: the
/// management catch-all (<c>http-management-api</c>) and the SCIM catch-all (<c>http-scim-api</c>)
/// never called it. Nothing on those two routes reads a reserved name today, so this was a structural
/// gap rather than an exploit — which is exactly why it needs a check: the next processor that reads
/// one there would have trusted whatever the caller sent.
/// </para>
/// <para>
/// Read from source, like the other fitness tests here: for each <c>From(...)</c> in the HTTP route
/// builder, the very first call after <c>RouteId(...)</c> must be the strip — whatever that call is,
/// not only a step from some list of DSL names, because a method the list does not know would otherwise
/// pass unseen in front of the strip. A route without a <c>RouteId</c> is an offender too: every route
/// here is named, and the supervisor's error attribution depends on it.
/// </para>
/// </summary>
public class HttpRouteReservedHeaderStripTests
{
    private const string Strip = "Process(HttpIdentityProcessors.PropagateCorrelationId)";

    /// <summary>
    /// From the end of <c>RouteId(...)</c> to the start of the next fluent call: optional statement end,
    /// optional receiver (<c>route.</c>), then the dot. What follows must be the strip.
    /// </summary>
    private static readonly Regex NextCall = new(@"^\s*;?\s*(?:\w+\s*)?\.", RegexOptions.Compiled);

    private static string LocateRouteBuilder()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            foreach (var candidate in new[]
                     {
                         Path.Combine(dir.FullName, "src", "redb.Identity.Http", "HttpFacadeRouteBuilder.cs"),
                         Path.Combine(dir.FullName, "redb.Identity", "src", "redb.Identity.Http", "HttpFacadeRouteBuilder.cs"),
                     })
            {
                if (File.Exists(candidate)) return candidate;
            }
            dir = dir.Parent;
        }
        throw new InvalidOperationException("Could not locate HttpFacadeRouteBuilder.cs from the test base directory.");
    }

    [Fact]
    public void Every_http_route_strips_the_reserved_headers_first()
    {
        var source = File.ReadAllText(LocateRouteBuilder());

        // Comments talk about From(...) and the strip constantly; only code counts.
        source = Regex.Replace(source, @"/\*.*?\*/", string.Empty, RegexOptions.Singleline);
        source = Regex.Replace(source, @"//.*?$", string.Empty, RegexOptions.Multiline);

        var starts = Regex.Matches(source, @"\bFrom\(").Select(m => m.Index).ToList();
        starts.Should().NotBeEmpty("the HTTP facade declares its routes in this file");

        var offenders = new List<string>();
        for (var i = 0; i < starts.Count; i++)
        {
            var end = i + 1 < starts.Count ? starts[i + 1] : source.Length;
            var route = source[starts[i]..end];

            var routeIdCall = Regex.Match(route, @"\.RouteId\(([^)]*)\)");
            if (!routeIdCall.Success)
            {
                offenders.Add("<unnamed route> " + route[..Math.Min(80, route.Length)].ReplaceLineEndings(" "));
                continue;
            }

            var afterRouteId = route[(routeIdCall.Index + routeIdCall.Length)..];
            var next = NextCall.Match(afterRouteId);
            var stripsFirst = next.Success
                              && afterRouteId.AsSpan(next.Length).StartsWith(Strip, StringComparison.Ordinal);
            if (!stripsFirst)
                offenders.Add(routeIdCall.Groups[1].Value);
        }

        // BeEmpty names only the first offender; the list is spelled out so a failure shows all of them.
        offenders.Should().BeEmpty(
            "every HTTP route must remove the caller-supplied reserved headers before any step can read them; "
            + "a route that skips it trusts whatever the caller sent for session_user_id, user_id, ip_address and "
            + "the rest. Routes without the strip first: {0}", string.Join(", ", offenders));
    }
}
