using AwesomeAssertions;
using redb.Identity.Core.Routes.Processors;
using redb.Identity.Tests.Infrastructure;
using Xunit;

namespace redb.Identity.Tests.Routes;

/// <summary>
/// The management gate starts every operation without an event, so an exchange reused for several
/// in-process management calls does not carry the previous call's event into the next route's WireTap.
/// </summary>
public class RequireManagementContextProcessorTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task PreviousEventMarkers_AreClearedOnEntry(bool withContext)
    {
        var exchange = new TestExchange();
        exchange.Properties["identity-event-type"] = "RoleScopeAttached";
        exchange.Properties["identity-event-data"] = new { RoleId = 1L, ScopeId = 2L };
        if (withContext)
            ManagementCallerContext.Apply(exchange, ManagementCaller.Admin);

        await new RequireManagementContextProcessor().Process(exchange);

        exchange.Properties.Should().NotContainKey("identity-event-type");
        exchange.Properties.Should().NotContainKey("identity-event-data");
        exchange.IsStopped.Should().Be(!withContext, "the gate itself still admits or refuses as before");
    }
}
