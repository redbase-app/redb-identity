using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using AwesomeAssertions;
using redb.Identity.Tests.Infrastructure;
using Xunit;
using Xunit.Abstractions;

namespace redb.Identity.Tests.Audit;

/// <summary>
/// An audit target receives the event and its own headers, never the request that raised it. Events are
/// raised on a WireTap copy of the request exchange; up to 4.5.0 that copy's headers (client_secret and the
/// other form fields, Authorization, Host, redbHttp.*) travelled on to every audit target.
/// </summary>
[Collection("ProductionHttp")]
public sealed class AuditTargetCarriesNoRequestHeadersTests
{
    private static readonly string[] EventHeaders =
        ["event-type", "event_id", "event_type", "timestamp", "user_id", "client_id", "ip_address", "user_agent", "details"];

    private readonly ProductionHttpFixture _fx;
    private readonly ITestOutputHelper _output;

    public AuditTargetCarriesNoRequestHeadersTests(ProductionHttpFixture fx, ITestOutputHelper output)
    {
        _fx = fx;
        _output = output;
    }

    [Fact]
    public async Task TokenRequest_EventAtTheTarget_CarriesNoSecretNoTokenNoRequestHeaders()
    {
        using var response = await _fx.Http.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = ProductionHttpFixture.TestClientId,
            ["client_secret"] = ProductionHttpFixture.TestClientSecret,
        }));
        var body = await response.Content.ReadAsStringAsync();
        response.StatusCode.Should().Be(HttpStatusCode.OK, "token: {0}", body);
        var accessToken = JsonDocument.Parse(body).RootElement.GetProperty("access_token").GetString()!;

        var message = await WaitForAsync(m =>
            Equals(m.Headers.GetValueOrDefault("event_type"), "TokenIssued")
            && Equals(m.Headers.GetValueOrDefault("client_id"), ProductionHttpFixture.TestClientId));

        AssertClean(message, ProductionHttpFixture.TestClientSecret, accessToken);
    }

    [Fact]
    public async Task BearerCall_EventAtTheTarget_CarriesNoAuthorization()
    {
        var groupName = "audit-leak-" + Guid.NewGuid().ToString("N")[..8];
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/identity/groups")
        {
            Content = JsonContent.Create(new { name = groupName }),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _fx.ManagementToken);
        using var response = await _fx.Http.SendAsync(request);
        response.StatusCode.Should().Be(HttpStatusCode.OK, await response.Content.ReadAsStringAsync());

        var message = await WaitForAsync(m => m.Body.Contains(groupName));

        AssertClean(message, ProductionHttpFixture.TestMgmtSecret, _fx.ManagementToken);
        // The group's name is in the event details and in the call's answer alike: the body must be the event.
        JsonDocument.Parse(message.Body).RootElement.GetProperty("eventType").GetString().Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task ManagementRoute_EventAtTheTarget_IsTheEventNotTheResponse()
    {
        // A startup route of a consumer module, in process: attach a scope to a role, then read the role's
        // scopes on the same exchange. Both calls answer with a body (a status, a list of scopes); the
        // target must get the RoleScopeAttached event, never those answers.
        var suffix = Guid.NewGuid().ToString("N")[..8];
        var (roleId, scopeId) = await _fx.UseRedbAsync(async redb =>
        {
            var svc = new redb.Identity.Core.Services.RoleService(redb);
            var role = await svc.CreateRoleAsync("audit-body-" + suffix, "organization", applicationId: null,
                displayName: null, description: null);
            var scope = new redb.Core.Models.Entities.RedbObject<redb.Identity.Core.Models.ScopeProps>(
                new redb.Identity.Core.Models.ScopeProps { ScopeName = "audit-body-" + suffix, Description = "Audit body scope" })
            { Name = "audit-body-" + suffix };
            await redb.SaveAsync(scope);
            return (role.Id, scope.Id);
        });

        var message = new redb.Route.Core.Message { Body = new Dictionary<string, object?> { ["roleId"] = roleId, ["scopeId"] = scopeId } };
        message.Headers["operation"] = "attach-scope";
        var exchange = new redb.Route.Core.Exchange(message) { Pattern = redb.Route.Abstractions.ExchangePattern.InOut };
        ManagementCallerContext.Apply(exchange, ManagementCaller.Admin);
        await _fx.Producer.SendAsync(redb.Identity.Contracts.Routes.IdentityEndpoints.ManageRoles, exchange);
        exchange.Exception.Should().BeNull();

        exchange.In = new redb.Route.Core.Message { Body = new Dictionary<string, object?> { ["roleId"] = roleId } };
        exchange.In.Headers["operation"] = "list-scopes";
        exchange.Out = null;
        await _fx.Producer.SendAsync(redb.Identity.Contracts.Routes.IdentityEndpoints.ManageRoles, exchange);
        exchange.Exception.Should().BeNull();

        var roleMarker = "\"RoleId\":" + roleId + ",";
        await WaitForAsync(m => (m.Headers.GetValueOrDefault("details")?.ToString() ?? "").Contains(roleMarker));
        await Task.Delay(1500); // the second call's tap, if it raised one, lands shortly after

        var forRole = _fx.AuditTargetMessages
            .Where(m => (m.Headers.GetValueOrDefault("details")?.ToString() ?? "").Contains(roleMarker))
            .ToList();
        // The read on the same exchange raises nothing: the attach is reported once, not again by list-scopes.
        forRole.Should().ContainSingle(m => Equals(m.Headers.GetValueOrDefault("event_type"), "RoleScopeAttached"));
        forRole.Should().HaveCount(1);
        foreach (var m in forRole)
        {
            _output.WriteLine("body: " + m.Body);
            var body = JsonDocument.Parse(m.Body).RootElement;
            body.ValueKind.Should().Be(JsonValueKind.Object, "the target gets the event, not the call's answer: {0}", m.Body);
            body.GetProperty("eventType").GetString().Should().Be(m.Headers["event_type"]!.ToString());
            body.GetProperty("eventId").GetString().Should().NotBeNullOrEmpty();
            m.Body.Should().NotContain("scopeName").And.NotContain("success");
        }
    }

    [Fact]
    public async Task ManagementRead_RaisesNoEvent_AndItsAnswerReachesNoTarget()
    {
        // Every management operation passes the route's WireTap, reads included. A read raises no event,
        // and its answer (here the role's scopes) must not be delivered to the audit targets.
        var suffix = Guid.NewGuid().ToString("N")[..8];
        var scopeName = "audit-read-" + suffix;
        var roleId = await _fx.UseRedbAsync(async redb =>
        {
            var svc = new redb.Identity.Core.Services.RoleService(redb);
            var role = await svc.CreateRoleAsync("audit-read-" + suffix, "organization", applicationId: null,
                displayName: null, description: null);
            var scope = new redb.Core.Models.Entities.RedbObject<redb.Identity.Core.Models.ScopeProps>(
                new redb.Identity.Core.Models.ScopeProps { ScopeName = scopeName }) { Name = scopeName };
            await redb.SaveAsync(scope);
            await svc.AttachScopeAsync(role.Id, scope.Id, actingUserId: null);
            return role.Id;
        });

        var message = new redb.Route.Core.Message { Body = new Dictionary<string, object?> { ["roleId"] = roleId } };
        message.Headers["operation"] = "list-scopes";
        var exchange = new redb.Route.Core.Exchange(message) { Pattern = redb.Route.Abstractions.ExchangePattern.InOut };
        ManagementCallerContext.Apply(exchange, ManagementCaller.Admin);
        await _fx.Producer.SendAsync(redb.Identity.Contracts.Routes.IdentityEndpoints.ManageRoles, exchange);
        exchange.Exception.Should().BeNull();
        ((exchange.Out ?? exchange.In).Body?.ToString() ?? "").Should().NotBeNull();

        await Task.Delay(1500); // the tap is fire-and-forget
        _fx.AuditTargetMessages.Should().NotContain(m => m.Body.Contains(scopeName),
            "a read raises no event and its answer goes nowhere");
    }

    private void AssertClean((Dictionary<string, object?> Headers, string Body) message, string secret, string token)
    {
        _output.WriteLine("headers: " + string.Join(", ", message.Headers.Keys));
        message.Headers.Keys.Should().BeSubsetOf(EventHeaders.Append("Content-Type"),
            "an audit target gets the event headers only");
        message.Headers.Keys.Should().NotContain(k => k.StartsWith("redbHttp.", StringComparison.OrdinalIgnoreCase));
        foreach (var value in message.Headers.Values)
        {
            var text = value?.ToString() ?? string.Empty;
            text.Should().NotContain(secret);
            text.Should().NotContain(token);
        }
        message.Body.Should().NotContain(secret).And.NotContain(token);
    }

    private async Task<(Dictionary<string, object?> Headers, string Body)> WaitForAsync(
        Func<(Dictionary<string, object?> Headers, string Body), bool> match)
    {
        var deadline = DateTime.UtcNow.AddSeconds(15);
        while (DateTime.UtcNow < deadline)
        {
            foreach (var m in _fx.AuditTargetMessages)
                if (match(m))
                    return m;
            await Task.Delay(100);
        }
        throw new TimeoutException("the audit target did not receive the expected event");
    }
}
