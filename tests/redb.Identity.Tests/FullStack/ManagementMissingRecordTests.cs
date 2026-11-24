using System.Net.Http.Headers;
using System.Net.Http.Json;
using AwesomeAssertions;
using redb.Identity.Tests.Infrastructure;
using Xunit;
using Xunit.Abstractions;

namespace redb.Identity.Tests.FullStack;

/// <summary>
/// A management request that names a record which does not exist is answered 404. It is never a
/// server error: the caller asked for something that is not there, the server did not fail.
/// </summary>
[Collection("ProductionHttp")]
public class ManagementMissingRecordTests
{
    private const string MissingId = "987654321012";

    private readonly ProductionHttpFixture _fx;
    private readonly ITestOutputHelper _out;

    public ManagementMissingRecordTests(ProductionHttpFixture fx, ITestOutputHelper output)
    {
        _fx = fx;
        _out = output;
    }

    public static IEnumerable<object?[]> Requests() => new[]
    {
        new object?[] { "PUT", $"/api/v1/identity/roles/{MissingId}", """{"displayName":"x"}""" },
        new object?[] { "PUT", $"/api/v1/identity/groups/{MissingId}", """{"name":"x"}""" },
        new object?[] { "POST", $"/api/v1/identity/groups/{MissingId}/children", """{"name":"child-of-nothing"}""" },
        new object?[] { "POST", $"/api/v1/identity/groups/{MissingId}/move", """{"newParentGroupId":987654321013}""" },
        new object?[] { "GET", $"/api/v1/identity/groups/{MissingId}/path", null },
        new object?[] { "GET", $"/api/v1/identity/groups/{MissingId}/children", null },
        new object?[] { "POST", $"/api/v1/identity/groups/{MissingId}/members", """{"userId":1}""" },
        new object?[] { "GET", $"/api/v1/identity/groups/{MissingId}", null },
        new object?[] { "GET", $"/api/v1/identity/groups/{MissingId}/tree", null },
        new object?[] { "PUT", $"/api/v1/identity/groups/{MissingId}/members/1", """{"role":"member"}""" },
        new object?[] { "GET", $"/api/v1/identity/roles/{MissingId}", null },
        new object?[] { "PUT", $"/api/v1/identity/users/{MissingId}", """{"displayName":"x"}""" },
        new object?[] { "PUT", $"/api/v1/identity/applications/{MissingId}", """{"displayName":"x"}""" },
        new object?[] { "PUT", $"/api/v1/identity/scopes/{MissingId}", """{"displayName":"x"}""" },
        new object?[] { "PUT", $"/api/v1/identity/claim-definitions/{MissingId}", """{"displayName":"x"}""" },
        new object?[] { "PUT", $"/api/v1/identity/federation-providers/{MissingId}", """{"displayName":"x"}""" },
        new object?[] { "DELETE", $"/api/v1/identity/federation-providers/{MissingId}", null },
    };

    [Theory]
    [MemberData(nameof(Requests))]
    public async Task ARecordThatDoesNotExist_IsAnswered404(string method, string path, string? body)
    {
        using var request = new HttpRequestMessage(new HttpMethod(method), path);
        if (body is not null)
            request.Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _fx.ManagementToken);

        using var response = await _fx.Http.SendAsync(request);
        var answer = await response.Content.ReadAsStringAsync();
        _out.WriteLine($"MISSING {method} {path} -> [{(int)response.StatusCode}] {(answer.Length > 200 ? answer[..200] : answer)}");

        ((int)response.StatusCode).Should().Be(404, answer);
    }
}
