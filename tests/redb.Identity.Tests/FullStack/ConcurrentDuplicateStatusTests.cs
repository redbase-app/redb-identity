using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using AwesomeAssertions;
using redb.Identity.Contracts.Scim;
using redb.Identity.Tests.Infrastructure;
using Xunit;
using Xunit.Abstractions;

namespace redb.Identity.Tests.FullStack;

/// <summary>
/// Concurrent creation of one and the same record through the HTTP surface. The check before the
/// insert cannot serialise the callers, so the losers reach the database and are refused by a
/// unique key. That refusal is a conflict the caller caused: it must be answered 409, never 500.
/// The answer depends on which exception type the provider raises, so these tests are worth
/// running on every provider.
/// </summary>
[Collection("ProductionHttp")]
public class ConcurrentDuplicateStatusTests
{
    private const int Callers = 6;

    private readonly ProductionHttpFixture _fx;
    private readonly ITestOutputHelper _out;

    public ConcurrentDuplicateStatusTests(ProductionHttpFixture fx, ITestOutputHelper output)
    {
        _fx = fx;
        _out = output;
    }

    [Fact]
    public async Task FederationProvider_ConcurrentSameProviderId_OneCreated_OthersConflict()
    {
        var providerId = "race-" + Guid.NewGuid().ToString("N")[..12];
        var statuses = await SendConcurrentlyAsync(() => Management("/api/v1/identity/federation-providers", new
        {
            providerId,
            kind = "oidc",
            displayName = "Race " + providerId,
            authority = "https://idp.example.test/",
            clientId = "race-client",
            clientSecret = "race-secret",
            enabled = false,
        }));

        // A loser that arrives after the winner committed is refused by the processor's own check, which
        // answers 400 "conflict" on this endpoint; one that was already past the check is refused by the
        // unique key and answered 409. Both are the caller's conflict; neither may be a server error.
        statuses.Should().OnlyContain(s => s < 500, "a duplicate is the caller's conflict, not a server failure");
        statuses.Count(s => s is >= 200 and < 300).Should().Be(1, "exactly one caller may create the record");
        statuses.Count(s => s is 400 or 409).Should().Be(Callers - 1, "every other caller must be refused as a conflict");
    }

    [Fact]
    public async Task Scope_ConcurrentSameName_OneCreated_OthersConflict()
    {
        var name = "race-scope-" + Guid.NewGuid().ToString("N")[..12];
        var statuses = await SendConcurrentlyAsync(() => Management("/api/v1/identity/scopes", new { name }));

        AssertOneWinnerOthersConflict(statuses);
    }

    [Fact]
    public async Task ScimUser_ConcurrentSameUserName_OneCreated_OthersConflict()
    {
        var user = new ScimUser { UserName = "race-scim-" + Guid.NewGuid().ToString("N")[..12], Active = true };
        var statuses = await SendConcurrentlyAsync(() =>
        {
            var request = new HttpRequestMessage(HttpMethod.Post, "/scim/v2/Users")
            {
                Content = new StringContent(JsonSerializer.Serialize(user), Encoding.UTF8, ScimConstants.MediaType),
            };
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _fx.ScimToken);
            return request;
        });

        AssertOneWinnerOthersConflict(statuses);
    }

    [Fact]
    public async Task Group_ConcurrentSameName_NeverAnswersServerError()
    {
        // A group name carries no unique key, so how many callers win is not asserted here:
        // only that none of them is told the server failed.
        var name = "race-group-" + Guid.NewGuid().ToString("N")[..12];
        var statuses = await SendConcurrentlyAsync(() => Management("/api/v1/identity/groups", new { name }));

        statuses.Should().OnlyContain(s => s < 500, "a duplicate is the caller's conflict, not a server failure");
    }

    private HttpRequestMessage Management(string path, object body)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = JsonContent.Create(body) };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _fx.ManagementToken);
        return request;
    }

    private async Task<int[]> SendConcurrentlyAsync(Func<HttpRequestMessage> newRequest)
    {
        var responses = await Task.WhenAll(
            Enumerable.Range(0, Callers).Select(_ => _fx.Http.SendAsync(newRequest())));
        try
        {
            foreach (var response in responses)
                _out.WriteLine($"[{(int)response.StatusCode}] {await response.Content.ReadAsStringAsync()}");
            return responses.Select(r => (int)r.StatusCode).OrderBy(s => s).ToArray();
        }
        finally
        {
            foreach (var response in responses) response.Dispose();
        }
    }

    private static void AssertOneWinnerOthersConflict(int[] statuses)
    {
        statuses.Should().OnlyContain(s => s < 500, "a duplicate is the caller's conflict, not a server failure");
        statuses.Count(s => s is >= 200 and < 300).Should().Be(1, "exactly one caller may create the record");
        statuses.Count(s => s == 409).Should().Be(Callers - 1, "every other caller must be told 409");
    }
}
