using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using AwesomeAssertions;
using redb.Identity.Contracts.Scim;
using redb.Identity.Tests.Infrastructure;
using Xunit;
using Xunit.Abstractions;

namespace redb.Identity.Tests.Scim;

/// <summary>
/// RFC 7644 3.12: a create refused for uniqueness is a SCIM error with scimType "uniqueness",
/// whichever check refused it, and its detail names the attribute that collided.
/// </summary>
[Collection("ProductionHttp")]
public class ScimDuplicateErrorTests
{
    private const int Callers = 6;

    private readonly ProductionHttpFixture _fx;
    private readonly ITestOutputHelper _out;

    public ScimDuplicateErrorTests(ProductionHttpFixture fx, ITestOutputHelper output)
    {
        _fx = fx;
        _out = output;
    }

    [Fact]
    public async Task ConcurrentCreatesOfOneUserName_EveryRefusalIsAScimUniquenessError()
    {
        // Which racing caller is refused by the processor's own check and which by the database
        // depends on the provider and on timing; the SCIM client must not see the difference.
        var user = new ScimUser { UserName = "race-scim-body-" + Guid.NewGuid().ToString("N")[..12], Active = true };
        var responses = await Task.WhenAll(Enumerable.Range(0, Callers).Select(_ => SendAsync(user)));

        try
        {
            responses.Count(r => (int)r.StatusCode == 201).Should().Be(1);
            foreach (var response in responses.Where(r => (int)r.StatusCode != 201))
            {
                var body = await response.Content.ReadAsStringAsync();
                _out.WriteLine(body);
                ((int)response.StatusCode).Should().Be(409, body);
                using var json = JsonDocument.Parse(body);
                json.RootElement.TryGetProperty("scimType", out var scimType).Should().BeTrue(body);
                scimType.GetString().Should().Be("uniqueness");
            }
        }
        finally
        {
            foreach (var response in responses) response.Dispose();
        }
    }

    [Fact]
    public async Task CreateWithAnEmailThatIsTaken_NamesTheEmail()
    {
        var email = $"scim-taken-{Guid.NewGuid():N}@example.test";
        ScimUser User(string prefix) => new()
        {
            UserName = prefix + Guid.NewGuid().ToString("N")[..12],
            Active = true,
            Emails = [new ScimMultiValuedAttribute { Value = email, Primary = true }],
        };

        using var first = await SendAsync(User("scim-mail-a-"));
        ((int)first.StatusCode).Should().Be(201, await first.Content.ReadAsStringAsync());

        using var second = await SendAsync(User("scim-mail-b-"));
        var answer = await second.Content.ReadAsStringAsync();
        _out.WriteLine(answer);
        ((int)second.StatusCode).Should().Be(409, answer);

        using var json = JsonDocument.Parse(answer);
        json.RootElement.GetProperty("scimType").GetString().Should().Be("uniqueness");
        json.RootElement.GetProperty("detail").GetString().Should().Contain(email).And.NotContain("userName");
    }

    private Task<HttpResponseMessage> SendAsync(ScimUser user)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/scim/v2/Users")
        {
            Content = new StringContent(JsonSerializer.Serialize(user), Encoding.UTF8, ScimConstants.MediaType),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _fx.ScimToken);
        return _fx.Http.SendAsync(request);
    }
}
