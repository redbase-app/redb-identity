using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Options;
using redb.Identity.Client.Auth;
using redb.Identity.Client.Tests.TestKit;

namespace redb.Identity.Client.Tests.TestKit;

/// <summary>
/// Builds an <see cref="IdentityClient"/> wired to a captured <see cref="FakeHttpMessageHandler"/>
/// so each endpoint test can assert request URI / method / body and stub a JSON response.
/// </summary>
internal sealed class IdentityClientFixture
{
    public FakeHttpMessageHandler Handler { get; }
    public IdentityClient Client { get; }

    public IdentityClientFixture(Func<HttpRequestMessage, HttpResponseMessage> responder)
    {
        Handler = new FakeHttpMessageHandler(req => Task.FromResult(responder(req)));
        var http = new HttpClient(Handler) { BaseAddress = new Uri("https://identity.test/") };
        var opts = Options.Create(new IdentityClientOptions { BaseUrl = new Uri("https://identity.test/") });
        Client = new IdentityClient(http, opts);
    }

    public IdentityClientFixture(HttpStatusCode status, string? body = null, string mediaType = "application/json")
        : this(_ => FakeHttpMessageHandler.BuildResponse(status, body, mediaType))
    {
    }

    public static string Json<T>(T value) => JsonSerializer.Serialize(value, new JsonSerializerOptions(JsonSerializerDefaults.Web)
    {
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    });
}
