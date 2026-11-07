using System.Net;
using System.Text;

namespace redb.Identity.Client.Tests.TestKit;

/// <summary>
/// In-memory <see cref="HttpMessageHandler"/> driven by a queued response builder.
/// Records all incoming requests so tests can assert path / method / body / headers.
/// </summary>
internal sealed class FakeHttpMessageHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, Task<HttpResponseMessage>> _responder;

    public List<HttpRequestMessage> Requests { get; } = new();
    public List<string?> RequestBodies { get; } = new();

    public FakeHttpMessageHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> responder)
    {
        _responder = responder;
    }

    public FakeHttpMessageHandler(HttpStatusCode status, string? body = null, string mediaType = "application/json")
        : this(_ => Task.FromResult(BuildResponse(status, body, mediaType)))
    {
    }

    public static HttpResponseMessage BuildResponse(HttpStatusCode status, string? body, string mediaType = "application/json")
    {
        var resp = new HttpResponseMessage(status);
        if (body is not null)
        {
            resp.Content = new StringContent(body, Encoding.UTF8, mediaType);
        }
        return resp;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Requests.Add(request);
        if (request.Content is not null)
        {
            RequestBodies.Add(await request.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false));
        }
        else
        {
            RequestBodies.Add(null);
        }
        return await _responder(request).ConfigureAwait(false);
    }
}
