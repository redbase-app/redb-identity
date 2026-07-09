using System.Net.Http.Headers;

namespace redb.Identity.Client.Auth;

/// <summary>
/// <see cref="DelegatingHandler"/> that adds <c>Authorization: Bearer &lt;token&gt;</c>
/// to outgoing requests. If the configured <see cref="IAccessTokenProvider"/> returns
/// <c>null</c> or an empty token, no header is added (anonymous flow allowed).
/// </summary>
public sealed class BearerTokenHandler : DelegatingHandler
{
    private readonly IAccessTokenProvider _tokenProvider;

    public BearerTokenHandler(IAccessTokenProvider tokenProvider)
    {
        _tokenProvider = tokenProvider;
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var token = await _tokenProvider.GetAccessTokenAsync(cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrEmpty(token))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }
        return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }
}
