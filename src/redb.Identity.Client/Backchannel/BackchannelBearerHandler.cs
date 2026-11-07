using System.Net.Http.Headers;

namespace redb.Identity.Client.Backchannel;

/// <summary>
/// <see cref="DelegatingHandler"/> that attaches <c>Authorization: Bearer &lt;token&gt;</c>
/// using <see cref="BackchannelTokenProvider"/>. Separate from
/// <c>redb.Identity.Client.Auth.BearerTokenHandler</c> so backchannel and user-context
/// clients can coexist in the same DI container.
/// </summary>
internal sealed class BackchannelBearerHandler : DelegatingHandler
{
    private readonly BackchannelTokenProvider _tokens;

    public BackchannelBearerHandler(BackchannelTokenProvider tokens)
    {
        _tokens = tokens;
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var token = await _tokens.GetAccessTokenAsync(cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrEmpty(token))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }
        return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }
}
