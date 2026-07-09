using System.Net.Http.Json;
using System.Text.Json;

namespace redb.Identity.Client.Internal;

/// <summary>
/// Helpers used by partial methods to either throw <see cref="ApiException"/> on
/// non-success responses (parsing RFC 7807 problem details when present) or
/// deserialize a JSON success body.
/// </summary>
internal static class HttpResponseExtensions
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = true,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    public static async Task EnsureSuccessOrThrowAsync(
        this HttpResponseMessage response, CancellationToken ct = default)
    {
        if (response.IsSuccessStatusCode) return;

        ProblemDetails? pd = null;
        string? raw = null;
        try
        {
            raw = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            var mediaType = response.Content.Headers.ContentType?.MediaType;
            if (!string.IsNullOrWhiteSpace(raw)
                && (mediaType == "application/problem+json" || mediaType == "application/json"))
            {
                pd = JsonSerializer.Deserialize<ProblemDetails>(raw, Json);
            }
        }
        catch
        {
            // Body unreadable / not JSON — fall through to bare exception.
        }

        var msg = pd?.Title ?? pd?.Detail
            ?? (string.IsNullOrWhiteSpace(raw)
                ? $"HTTP {(int)response.StatusCode} {response.ReasonPhrase}"
                : $"HTTP {(int)response.StatusCode} {response.ReasonPhrase}: {Truncate(raw, 400)}");

        throw new ApiException(response.StatusCode, msg, pd, raw);
    }

    private static string Truncate(string s, int max)
        => s.Length <= max ? s : s[..max] + "…";

    public static async Task<T> ReadJsonAsync<T>(
        this HttpResponseMessage response, CancellationToken ct = default)
    {
        await response.EnsureSuccessOrThrowAsync(ct).ConfigureAwait(false);
        try
        {
            var result = await response.Content.ReadFromJsonAsync<T>(Json, ct).ConfigureAwait(false);
            return result ?? throw new ApiException(
                response.StatusCode, "Empty response body", null, null);
        }
        catch (JsonException ex)
        {
            throw new ApiException(
                response.StatusCode,
                $"Failed to deserialize response body as {typeof(T).Name}: {ex.Message}",
                null, null, ex);
        }
    }
}
