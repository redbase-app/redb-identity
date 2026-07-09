using System.Text.Json;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using redb.Route.Abstractions;

namespace redb.Identity.Core.OpenIddict;

/// <summary>
/// Internal helpers for bridging <see cref="IExchange"/> and <see cref="OpenIddictServerTransaction"/>.
/// </summary>
internal static class RedbRouteOpenIddictServerHelpers
{
    internal const string ExchangePropertyKey = "redb.route.exchange";

    /// <summary>
    /// Retrieves the <see cref="IExchange"/> stored in the transaction properties.
    /// Returns <c>null</c> if the current request is not handled by the redb.Route adapter.
    /// </summary>
    internal static IExchange? GetRouteExchange(this OpenIddictServerTransaction transaction)
    {
        if (transaction.Properties.TryGetValue(ExchangePropertyKey, out var value))
            return value as IExchange;
        return null;
    }

    /// <summary>
    /// Creates an <see cref="OpenIddictRequest"/> from the exchange body.
    /// Supports <see cref="OpenIddictRequest"/>, <c>IDictionary&lt;string, string&gt;</c>,
    /// <c>IDictionary&lt;string, object?&gt;</c>, and form-urlencoded strings.
    /// </summary>
    internal static OpenIddictRequest CreateRequestFromExchange(IExchange exchange)
    {
        switch (exchange.In.Body)
        {
            case OpenIddictRequest existing:
                return existing;

            case IDictionary<string, string> form:
            {
                var request = new OpenIddictRequest();
                foreach (var (key, value) in form)
                    request.SetParameter(key, new OpenIddictParameter(value));
                return request;
            }

            case IDictionary<string, object?> dict:
            {
                var request = new OpenIddictRequest();
                foreach (var (key, value) in dict)
                {
                    if (value is string s)
                        request.SetParameter(key, new OpenIddictParameter(s));
                    else if (value is string[] arr)
                        request.SetParameter(key, new OpenIddictParameter(string.Join(" ", arr)));
                    else if (value != null)
                        request.SetParameter(key, new OpenIddictParameter(value.ToString()));
                }
                return request;
            }

            case string text when !string.IsNullOrEmpty(text):
            {
                var request = new OpenIddictRequest();
                foreach (var segment in text.Split('&', StringSplitOptions.RemoveEmptyEntries))
                {
                    var eqIdx = segment.IndexOf('=');
                    if (eqIdx > 0)
                    {
                        var k = Uri.UnescapeDataString(segment[..eqIdx]);
                        var v = Uri.UnescapeDataString(segment[(eqIdx + 1)..]);
                        request.SetParameter(k, new OpenIddictParameter(v));
                    }
                }
                return request;
            }

            default:
                return new OpenIddictRequest();
        }
    }

    /// <summary>
    /// Writes an <see cref="OpenIddictResponse"/> to the exchange Out message.
    /// Creates the Out message if it doesn't exist (sets InOut pattern).
    /// </summary>
    internal static void WriteResponseToExchange(IExchange exchange, OpenIddictResponse response)
    {
        if (exchange.Out == null)
        {
            exchange.Pattern = ExchangePattern.InOut;
            exchange.Out = exchange.In.Clone();
            exchange.Out.Body = null;
            exchange.Out.Headers.Clear();
        }

        var result = new Dictionary<string, object?>();
        foreach (var param in response.GetParameters())
        {
            result[param.Key] = NormalizeParameterValue(param.Value);
        }

        exchange.Out.Body = result;
        exchange.Out.ContentType = "application/json";
    }

    /// <summary>
    /// Normalizes an <see cref="OpenIddictParameter"/> to a CLR value suitable for
    /// <see cref="System.Text.Json.JsonSerializer"/>. Arrays become <c>List&lt;object?&gt;</c>,
    /// objects become <c>Dictionary&lt;string, object?&gt;</c>, primitives are unwrapped.
    /// </summary>
    private static object? NormalizeParameterValue(OpenIddictParameter parameter)
    {
        var value = parameter.Value;

        if (value is null)
            return null;

        if (value is JsonElement element)
        {
            return NormalizeJsonElement(element);
        }

        return value;
    }

    private static object? NormalizeJsonElement(JsonElement element)
    {
        return element.ValueKind switch
        {
            JsonValueKind.String => element.GetString(),
            JsonValueKind.Number when element.TryGetInt64(out var l) => l,
            JsonValueKind.Number => element.GetDouble(),
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.Null => null,
            JsonValueKind.Array => NormalizeJsonArray(element),
            JsonValueKind.Object => NormalizeJsonObject(element),
            _ => element.GetRawText()
        };
    }

    private static List<object?> NormalizeJsonArray(JsonElement element)
    {
        var list = new List<object?>();
        foreach (var item in element.EnumerateArray())
        {
            list.Add(NormalizeJsonElement(item));
        }
        return list;
    }

    private static Dictionary<string, object?> NormalizeJsonObject(JsonElement element)
    {
        var dict = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (var prop in element.EnumerateObject())
        {
            dict[prop.Name] = NormalizeJsonElement(prop.Value);
        }
        return dict;
    }
}
