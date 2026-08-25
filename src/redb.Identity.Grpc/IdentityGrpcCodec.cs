using System.Globalization;
using Google.Protobuf;
using Google.Protobuf.Reflection;
using Google.Protobuf.WellKnownTypes;

namespace redb.Identity.Grpc;

/// <summary>
/// Translates between the published <c>identity.v1</c> protobuf contract and the shape the
/// <c>direct-vm://identity-*</c> boundary speaks.
/// <para>
/// The boundary takes a <c>Dictionary&lt;string, string&gt;</c> of request parameters and answers with a
/// <c>Dictionary&lt;string, object?&gt;</c> — a typed object, never encoded bytes, which is what lets a
/// facade choose its own wire format (guarded by <c>TransportBoundaryTests</c> in Core).
/// </para>
/// <para>
/// Mapping is driven by protobuf reflection rather than a hand-written table per message: proto field
/// names are snake_case and already equal the OAuth parameter names (<c>grant_type</c>,
/// <c>client_id</c>, …), so the descriptor <i>is</i> the mapping. Add a field to the contract and it
/// starts flowing without touching this file.
/// </para>
/// </summary>
internal static class IdentityGrpcCodec
{
    // ── request: proto → parameters ──────────────────────────

    /// <summary>
    /// Flattens a request message into the parameter dictionary the boundary expects. Empty fields are
    /// omitted: OAuth distinguishes «absent» from «present and empty», and sending the latter would make
    /// the server reject requests it should accept.
    /// </summary>
    public static Dictionary<string, string> ToParameters(IMessage request)
    {
        ArgumentNullException.ThrowIfNull(request);

        var parameters = new Dictionary<string, string>(StringComparer.Ordinal);

        foreach (var field in request.Descriptor.Fields.InFieldNumberOrder())
        {
            var value = field.Accessor.GetValue(request);

            if (field.IsMap)
            {
                // The extension bag is merged flat — an extension parameter is a parameter.
                if (value is System.Collections.IDictionary map)
                {
                    foreach (System.Collections.DictionaryEntry entry in map)
                    {
                        var key = entry.Key?.ToString();
                        if (!string.IsNullOrEmpty(key) && entry.Value is not null)
                            parameters[key!] = entry.Value.ToString() ?? string.Empty;
                    }
                }
                continue;
            }

            var text = Stringify(value);
            if (!string.IsNullOrEmpty(text))
                parameters[field.Name] = text!;
        }

        return parameters;
    }

    private static string? Stringify(object? value) => value switch
    {
        null => null,
        string s => s,
        bool b => b ? "true" : "false",
        IFormattable f => f.ToString(null, CultureInfo.InvariantCulture),
        _ => value.ToString(),
    };

    // ── response: parameters → proto ─────────────────────────

    /// <summary>
    /// Populates a response message from the boundary's answer. Named fields are filled by proto field
    /// name; everything left over goes into <paramref name="overflowField"/> (a
    /// <c>google.protobuf.Struct</c>), because userinfo claims and introspection extensions are open sets
    /// and dropping them silently would lose data the caller asked for.
    /// </summary>
    public static void Populate(IMessage response, IDictionary<string, object?> source, string overflowField)
    {
        ArgumentNullException.ThrowIfNull(response);
        ArgumentNullException.ThrowIfNull(source);

        var consumed = new HashSet<string>(StringComparer.Ordinal);

        foreach (var field in response.Descriptor.Fields.InFieldNumberOrder())
        {
            if (field.Name == overflowField) continue;
            if (!TryGet(source, field.Name, out var raw) || raw is null) continue;

            if (TrySet(response, field, raw))
                consumed.Add(field.Name);
        }

        var overflow = response.Descriptor.FindFieldByName(overflowField);
        if (overflow is null) return;

        var rest = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (var (key, value) in source)
        {
            if (consumed.Contains(key)) continue;
            rest[key] = value;
        }

        if (rest.Count > 0)
            overflow.Accessor.SetValue(response, ToStruct(rest));
    }

    /// <summary>
    /// Fills a message whose whole payload is one <c>Struct</c> — discovery and JWKS, where the document
    /// is passed through verbatim because its contents are the server's business, not ours.
    /// </summary>
    public static void PopulateDocument(IMessage response, IDictionary<string, object?> source, string field)
    {
        ArgumentNullException.ThrowIfNull(response);
        ArgumentNullException.ThrowIfNull(source);

        var descriptor = response.Descriptor.FindFieldByName(field)
                         ?? throw new InvalidOperationException(
                             $"{response.Descriptor.Name} has no field '{field}'.");

        descriptor.Accessor.SetValue(response, ToStruct(source));
    }

    private static bool TryGet(IDictionary<string, object?> source, string key, out object? value)
    {
        if (source.TryGetValue(key, out value)) return true;

        // Tolerate a case difference from a hand-written processor without matching loosely enough to
        // pick up an unrelated key.
        foreach (var (candidate, candidateValue) in source)
        {
            if (string.Equals(candidate, key, StringComparison.OrdinalIgnoreCase))
            {
                value = candidateValue;
                return true;
            }
        }

        value = null;
        return false;
    }

    private static bool TrySet(IMessage message, FieldDescriptor field, object raw)
    {
        try
        {
            if (field.IsRepeated)
            {
                if (field.Accessor.GetValue(message) is not System.Collections.IList list) return false;

                foreach (var item in Enumerate(raw))
                {
                    var converted = Convert(field, item);
                    if (converted is not null) list.Add(converted);
                }
                return true;
            }

            var value = Convert(field, raw);
            if (value is null) return false;

            field.Accessor.SetValue(message, value);
            return true;
        }
        catch (Exception ex) when (ex is InvalidCastException or FormatException or OverflowException)
        {
            // A value the contract cannot hold is not a reason to fail the call — it falls through to the
            // overflow Struct, where the caller can still see it.
            return false;
        }
    }

    private static IEnumerable<object?> Enumerate(object raw)
    {
        if (raw is string s) { yield return s; yield break; }
        if (raw is System.Collections.IEnumerable list)
        {
            foreach (var item in list) yield return item;
            yield break;
        }
        yield return raw;
    }

    private static object? Convert(FieldDescriptor field, object? raw)
    {
        if (raw is null) return null;

        return field.FieldType switch
        {
            FieldType.String => raw as string ?? Stringify(raw),
            FieldType.Bool => raw switch
            {
                bool b => b,
                string s => bool.Parse(s),
                _ => System.Convert.ToBoolean(raw, CultureInfo.InvariantCulture),
            },
            FieldType.Int64 or FieldType.SInt64 or FieldType.SFixed64 =>
                raw is long l ? l : System.Convert.ToInt64(raw, CultureInfo.InvariantCulture),
            FieldType.Int32 or FieldType.SInt32 or FieldType.SFixed32 =>
                raw is int i ? i : System.Convert.ToInt32(raw, CultureInfo.InvariantCulture),
            FieldType.Double => raw is double d ? d : System.Convert.ToDouble(raw, CultureInfo.InvariantCulture),
            FieldType.Float => raw is float f ? f : System.Convert.ToSingle(raw, CultureInfo.InvariantCulture),
            _ => null,
        };
    }

    // ── Struct conversion ────────────────────────────────────

    /// <summary>Converts the boundary's loosely typed answer into a <c>google.protobuf.Struct</c>.</summary>
    public static Struct ToStruct(IDictionary<string, object?> source)
    {
        var result = new Struct();
        foreach (var (key, value) in source)
            result.Fields[key] = ToValue(value);
        return result;
    }

    private static Value ToValue(object? value) => value switch
    {
        null => Value.ForNull(),
        string s => Value.ForString(s),
        bool b => Value.ForBool(b),
        long l => Value.ForNumber(l),
        int i => Value.ForNumber(i),
        double d => Value.ForNumber(d),
        float f => Value.ForNumber(f),
        decimal m => Value.ForNumber((double)m),
        IDictionary<string, object?> nested => Value.ForStruct(ToStruct(nested)),
        System.Collections.IEnumerable list => Value.ForList(
            list.Cast<object?>().Select(ToValue).ToArray()),
        _ => Value.ForString(value.ToString() ?? string.Empty),
    };
}
