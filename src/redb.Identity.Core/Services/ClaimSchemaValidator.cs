using redb.Core;
using redb.Core.Query;
using redb.Identity.Core.Models;

namespace redb.Identity.Core.Services;

/// <summary>
/// S2 — shared validator for global <see cref="ClaimDefinitionProps"/>.
/// Used by both the admin user-management path
/// (<c>UserManagementProcessor.Create/Update</c>) and the public
/// self-service registration path (<c>AccountRegisterProcessor</c>) so the
/// schema is enforced uniformly regardless of how the user enters the
/// system.
///
/// <para>
/// Per-application definitions are NOT enforced here — those gate token
/// issuance time (a user may exist without ever signing into the app whose
/// schema requires them).
/// </para>
/// </summary>
public static class ClaimSchemaValidator
{
    /// <summary>
    /// Validate <paramref name="incoming"/> (may be null on create) against
    /// every global <see cref="ClaimDefinitionProps"/>. Returns a tuple:
    /// <list type="bullet">
    ///   <item><c>normalized</c> — the validated dict with defaults applied;
    ///         null on validation failure.</item>
    ///   <item><c>errorMessage</c> — null on success, error string on failure.</item>
    /// </list>
    /// </summary>
    public static async Task<(Dictionary<string, string>? normalized, string? errorMessage)>
        EnforceGlobalAsync(IRedbService redb, Dictionary<string, string>? incoming, CancellationToken ct = default)
    {
        var definitions = await redb.Query<ClaimDefinitionProps>()
            .Where(p => p.Scope == "global")
            .ToListAsync()
            .ConfigureAwait(false);

        var result = new Dictionary<string, string>(incoming ?? new(), StringComparer.Ordinal);

        // Null-guard for the Query result — production providers always return
        // a (possibly empty) list, but unit-test substitutes may not configure
        // the schema-defs query and return null. No-op when empty / null.
        if (definitions is null) return (result, null);

        foreach (var def in definitions)
        {
            var name = def.Props.ClaimName;
            var has = result.TryGetValue(name, out var value);

            if (!has || string.IsNullOrEmpty(value))
            {
                if (def.Props.Required)
                {
                    if (!string.IsNullOrEmpty(def.Props.DefaultValue))
                    {
                        result[name] = def.Props.DefaultValue;
                        continue;
                    }
                    return (null, $"Claim '{name}' is required");
                }
                // Optional + missing — leave unset.
                continue;
            }

            switch ((def.Props.Type ?? "string").ToLowerInvariant())
            {
                case "int":
                    if (!int.TryParse(value, out _))
                        return (null, $"Claim '{name}' must be an int");
                    break;
                case "long":
                    if (!long.TryParse(value, out _))
                        return (null, $"Claim '{name}' must be a long");
                    break;
                case "bool":
                    if (!bool.TryParse(value, out _))
                        return (null, $"Claim '{name}' must be 'true' or 'false'");
                    break;
                case "datetime":
                    if (!DateTimeOffset.TryParse(value, out _))
                        return (null, $"Claim '{name}' must be an ISO-8601 datetime");
                    break;
                case "url":
                    if (!Uri.TryCreate(value, UriKind.Absolute, out _))
                        return (null, $"Claim '{name}' must be an absolute URL");
                    break;
                case "email":
                    if (!value.Contains('@') || value.Length < 3)
                        return (null, $"Claim '{name}' must be a valid email");
                    break;
                case "string":
                default:
                    if (!string.IsNullOrEmpty(def.Props.ValidationPattern))
                    {
                        try
                        {
                            if (!System.Text.RegularExpressions.Regex.IsMatch(value, def.Props.ValidationPattern))
                                return (null, $"Claim '{name}' does not match the required pattern");
                        }
                        catch (Exception)
                        {
                            // Malformed pattern — treat as no constraint to avoid blocking
                            // operator mutations behind a definition row they can't fix.
                        }
                    }
                    break;
            }
        }

        return (result, null);
    }
}
