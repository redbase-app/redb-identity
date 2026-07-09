using System.Collections.Immutable;
using redb.Identity.Contracts.Cors;

namespace redb.Identity.Http.Cors;

/// <summary>
/// Composes a base <see cref="IRegisteredClientOriginRegistry"/> (which derives origins from
/// registered OAuth clients) with an additional set of allowed origins supplied as a CSV
/// string from transport options. The CSV callback is evaluated on every read so config
/// hot-reload is picked up without restarting.
/// <para>
/// Lives in the HTTP facade because the additional-origins concept is a transport-level
/// fallback (dev/staging cases where browser apps are not yet registered as OAuth clients).
/// </para>
/// </summary>
internal sealed class AdditionalOriginsRegistry : IRegisteredClientOriginRegistry
{
    private readonly IRegisteredClientOriginRegistry _inner;
    private readonly Func<string?> _additionalOriginsCsv;

    public AdditionalOriginsRegistry(
        IRegisteredClientOriginRegistry inner,
        Func<string?> additionalOriginsCsv)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _additionalOriginsCsv = additionalOriginsCsv ?? throw new ArgumentNullException(nameof(additionalOriginsCsv));
    }

    public async ValueTask<bool> IsAllowedAsync(string? origin, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(origin)) return false;
        var snapshot = await GetAllowedOriginsAsync(ct).ConfigureAwait(false);
        return snapshot.Contains(origin);
    }

    public async ValueTask<ImmutableHashSet<string>> GetAllowedOriginsAsync(CancellationToken ct = default)
    {
        var baseSet = await _inner.GetAllowedOriginsAsync(ct).ConfigureAwait(false);
        var csv = _additionalOriginsCsv();
        if (string.IsNullOrEmpty(csv)) return baseSet;

        var builder = baseSet.ToBuilder();
        foreach (var raw in csv.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            if (!Uri.TryCreate(raw, UriKind.Absolute, out var parsed)) continue;
            if (string.IsNullOrEmpty(parsed.Scheme) || string.IsNullOrEmpty(parsed.Host)) continue;
            builder.Add(parsed.GetLeftPart(UriPartial.Authority).ToLowerInvariant());
        }
        return builder.ToImmutable();
    }

    public void Invalidate() => _inner.Invalidate();
}
