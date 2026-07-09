using System.Text.Json;
using Microsoft.Extensions.Logging;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Models;
using redb.Route.Abstractions;
using redb.Route.RedbCore.Extensions;

namespace redb.Identity.Core.Routes.Processors;

// Internal property keys shared between the PRE / POST processors.
internal static class IdempotencyProperties
{
    public const string Name = "__idempotency:name";
    public const string Scope = "__idempotency:scope";
    public const string Method = "__idempotency:method";
    public const string Operation = "__idempotency:operation";
    public const string Caller = "__idempotency:caller";
    public const string Key = "__idempotency:key";
    public const string CacheHit = "idempotency:cache-hit";
}

/// <summary>
/// E2 — pre-step that consults the idempotency cache.
/// <list type="bullet">
///   <item><description>If no <c>Idempotency-Key</c> header is present (or it is too long),
///   the processor is a no-op.</description></item>
///   <item><description>On a cache hit (matching record whose <c>date_complete</c> is in the
///   future), the cached body and HTTP status are written to <c>exchange.Out</c> and the
///   route is short-circuited via <see cref="IExchange.Stop"/> — downstream business
///   processors and <c>WireTap</c> do NOT run, so no audit event is emitted for the
///   replayed response (intended: the original event was emitted on first execution).</description></item>
///   <item><description>On a cache miss, request metadata is stashed in
///   <see cref="IExchange.Properties"/> for the paired <see cref="IdempotencyCaptureProcessor"/>
///   to consume after the business step completes.</description></item>
/// </list>
/// </summary>
internal sealed class IdempotencyProcessor : IProcessor
{
    private readonly IRouteContext _context;
    private readonly string? _redbName;
    private readonly string _scope;
    private readonly IdempotencyOptions _options;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger? _logger;

    public IdempotencyProcessor(
        IRouteContext context,
        string? redbName,
        string scope,
        IdempotencyOptions options,
        TimeProvider? timeProvider = null,
        ILogger? logger = null)
    {
        _context = context;
        _redbName = redbName;
        _scope = scope;
        _options = options;
        _timeProvider = timeProvider ?? TimeProvider.System;
        _logger = logger;
    }

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        if (!_options.Enabled) return;

        // Headers dictionary is OrdinalIgnoreCase — single lookup is enough.
        var key = exchange.In.GetHeader<string>("Idempotency-Key");
        if (string.IsNullOrWhiteSpace(key)) return;
        if (key.Length > _options.MaxKeyLength) return;

        var operation = exchange.In.GetHeader<string>("operation") ?? "default";
        var method = exchange.In.GetHeader<string>("redbHttp.Method") ?? string.Empty;
        var caller = ResolveCaller(exchange);
        var name = ComposeName(_scope, operation, caller, key);

        // Stash for the capture processor BEFORE we attempt the lookup so that a transient
        // read failure still allows the business step to run (capture will then write a
        // fresh record on completion).
        exchange.Properties[IdempotencyProperties.Name] = name;
        exchange.Properties[IdempotencyProperties.Scope] = _scope;
        exchange.Properties[IdempotencyProperties.Method] = method;
        exchange.Properties[IdempotencyProperties.Operation] = operation;
        exchange.Properties[IdempotencyProperties.Caller] = caller;
        exchange.Properties[IdempotencyProperties.Key] = key;

        try
        {
            var redb = _context.GetRedbService(_redbName, exchange);
            var now = _timeProvider.GetUtcNow();

            // Indexed lookup on _objects._name (IX__objects__name).
            var matches = await redb.Query<IdempotencyRecordProps>()
                .WhereRedb(o => o.Name == name)
                .ToListAsync()
                .ConfigureAwait(false);

            // Defensive equality check on Props guards against any name collision from a
            // foreign scheme that happens to share the composite name format.
            var hit = matches.FirstOrDefault(m =>
                m.Props.Scope == _scope &&
                m.Props.Operation == operation &&
                m.Props.CallerSubject == caller &&
                m.Props.IdempotencyKey == key &&
                m.date_complete is { } dc && dc > now);

            if (hit is null) return;

            exchange.Out ??= new redb.Route.Core.Message();
            exchange.Out.Body = DeserializeBody(hit.Props.ResponseBody);
            exchange.Out.Headers["redbHttp.ResponseCode"] = hit.Props.StatusCode;
            exchange.Out.Headers["Idempotency-Replayed"] = "true";
            exchange.Properties[IdempotencyProperties.CacheHit] = true;

            _logger?.LogDebug(
                "Idempotency cache hit for scope={Scope} operation={Operation} caller={Caller}.",
                _scope, operation, caller);

            exchange.Stop();
        }
        catch (Exception ex)
        {
            // Cache lookup failures must NOT prevent the business operation from running.
            // Worst case the client sees the response twice — same as today.
            _logger?.LogWarning(ex, "Idempotency lookup failed; proceeding without cache.");
        }
    }

    internal static string ComposeName(string scope, string operation, string caller, string key)
        => $"idem:{scope}:{operation}:{caller}:{key}";

    internal static string ResolveCaller(IExchange exchange)
    {
        if (exchange.Properties.TryGetValue("identity:management-subject", out var s)
            && s is string sub && !string.IsNullOrEmpty(sub))
            return sub;
        return "anon";
    }

    internal static object? DeserializeBody(string? json)
    {
        if (string.IsNullOrEmpty(json)) return null;
        try
        {
            // JsonElement round-trips identically through System.Text.Json on the next write.
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.Clone();
        }
        catch
        {
            return json;
        }
    }
}

/// <summary>
/// E2 — post-step that captures the response into the idempotency cache when the paired
/// <see cref="IdempotencyProcessor"/> stashed metadata for a cache miss.
/// <para>
/// Runs inside the same redb transaction as the business step, so a failed mutation that
/// rolls back also rolls back the cache write — clients can safely retry a failed request
/// without being permanently stuck on the failure response.
/// </para>
/// </summary>
internal sealed class IdempotencyCaptureProcessor : IProcessor
{
    private readonly IRouteContext _context;
    private readonly string? _redbName;
    private readonly IdempotencyOptions _options;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger? _logger;

    public IdempotencyCaptureProcessor(
        IRouteContext context,
        string? redbName,
        IdempotencyOptions options,
        TimeProvider? timeProvider = null,
        ILogger? logger = null)
    {
        _context = context;
        _redbName = redbName;
        _options = options;
        _timeProvider = timeProvider ?? TimeProvider.System;
        _logger = logger;
    }

    public async Task Process(IExchange exchange, CancellationToken ct = default)
    {
        if (!_options.Enabled) return;

        if (!exchange.Properties.TryGetValue(IdempotencyProperties.Name, out var nameObj)
            || nameObj is not string name) return;
        if (exchange.Properties.TryGetValue(IdempotencyProperties.CacheHit, out var hit)
            && hit is true) return;

        // Identity convention follows Camel canon: the response is exchange.Out ?? exchange.In.
        // PipelineProcessor merges business.Out into In before invoking this terminal step,
        // so In.Body holds whatever the business processor wrote. Callers downstream must also
        // read via `Out ?? In` — we do NOT synthesise Out here (that would be redundant: the
        // outer PipelineProcessor would re-merge it back into In on the next step anyway).
        var responseSource = exchange.Out ?? exchange.In;
        if (responseSource?.Body is null) return;

        // Skip caching error responses (4xx/5xx). RFC-style idempotency only protects
        // successful state changes; a transient 5xx must be retriable.
        var status = ResolveStatus(exchange);
        if (status >= 400) return;

        var method = exchange.Properties.TryGetValue(IdempotencyProperties.Method, out var m) ? m as string ?? string.Empty : string.Empty;
        var operation = exchange.Properties.TryGetValue(IdempotencyProperties.Operation, out var o) ? o as string ?? string.Empty : string.Empty;
        var caller = exchange.Properties.TryGetValue(IdempotencyProperties.Caller, out var c) ? c as string ?? "anon" : "anon";
        var key = exchange.Properties.TryGetValue(IdempotencyProperties.Key, out var k) ? k as string ?? string.Empty : string.Empty;

        try
        {
            var redb = _context.GetRedbService(_redbName, exchange);
            var now = _timeProvider.GetUtcNow();

            // Re-check (TOCTOU): a concurrent request with the same key may have already
            // stored a record between the PRE-lookup and now. Keep the first writer's record
            // to give callers stable replay semantics.
            var existing = await redb.Query<IdempotencyRecordProps>()
                .WhereRedb(obj => obj.Name == name)
                .ToListAsync()
                .ConfigureAwait(false);

            if (existing.Any(e =>
                e.Props.IdempotencyKey == key &&
                e.Props.CallerSubject == caller &&
                e.date_complete is { } dc && dc > now))
            {
                return;
            }

            var scope = exchange.Properties.TryGetValue(IdempotencyProperties.Scope, out var sc) ? sc as string : null;

            var record = new RedbObject<IdempotencyRecordProps>
            {
                name = name,
                date_complete = now.Add(_options.Ttl),
                Props = new IdempotencyRecordProps
                {
                    Method = method,
                    Scope = scope,
                    Operation = operation,
                    CallerSubject = caller,
                    IdempotencyKey = key,
                    StatusCode = status,
                    ResponseBody = SerializeBody(responseSource.Body),
                }
            };

            await redb.SaveAsync(record).ConfigureAwait(false);
        }
        catch (Exception ex) when (IdentityProcessorHelpers.IsUniqueViolation(ex))
        {
            // Concurrent capture won the race — the partial unique index on
            // _objects(_name) WHERE _id_scheme = IdempotencyRecordProps rejected this
            // insert. The other writer already persisted the authoritative response,
            // so silently drop this attempt: the client still gets its 2xx from the
            // business step, and future retries will hit the cached copy.
            _logger?.LogDebug(
                "Idempotency capture race — another writer already stored name={Name}.", name);
        }
        catch (Exception ex)
        {
            // Cache write failure must NOT fail the user's request — they already got the
            // real response from the business step. Log and move on; next retry simply won't
            // be deduplicated.
            _logger?.LogWarning(ex, "Idempotency capture failed for name={Name}.", name);
        }
    }

    private static int ResolveStatus(IExchange exchange)
    {
        var src = exchange.Out ?? exchange.In;
        if (src is null) return 200;
        if (src.Headers.TryGetValue("redbHttp.ResponseCode", out var rc))
        {
            if (rc is int i) return i;
            if (rc is string s && int.TryParse(s, out var p)) return p;
        }
        return 200;
    }

    private static string? SerializeBody(object? body)
    {
        if (body is null) return null;
        try { return JsonSerializer.Serialize(body); }
        catch { return null; }
    }

}
