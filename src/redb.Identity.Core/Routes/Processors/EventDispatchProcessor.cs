using System.Reflection;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using redb.Identity.Contracts.Events;
using redb.Identity.Core.Configuration;
using redb.Route.Abstractions;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// Receives WireTap copies from mutating endpoints.
/// Reads event properties set by upstream processors, creates typed <see cref="IdentityEvent"/>,
/// applies the audit filter, and prepares headers for downstream audit targets (SQL param binding, etc.).
/// </summary>
internal sealed class EventDispatchProcessor : IProcessor
{
    private readonly ILogger _logger;
    private readonly HashSet<string>? _allowedEventTypes;
    private readonly TimeProvider _timeProvider;

    public EventDispatchProcessor(ILogger logger, IdentityAuditOptions? auditOptions = null, TimeProvider? timeProvider = null)
    {
        _logger = logger;
        _timeProvider = timeProvider ?? TimeProvider.System;

        if (auditOptions is { Enabled: true, Filter: not ("*" or "" or null) })
        {
            _allowedEventTypes = new HashSet<string>(
                auditOptions.Filter.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
                StringComparer.OrdinalIgnoreCase);
        }
    }

    public Task Process(IExchange exchange, CancellationToken ct = default)
    {
        var eventType = exchange.GetProperty<string>("identity-event-type");
        if (string.IsNullOrEmpty(eventType))
            return Task.CompletedTask;

        // Apply filter — skip events not in whitelist
        if (_allowedEventTypes is not null && !_allowedEventTypes.Contains(eventType))
            return Task.CompletedTask;

        var detailsDict = exchange.GetProperty<object>("identity-event-data") switch
        {
            Dictionary<string, object?> d => d,
            null => null,
            { } obj => obj.GetType().GetProperties(BindingFlags.Public | BindingFlags.Instance)
                .ToDictionary(p => p.Name, p => (object?)p.GetValue(obj))
        };

        var identityEvent = new IdentityEvent
        {
            EventType = eventType,
            Timestamp = _timeProvider.GetUtcNow(),
            ClientId = exchange.In.GetHeader<string>("client_id"),
            // user_id resolution order: explicit header (top priority) →
            // UserId field on the identity-event-data payload (the common
            // shape — most emitters stamp it). Keeps per-user audit filters
            // hitting the indexed user_id column instead of falling back to
            // the wider login OR-clause on every query.
            UserId = exchange.In.GetHeader<string>("user_id")
                ?? ExtractStringFromDetails(detailsDict, "UserId"),
            IpAddress = exchange.In.GetHeader<string>("ip_address"),
            UserAgent = exchange.In.GetHeader<string>("user_agent"),
            Details = detailsDict
        };

        _logger.LogDebug("Identity event: {EventType}", eventType);

        // Prepare exchange for downstream audit targets.
        // Body carries the typed IdentityEvent + ContentType="application/json" — the OAuth/OIDC
        // domain is RFC-defined in JSON shape, but each downstream transport (Kafka/Elasticsearch/
        // RabbitMQ/log) is responsible for its own wire encoding via IDataFormatRegistry, or the
        // route DSL inserts an explicit .Marshal() step at the boundary. Core MUST NOT pre-serialise
        // to string/bytes here: that would lock every sink to JSON and break proto/avro/CBOR sinks.
        exchange.Out ??= new redb.Route.Core.Message();
        exchange.Out.Body = identityEvent;
        exchange.Out.ContentType = "application/json";
        exchange.Out.Headers["event-type"] = eventType;

        // Headers for SQL param binding (auto-bind by parameter name from exchange.In.Headers)
        exchange.Out.Headers["event_id"] = Guid.Parse(identityEvent.EventId);
        exchange.Out.Headers["event_type"] = identityEvent.EventType;
        exchange.Out.Headers["timestamp"] = identityEvent.Timestamp;
        exchange.Out.Headers["user_id"] = identityEvent.UserId ?? (object)DBNull.Value;
        exchange.Out.Headers["client_id"] = identityEvent.ClientId ?? (object)DBNull.Value;
        exchange.Out.Headers["ip_address"] = identityEvent.IpAddress ?? (object)DBNull.Value;
        exchange.Out.Headers["user_agent"] = identityEvent.UserAgent ?? (object)DBNull.Value;
        // Typed details — the PROPS sink owns its own persistence encoding (DetailsJson column).
        // Wire-encoding for external transports happens at the boundary via .Marshal(...) in the DSL.
        // The header carries the JSON string only because it doubles as an SQL bind parameter for
        // jsonb columns (Npgsql parameters require ground-typed values, not arbitrary objects).
        // This is a persistence-binding contract for headers, NOT a wire encoding for Body.
        exchange.Out.Headers["details"] = identityEvent.Details is { Count: > 0 } detailsMap
            ? JsonSerializer.Serialize(detailsMap)
            : (object)DBNull.Value;

        return Task.CompletedTask;
    }

    /// <summary>
    /// Pull a string field off the (anonymous-object-shaped or Dictionary-shaped)
    /// identity-event-data payload. Used as a fallback to surface canonical
    /// audit columns (UserId, Login, ...) when the emitter put them on the
    /// payload but not on the exchange header.
    /// </summary>
    private static string? ExtractStringFromDetails(Dictionary<string, object?>? details, string key)
    {
        if (details is null) return null;
        if (!details.TryGetValue(key, out var v) || v is null) return null;
        return v switch
        {
            string s => string.IsNullOrEmpty(s) ? null : s,
            long l => l.ToString(System.Globalization.CultureInfo.InvariantCulture),
            int i => i.ToString(System.Globalization.CultureInfo.InvariantCulture),
            Guid g => g.ToString("D"),
            _ => v.ToString()
        };
    }
}
