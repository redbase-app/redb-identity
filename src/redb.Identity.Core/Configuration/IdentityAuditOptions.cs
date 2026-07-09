namespace redb.Identity.Core.Configuration;

/// <summary>
/// Configuration for the identity audit subsystem.
/// Audit events are dispatched to one or more configurable targets (any redb.Route URI).
/// </summary>
public class IdentityAuditOptions
{
    /// <summary>
    /// Master switch for audit event dispatch. Default: <c>true</c>.
    /// When disabled, events are still logged via ILogger but not sent to any target.
    /// <para>
    /// R1 made local persistence cheap (single INSERT into a flat
    /// <c>identity_audit_log</c> table instead of a multi-row props write),
    /// so the gate flipped to opt-out — every operator's first question on a
    /// fresh Identity deployment was "where's the audit log?".
    /// </para>
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Global event type filter. <c>"*"</c> means all events.
    /// Comma-separated whitelist: <c>"TokenIssued,UserLoggedOut,AuthorizationGranted"</c>.
    /// Applies to all targets uniformly.
    /// </summary>
    public string Filter { get; set; } = "*";

    /// <summary>
    /// H9 (v1.0 DoD): When true and <see cref="Enabled"/> is also true, every event is persisted to the
    /// built-in <c>identity.audit_event</c> PROPS store (queryable via <c>GET /api/v1/identity/audit</c>).
    /// External streaming <see cref="Targets"/> remain independent. Default: <c>true</c>.
    /// </summary>
    public bool PersistToProps { get; set; } = true;

    /// <summary>
    /// List of audit targets. Each target is a redb.Route URI endpoint.
    /// </summary>
    public List<AuditTarget> Targets { get; set; } = [];
}

/// <summary>
/// A single audit target — any redb.Route producer URI (sql:, kafka:, es:, rabbitmq:, log:, etc.).
/// </summary>
public class AuditTarget
{
    /// <summary>
    /// Human-readable name for this target (used in logs and diagnostics).
    /// </summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Whether this target is active. Default: <c>false</c>.
    /// </summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// redb.Route URI for the target endpoint.
    /// Examples:
    /// <list type="bullet">
    ///   <item><c>sql:INSERT INTO identity_audit_log(...) VALUES(...)?dataSource=#pg-audit</c></item>
    ///   <item><c>kafka:identity-audit?brokers=localhost:29092</c></item>
    ///   <item><c>es:identity-audit?server=localhost&amp;port=9200</c></item>
    ///   <item><c>rabbitmq:identity-audit?host=localhost</c></item>
    ///   <item><c>log:identity-audit?level=Information</c></item>
    /// </list>
    /// </summary>
    public string Uri { get; set; } = string.Empty;
}
