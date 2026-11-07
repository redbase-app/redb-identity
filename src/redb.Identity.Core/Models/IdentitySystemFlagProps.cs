using redb.Core.Attributes;

namespace redb.Identity.Core.Models;

/// <summary>
/// B1 — System-wide one-shot flag stored as a bare <c>RedbObject&lt;IdentitySystemFlagProps&gt;</c>
/// whose data lives entirely in the root <c>_objects</c> table — no PROPS row is written.
/// <para>
/// All payload fields use built-in <see cref="redb.Core.Models.Entities.RedbObject"/> base columns:
/// <list type="bullet">
///   <item><c>name</c> = flag identifier (e.g. <c>"bootstrap_completed"</c>), mirrored into
///   <c>value_unique</c> — UNIQUE per scheme via the core index (V4-UNIQUE).</item>
///   <item><c>value_bool</c> = set / unset state.</item>
///   <item><c>value_datetime</c> = when the flag was set.</item>
///   <item><c>value_string</c> = optional context payload (e.g. client_id of the bootstrapped app).</item>
///   <item><c>note</c> = optional human-readable comment.</item>
///   <item><c>date_create</c> + <c>owner_id</c> = audit, free.</item>
/// </list>
/// </para>
/// <para>
/// The Props body is intentionally empty: this class exists only so a typed
/// <c>Query&lt;IdentitySystemFlagProps&gt;()</c> binds to a known scheme. Bootstrap races
/// are closed by the core's <c>ValueUnique</c> per-scheme unique index (V4-UNIQUE,
/// doc/v4/03 §2, first-wins: the loser catches <c>RedbUniqueViolationException</c> and
/// treats it as "already completed"); the pre-V4 artificial <c>(scheme_id, _name)</c>
/// index from <see cref="Module.IdentityUniqueIndexesInitListener"/> is being retired.
/// </para>
/// </summary>
[RedbScheme("identity.system_flag")]
public sealed class IdentitySystemFlagProps
{
    // intentionally empty — see class XML doc.
}
