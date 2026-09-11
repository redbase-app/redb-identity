using System.Security.Cryptography;
using System.Text;

namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// V4-UNIQUE, owner decision Р5(в) (doc/v4/00-PLAN.md §6): the idempotency-record unique key
/// is <c>_objects._value_unique</c> = SHA-256 of the composite name, hex-lowercase (64 chars,
/// always under the 440-char ValueUnique limit — the raw composite
/// <c>idem:{scope}:{operation}:{caller}:{key}</c> is unbounded because caller subject and the
/// client-chosen Idempotency-Key are). The readable composite stays in <c>_objects._name</c>
/// exactly as before; only the enforced key is hashed. Collisions are negligible for this
/// small, TTL-reaped table, and the defensive Props equality check in the processor guards
/// the replay path regardless.
/// </summary>
internal static class IdempotencyKeyHash
{
    public static string Sha256Hex(string composite)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(composite))).ToLowerInvariant();
}
