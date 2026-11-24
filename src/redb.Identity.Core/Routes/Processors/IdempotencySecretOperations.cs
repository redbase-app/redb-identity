namespace redb.Identity.Core.Routes.Processors;

/// <summary>
/// The operations behind the Idempotency-Key cache whose answer carries a one-time secret. Their answer is recorded
/// without its body: a repeat with the same key does not run the operation again and is told that the secret is not
/// shown again (<see cref="IdempotencyProcessor"/>, <see cref="IdempotencyCaptureProcessor"/>).
/// <para>
/// This list is the 4.7 line's form of the rule. From 4.8.0 the cache finds these answers by the
/// <c>[OneTimeSecret]</c> markers on the result types of redb.Identity.Contracts instead, and this list is gone. The
/// entries match those markers on the cached routes: <c>MfaSetupResponse</c> (setup), <c>MfaConfirmedResponse</c>
/// (confirm), <c>MfaRecoveryCodesResponse</c> (regenerate-recovery), <c>ApplicationResponse.NewSecret</c>
/// (rotate-secret), <c>WebhookSubscriptionResponse.HmacSecret</c> (create) and <c>WebhookSecretRotatedResponse</c>
/// (rotate-secret). The other marked results are not behind the cache on the line: tokens, dynamic registration,
/// bootstrap and the self-service WebAuthn routes, and the SCIM password, which is never returned.
/// </para>
/// </summary>
internal static class IdempotencySecretOperations
{
    /// <summary>The cached operations whose answer carries a one-time secret, as (route scope, operation).</summary>
    internal static readonly IReadOnlyList<(string Scope, string Operation)> All =
    [
        ("mfa-manage", "setup"),
        ("mfa-manage", "confirm"),
        ("mfa-manage", "regenerate-recovery"),
        ("manage-apps", "rotate-secret"),
        ("manage-webhooks", "create"),
        ("manage-webhooks", "rotate-secret"),
    ];

    /// <summary>True when the answer of <paramref name="operation"/> on the route <paramref name="scope"/> carries a one-time secret.</summary>
    internal static bool Carries(string? scope, string? operation)
    {
        foreach (var (s, o) in All)
        {
            if (string.Equals(s, scope, StringComparison.Ordinal) && string.Equals(o, operation, StringComparison.Ordinal))
                return true;
        }

        return false;
    }

    /// <summary>The answer to a repeat of such an operation: the operation is not run again and the secret is not shown.</summary>
    internal static Dictionary<string, object?> WithheldReplayBody() => new()
    {
        ["replayed"] = true,
        ["secretWithheld"] = true,
        ["description"] = "The operation was already carried out for this Idempotency-Key. Its answer carried a secret that is shown only once, so it is not shown again.",
    };
}
