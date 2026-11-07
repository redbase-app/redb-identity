using System.Diagnostics.Metrics;

namespace redb.Identity.Core.Metrics;

/// <summary>
/// F3: OpenTelemetry-compatible <see cref="Meter"/>-based metrics for Identity. Exposed as a
/// Singleton and consumed from route processors. Meter name <c>RedbIdentity</c> can be picked
/// up by <c>builder.Services.AddOpenTelemetry().WithMetrics(b =&gt; b.AddMeter("RedbIdentity"))</c>
/// in the host process (Tsak.Worker) without any Identity-side dependency on OTEL packages.
/// <para>
/// Intentionally minimal: every counter / histogram represents an operational signal the
/// Identity SRE needs on day-one (login success/fail, MFA success/fail, token issue/revoke,
/// rate-limit rejections, password-verify latency). Call-sites use <see cref="Meter"/>-local
/// instruments directly — no abstraction layer so we do not pay boxing / dispatch cost in the
/// auth hot path.
/// </para>
/// </summary>
public sealed class IdentityMetrics : IDisposable
{
    public const string MeterName = "RedbIdentity";

    private readonly Meter _meter;

    public IdentityMetrics()
    {
        _meter = new Meter(MeterName, version: "1.0.0");

        LoginAttempts = _meter.CreateCounter<long>(
            "identity.login.attempts",
            unit: "{attempt}",
            description: "Total password login attempts dispatched to the Identity core route.");
        LoginFailures = _meter.CreateCounter<long>(
            "identity.login.failures",
            unit: "{failure}",
            description: "Failed password logins (bad password, unknown user, locked, mfa-required treated separately).");

        MfaVerifications = _meter.CreateCounter<long>(
            "identity.mfa.verifications",
            unit: "{verification}",
            description: "MFA verification attempts (totp / sms / email / recovery). Tag: method, result.");
        MfaLockouts = _meter.CreateCounter<long>(
            "identity.mfa.lockouts",
            unit: "{lockout}",
            description: "MFA lockouts activated (FailedAttempts crossed the threshold). Tag: method.");

        TokensIssued = _meter.CreateCounter<long>(
            "identity.tokens.issued",
            unit: "{token}",
            description: "Tokens minted by OpenIddict. Tag: grant_type, token_type.");
        TokenErrors = _meter.CreateCounter<long>(
            "identity.tokens.errors",
            unit: "{error}",
            description: "Token endpoint errors (invalid_grant, invalid_client, etc.). Tag: error.");

        RateLimitRejections = _meter.CreateCounter<long>(
            "identity.rate_limit.rejections",
            unit: "{rejection}",
            description: "Throttled requests. Tag: endpoint, key_dimension (ip/client/user).");

        PasswordVerifyDuration = _meter.CreateHistogram<double>(
            "identity.password.verify.duration",
            unit: "ms",
            description: "Wall-clock duration of a single password hash verification (BCrypt / PBKDF2 / Argon2).");

        UniqueViolations = _meter.CreateCounter<long>(
            "identity.unique_violation",
            unit: "{violation}",
            description: "DB unique-index violations surfaced to callers (TOCTOU guard). Tag: scheme, column.");
    }

    public Counter<long> LoginAttempts { get; }
    public Counter<long> LoginFailures { get; }
    public Counter<long> MfaVerifications { get; }
    public Counter<long> MfaLockouts { get; }
    public Counter<long> TokensIssued { get; }
    public Counter<long> TokenErrors { get; }
    public Counter<long> RateLimitRejections { get; }
    public Histogram<double> PasswordVerifyDuration { get; }
    public Counter<long> UniqueViolations { get; }

    public void Dispose() => _meter.Dispose();
}
