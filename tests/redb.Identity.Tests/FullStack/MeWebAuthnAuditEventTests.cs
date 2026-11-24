using AwesomeAssertions;
using redb.Core;
using redb.Core.Models.Entities;
using redb.Identity.Contracts.Routes;
using redb.Identity.Core.Models;
using redb.Identity.Core.Routes.Processors;
using redb.Identity.Tests.Infrastructure;
using redb.Route.Core;
using Xunit;

namespace redb.Identity.Tests.FullStack;

/// <summary>
/// The audit event a self-service WebAuthn operation leaves on the exchange, with the real MfaService and database of
/// the fixture. An operation that records its own event (credential-delete: <c>MfaWebAuthnRevoked</c>) keeps it; the
/// generic <c>MfaSelfService:webauthn:*</c> event goes only to operations that record none. Before, the generic event
/// overwrote the specific one, so <c>MfaWebAuthnRevoked</c> and <c>MfaWebAuthnRegistered</c> never reached the audit
/// from self-service. register-complete takes the same branch; it is not driven here because it needs a real
/// authenticator attestation.
/// </summary>
[Collection("ProductionHttp")]
public class MeWebAuthnAuditEventTests
{
    private readonly ProductionHttpFixture _fx;

    public MeWebAuthnAuditEventTests(ProductionHttpFixture fx) => _fx = fx;

    [Fact]
    public async Task Deleting_a_credential_records_MfaWebAuthnRevoked()
    {
        var userId = await SeedCredentialAsync("k1");

        var exchange = await RunAsync(userId, "credential-delete", new Dictionary<string, object?> { ["key"] = "k1" });

        exchange.Properties["identity-event-type"].Should().Be(IdentityAuditEventIds.MfaWebAuthnRevoked);
    }

    [Fact]
    public async Task Listing_credentials_still_records_the_generic_self_service_event()
    {
        var userId = await SeedCredentialAsync("k1");

        var exchange = await RunAsync(userId, "credentials", new Dictionary<string, object?>());

        exchange.Properties["identity-event-type"].Should().Be("MfaSelfService:webauthn:credentials");
    }

    private async Task<Exchange> RunAsync(long userId, string operation, Dictionary<string, object?> body)
    {
        var exchange = new Exchange(new Message { Body = body });
        exchange.In.Headers["operation"] = operation;
        exchange.Properties["identity:management-user-id"] = userId;

        await new MeWebAuthnProcessor(_fx.ServiceProvider).Process(exchange);
        return exchange;
    }

    private Task<long> SeedCredentialAsync(string key) => _fx.UseRedbAsync(async redb =>
    {
        var userId = 900_000_000L + Random.Shared.Next(1, 99_999_999);
        await redb.SaveAsync(new RedbObject<MfaProps>(new MfaProps
        {
            Enabled = true,
            DefaultMethod = "webauthn",
            WebAuthnCredentials = new Dictionary<string, WebAuthnCredential>
            {
                [key] = new() { CredentialId = [1, 2, 3], PublicKey = [4, 5, 6], DisplayName = "Laptop", RegisteredAt = DateTimeOffset.UtcNow },
            },
        })
        {
            key = userId,
        });
        return userId;
    });
}
