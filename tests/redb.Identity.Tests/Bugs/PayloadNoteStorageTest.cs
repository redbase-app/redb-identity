using FluentAssertions;
using redb.Core.Models.Entities;
using redb.Identity.Core.Models;
using redb.Identity.Core.Stores;
using redb.Identity.Tests.Infrastructure;
using Xunit;
using Xunit.Abstractions;

namespace redb.Identity.Tests.Bugs;

/// <summary>
/// Tests that token Payload is stored in root _objects.note field
/// instead of PROPS _values._string, avoiding btree index size limits.
/// </summary>
[Collection("Postgres")]
public class PayloadNoteStorageTest
{
    private readonly PostgresFixture _fx;
    private readonly RedbTokenStore _store;
    private readonly RedbApplicationStore _appStore;
    private readonly RedbAuthorizationStore _authStore;
    private readonly ITestOutputHelper _output;

    public PayloadNoteStorageTest(PostgresFixture fx, ITestOutputHelper output)
    {
        _fx = fx;
        _output = output;
        _store = new RedbTokenStore(fx.Redb);
        _appStore = new RedbApplicationStore(fx.Redb);
        _authStore = new RedbAuthorizationStore(fx.Redb);
    }

    private async Task<(long appId, long authId)> CreateTestInfraAsync()
    {
        var app = new RedbObject<ApplicationProps>
        {
            name = $"payload-test-{Guid.NewGuid():N}",
            Props = new ApplicationProps
            {
                ClientId = $"pay-{Guid.NewGuid():N}",
                ClientType = "confidential"
            }
        };
        await _appStore.CreateAsync(app, CancellationToken.None);

        var auth = new RedbObject<AuthorizationProps>
        {
            key = 1,
            Props = new AuthorizationProps
            {
                ApplicationObjectId = app.id,
                Status = "valid",
                Type = "permanent"
            }
        };
        await _authStore.CreateAsync(auth, CancellationToken.None);
        return (app.id, auth.id);
    }

    // ────────── Unit-level: SetPayload writes to note, GetPayload reads from note ──────────

    [Fact]
    public async Task SetPayloadAsync_WritesToNoteField()
    {
        var token = await _store.InstantiateAsync(CancellationToken.None);
        await _store.SetPayloadAsync(token, "test-payload", CancellationToken.None);

        token.note.Should().Be("test-payload");
    }

    [Fact]
    public async Task GetPayloadAsync_ReadsFromNoteField()
    {
        var token = await _store.InstantiateAsync(CancellationToken.None);
        token.note = "note-payload";

        var result = await _store.GetPayloadAsync(token, CancellationToken.None);
        result.Should().Be("note-payload");
    }

    [Fact]
    public async Task PayloadRoundtrip_ViaSetGet()
    {
        var token = await _store.InstantiateAsync(CancellationToken.None);
        const string payload = "{\"sub\":\"test\",\"scope\":\"openid profile\"}";

        await _store.SetPayloadAsync(token, payload, CancellationToken.None);
        var result = await _store.GetPayloadAsync(token, CancellationToken.None);

        result.Should().Be(payload);
    }

    [Fact]
    public async Task SetPayloadAsync_NullValue_SetsNoteNull()
    {
        var token = await _store.InstantiateAsync(CancellationToken.None);
        token.note = "something";

        await _store.SetPayloadAsync(token, null, CancellationToken.None);
        token.note.Should().BeNull();
    }

    [Fact]
    public async Task PayloadIgnoredByProps_PropsPayloadStaysNull()
    {
        // [RedbIgnore] means Props.Payload is not saved to PROPS.
        // After save+reload, Props.Payload should be null/default,
        // while note field should hold the actual payload.
        var (appId, authId) = await CreateTestInfraAsync();

        var token = new RedbObject<TokenProps>
        {
            key = 1,
            value_long = appId,
            value_string = $"ref-{Guid.NewGuid():N}",
            note = "{\"aud\":\"test\"}",
            Props = new TokenProps
            {
                AuthorizationObjectId = authId,
                Status = "valid",
                Type = "access_token"
            }
        };
        await _store.CreateAsync(token, CancellationToken.None);

        var loaded = await _store.FindByIdAsync(token.id.ToString(), CancellationToken.None);
        loaded.Should().NotBeNull();

        // note field should be persisted
        loaded!.note.Should().Be("{\"aud\":\"test\"}");

        // Props.Payload should be null — it's [RedbIgnore], not stored in PROPS
        loaded.Props.Payload.Should().BeNull();
    }

    // ────────── Integration: Large payloads that would crash btree ──────────

    [Fact]
    public async Task LargePayload_SavedInNote_NoBtreeOverflow()
    {
        var (appId, authId) = await CreateTestInfraAsync();

        // Generate a payload larger than the 2704-byte btree limit
        var largePayload = new string('x', 4000);
        _output.WriteLine($"Payload size: {largePayload.Length} bytes");

        var token = new RedbObject<TokenProps>
        {
            key = 1,
            value_long = appId,
            value_string = $"ref-{Guid.NewGuid():N}",
            note = largePayload,
            Props = new TokenProps
            {
                AuthorizationObjectId = authId,
                Status = "valid",
                Type = "access_token"
            }
        };

        // Should NOT throw — note is TEXT without btree index
        await _store.CreateAsync(token, CancellationToken.None);
        token.id.Should().BeGreaterThan(0);
        _output.WriteLine($"Token saved with id={token.id}");

        // Reload and verify
        var loaded = await _store.FindByIdAsync(token.id.ToString(), CancellationToken.None);
        loaded.Should().NotBeNull();
        loaded!.note.Should().Be(largePayload);
    }

    [Fact]
    public async Task RealisticJwtPayload_5000Bytes_Roundtrips()
    {
        var (appId, authId) = await CreateTestInfraAsync();

        // Simulate a realistic JWT payload with 4 scopes + claims
        var realisticPayload = """
        {"sub":"12345","name":"Test User","email":"test@example.com",
        "email_verified":true,"phone_number":"+1234567890",
        "phone_number_verified":false,"preferred_username":"testuser",
        "given_name":"Test","family_name":"User","locale":"en",
        "iss":"https://identity.example.com/","aud":"my-app",
        "exp":1749657600,"iat":1749654000,"nbf":1749654000,
        "scope":"openid profile email phone",
        "azp":"my-app","at_hash":"abc123","c_hash":"def456",
        "nonce":"random-nonce-value","auth_time":1749654000,
        "acr":"urn:mace:incommon:iap:silver",
        "amr":["pwd","mfa"],"jti":"unique-token-id-12345",
        "custom_claim_1":"value1","custom_claim_2":"value2",
        "custom_claim_3":"value3","custom_claim_4":"value4",
        "roles":["admin","user","moderator","editor"],
        "permissions":["read","write","delete","manage"],
        "org_id":"org-123","tenant_id":"tenant-456",
        "session_id":"sess-789","device_id":"dev-012"}
        """;
        // Pad to ~5000 bytes
        realisticPayload += new string(' ', 5000 - realisticPayload.Length);
        _output.WriteLine($"Realistic payload size: {realisticPayload.Length} bytes");

        var token = new RedbObject<TokenProps>
        {
            key = 1,
            value_long = appId,
            value_string = $"ref-{Guid.NewGuid():N}",
            note = realisticPayload,
            Props = new TokenProps
            {
                AuthorizationObjectId = authId,
                Status = "valid",
                Type = "access_token"
            }
        };

        await _store.CreateAsync(token, CancellationToken.None);
        _output.WriteLine($"Saved token id={token.id}");

        var loaded = await _store.FindByIdAsync(token.id.ToString(), CancellationToken.None);
        loaded!.note.Should().Be(realisticPayload);
    }

    [Fact]
    public async Task UpdatePayload_ViaNote_Roundtrips()
    {
        var (appId, authId) = await CreateTestInfraAsync();

        var token = new RedbObject<TokenProps>
        {
            key = 1,
            value_long = appId,
            value_string = $"ref-{Guid.NewGuid():N}",
            note = "original-payload",
            Props = new TokenProps
            {
                AuthorizationObjectId = authId,
                Status = "valid",
                Type = "access_token"
            }
        };
        await _store.CreateAsync(token, CancellationToken.None);

        // Reload, update payload via SetPayloadAsync, save again
        var loaded = (await _store.FindByIdAsync(token.id.ToString(), CancellationToken.None))!;
        await _store.SetPayloadAsync(loaded, "updated-payload", CancellationToken.None);
        await _store.UpdateAsync(loaded, CancellationToken.None);

        // Reload and verify
        var reloaded = (await _store.FindByIdAsync(token.id.ToString(), CancellationToken.None))!;
        reloaded.note.Should().Be("updated-payload");
        (await _store.GetPayloadAsync(reloaded, CancellationToken.None)).Should().Be("updated-payload");
    }

    [Fact]
    public async Task PropsFieldsUnaffected_WhenPayloadInNote()
    {
        var (appId, authId) = await CreateTestInfraAsync();

        var token = new RedbObject<TokenProps>
        {
            key = 42,
            value_long = appId,
            value_string = $"ref-{Guid.NewGuid():N}",
            note = "jwt-body-here",
            Props = new TokenProps
            {
                AuthorizationObjectId = authId,
                Status = "valid",
                Type = "refresh_token",
                ReferenceId = "ref-id-123"
            }
        };
        await _store.CreateAsync(token, CancellationToken.None);

        var loaded = (await _store.FindByIdAsync(token.id.ToString(), CancellationToken.None))!;

        // PROPS fields are intact
        loaded.Props.Status.Should().Be("valid");
        loaded.Props.Type.Should().Be("refresh_token");
        loaded.Props.ReferenceId.Should().Be("ref-id-123");
        loaded.Props.AuthorizationObjectId.Should().Be(authId);

        // Payload is in note, not in PROPS
        loaded.note.Should().Be("jwt-body-here");
        loaded.Props.Payload.Should().BeNull();
    }
}
