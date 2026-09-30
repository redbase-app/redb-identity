using System.Collections.Immutable;
using System.Security.Cryptography;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using OpenIddict.Server;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Keys;
using Xunit;

namespace redb.Identity.Tests.Configuration;

/// <summary>
/// What the store-backed post-configure hands OpenIddict, tested on the component alone.
/// <para>
/// The component built two pools: keys inside their window went into the credentials, and a broader
/// "validation pool" of every persisted key past <c>NotBefore</c> — retired ones included — was written
/// into <c>TokenValidationParameters.IssuerSigningKeys</c>, so that, the comments said, tokens signed by
/// retired keys would keep validating "during the grace window". Retirement sets <c>NotAfter</c> to now,
/// so that pool kept a retired key for as long as its row existed. In the shipped wiring the list never
/// reached a token: OpenIddict's own post-configure runs after this one and rebuilds the validation keys
/// from the credentials. That was luck of registration order, and this component is not allowed to rely on
/// it: run in isolation, as here, it must produce lists a validator could trust directly.
/// </para>
/// <para>
/// There is no validation pool of retired keys. A rotated key validates until its own <c>NotAfter</c> —
/// that is the handover window; a retired key's <c>NotAfter</c> is the moment of retirement, and trust ends
/// there. Whatever OpenIddict reads, the credentials and the validation parameters say the same thing.
/// </para>
/// </summary>
public sealed class SigningKeyPostConfigureTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;

    private static SigningKeyMaterial Key(string kid, string kind, DateTimeOffset notBefore, DateTimeOffset notAfter, bool active) =>
        new(kid, kind, kind == "signing" ? "RS256" : "RSA-OAEP", new RsaSecurityKey(RSA.Create(2048)), notBefore, notAfter, active);

    private static readonly SigningKeyMaterial Active = Key("k_active", "signing", Now.AddDays(-1), Now.AddDays(89), active: true);
    private static readonly SigningKeyMaterial Demoted = Key("k_demoted", "signing", Now.AddDays(-30), Now.AddDays(60), active: false);
    private static readonly SigningKeyMaterial Retired = Key("k_retired", "signing", Now.AddDays(-60), Now.AddMinutes(-1), active: false);
    private static readonly SigningKeyMaterial Encryption = Key("k_enc", "encryption", Now.AddDays(-1), Now.AddDays(89), active: true);
    private static readonly SigningKeyMaterial RetiredEncryption = Key("k_enc_retired", "encryption", Now.AddDays(-60), Now.AddMinutes(-1), active: false);

    /// <summary>The store as it really answers: the working set is the in-window subset of the full list.</summary>
    private static ISigningKeyStore Store()
    {
        var all = ImmutableArray.Create(Active, Demoted, Retired, Encryption, RetiredEncryption);
        var store = Substitute.For<ISigningKeyStore>();
        store.ListAllIncludingRetiredAsync(Arg.Any<CancellationToken>()).Returns(all);
        store.GetAllAsync(Arg.Any<CancellationToken>()).Returns(all.Where(k => k.NotAfter > Now).ToImmutableArray());
        return store;
    }

    private static OpenIddictServerOptions Configure(
        ISigningKeyStore store, OpenIddictServerOptions? options = null, MintingKeySource? minting = null)
    {
        options ??= new OpenIddictServerOptions();
        var sut = new PropsSigningKeyStoreOpenIddictPostConfigure(
            store,
            Options.Create(new RedbIdentityOptions { UsePropsSigningKeyStore = true, MintingKeySource = minting }),
            NullLogger<PropsSigningKeyStoreOpenIddictPostConfigure>.Instance);
        sut.PostConfigure(null, options);
        return options;
    }

    private static string Fingerprint(SecurityKey key) =>
        Convert.ToHexString(((RsaSecurityKey)key).Rsa!.ExportParameters(false).Modulus!);

    [Fact]
    public void Keys_inside_their_window_are_credentials_active_first()
    {
        var options = Configure(Store());

        // The active key must win OpenIddict's first-compatible-credential pick for minting; the demoted one
        // stays behind it so tokens it signed keep validating until its own NotAfter.
        options.SigningCredentials.Select(c => c.Key.KeyId).Should().Equal("k_active", "k_demoted");
        options.EncryptionCredentials.Select(c => c.Key.KeyId).Should().Equal("k_enc");
    }

    [Fact]
    public void A_retired_key_is_in_no_list_at_all()
    {
        var options = Configure(Store());

        options.SigningCredentials.Select(c => Fingerprint(c.Key)).Should().NotContain(Fingerprint(Retired.SecurityKey));
        options.TokenValidationParameters.IssuerSigningKeys.Select(Fingerprint).Should().NotContain(Fingerprint(Retired.SecurityKey),
            "retirement is the moment trust ends; a validation list that keeps the key defeats it, and whether "
            + "OpenIddict happens to overwrite this list is not this component's to lean on");
        options.TokenValidationParameters.TokenDecryptionKeys.Select(Fingerprint).Should().NotContain(Fingerprint(RetiredEncryption.SecurityKey));
    }

    [Fact]
    public void The_validation_parameters_say_exactly_what_the_credentials_say()
    {
        var options = Configure(Store());

        options.TokenValidationParameters.IssuerSigningKeys.Select(Fingerprint)
            .Should().BeEquivalentTo(options.SigningCredentials.Select(c => Fingerprint(c.Key)),
                "one set of trusted keys, not two that can disagree");
        options.TokenValidationParameters.TokenDecryptionKeys.Select(Fingerprint)
            .Should().BeEquivalentTo(options.EncryptionCredentials.Select(c => Fingerprint(c.Key)));
    }

    [Fact]
    public void A_credential_another_configurer_added_is_kept_and_trusted()
    {
        // The file's own rule: re-run on every options refresh, so be additive and never clear the lists.
        // Assigning the validation parameters from the store's keys alone broke that rule for everyone
        // else's credentials; they must stay in the credentials AND be trusted for validation.
        var hostKey = new RsaSecurityKey(RSA.Create(2048)) { KeyId = "k_host" };
        var options = new OpenIddictServerOptions();
        options.SigningCredentials.Add(new SigningCredentials(hostKey, SecurityAlgorithms.RsaSha256));

        Configure(Store(), options);

        options.SigningCredentials.Select(c => c.Key.KeyId).Should().Contain("k_host");
        options.TokenValidationParameters.IssuerSigningKeys.Select(Fingerprint).Should().Contain(Fingerprint(hostKey));
    }

    // Who mints when the operator's own credentials and the store are both present is the operator's choice,
    // not the order two registrations happen to run in. OpenIddict mints with the first compatible entry, so
    // the choice is the position of the store's keys relative to the configured ones; both sets stay
    // trusted and published whichever comes first.

    [Fact]
    public void Configured_minting_source_keeps_the_operators_credential_first_and_the_store_behind_it()
    {
        var hostKey = new RsaSecurityKey(RSA.Create(2048)) { KeyId = "k_host" };
        var hostEncryption = new RsaSecurityKey(RSA.Create(2048)) { KeyId = "k_host_enc" };
        var options = new OpenIddictServerOptions();
        options.SigningCredentials.Add(new SigningCredentials(hostKey, SecurityAlgorithms.RsaSha256));
        options.EncryptionCredentials.Add(new EncryptingCredentials(hostEncryption, SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes256CbcHmacSha512));

        Configure(Store(), options, MintingKeySource.Configured);

        options.SigningCredentials.Select(c => c.Key.KeyId).Should().Equal("k_host", "k_active", "k_demoted");
        options.EncryptionCredentials.Select(c => c.Key.KeyId).Should().Equal("k_host_enc", "k_enc");
        options.TokenValidationParameters.IssuerSigningKeys.Select(Fingerprint)
            .Should().BeEquivalentTo(options.SigningCredentials.Select(c => Fingerprint(c.Key)), "both sources validate");
    }

    [Fact]
    public void Store_minting_source_puts_the_stores_active_key_first_and_the_operators_credential_behind_it()
    {
        var hostKey = new RsaSecurityKey(RSA.Create(2048)) { KeyId = "k_host" };
        var options = new OpenIddictServerOptions();
        options.SigningCredentials.Add(new SigningCredentials(hostKey, SecurityAlgorithms.RsaSha256));

        Configure(Store(), options, MintingKeySource.Store);

        options.SigningCredentials.Select(c => c.Key.KeyId).Should().Equal("k_active", "k_demoted", "k_host");
        options.TokenValidationParameters.IssuerSigningKeys.Select(Fingerprint).Should().Contain(Fingerprint(hostKey));
    }
}
