using FluentAssertions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using redb.Identity.Core;
using redb.Identity.Core.DataProtection;
using redb.Identity.DataProtection;
using System.Xml.Linq;
using Xunit;
using DataProtectionOptions = redb.Identity.Core.Configuration.DataProtectionOptions;
using DataProtectionCertificateOptions = redb.Identity.Core.Configuration.DataProtectionCertificateOptions;
using RedbIdentityOptions = redb.Identity.Core.Configuration.RedbIdentityOptions;

namespace redb.Identity.Tests.DataProtection;

/// <summary>
/// C10 — at-rest encryption for the DataProtection key-ring.
/// </summary>
public class DataProtectionAtRestTests
{
    private static byte[] NewKey() => System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);

    // ── AES-GCM master-key encryptor ──

    [Fact]
    public void AesGcmEncryptor_RoundTrips_Plaintext()
    {
        var keyProvider = new RedbMasterKeyProvider(NewKey());
        var encryptor = new RedbAesGcmXmlEncryptor(keyProvider);

        var original = new XElement("key",
            new XAttribute("id", "abc"),
            new XElement("descriptor", "secret-payload"));

        var encrypted = encryptor.Encrypt(original);
        encrypted.DecryptorType.Should().Be(typeof(RedbAesGcmXmlDecryptor));
        encrypted.EncryptedElement.Element("encryptionAlgorithm")!.Value
            .Should().Be(RedbAesGcmXmlEncryptor.AlgorithmId);

        // Roundtrip via the decryptor (resolved from a tiny DI graph).
        var sp = new ServiceCollection().AddSingleton(keyProvider).BuildServiceProvider();
        var decryptor = new RedbAesGcmXmlDecryptor(sp);
        var roundtripped = decryptor.Decrypt(encrypted.EncryptedElement);

        XNode.DeepEquals(roundtripped, original).Should().BeTrue();
    }

    [Fact]
    public void AesGcmEncryptor_CiphertextDoesNotContainPlaintext()
    {
        var encryptor = new RedbAesGcmXmlEncryptor(new RedbMasterKeyProvider(NewKey()));
        var element = new XElement("key", "very-secret-marker");

        var encrypted = encryptor.Encrypt(element);

        encrypted.EncryptedElement.ToString(SaveOptions.DisableFormatting)
            .Should().NotContain("very-secret-marker");
    }

    [Fact]
    public void AesGcmDecryptor_RejectsTamperedCiphertext()
    {
        var keyProvider = new RedbMasterKeyProvider(NewKey());
        var encryptor = new RedbAesGcmXmlEncryptor(keyProvider);
        var encrypted = encryptor.Encrypt(new XElement("key", "data"));

        // Flip a bit inside the ciphertext blob — AES-GCM tag check must reject.
        var valueElement = encrypted.EncryptedElement.Element("value")!;
        var blob = Convert.FromBase64String(valueElement.Value);
        blob[blob.Length - 1] ^= 0x01;
        valueElement.Value = Convert.ToBase64String(blob);

        var sp = new ServiceCollection().AddSingleton(keyProvider).BuildServiceProvider();
        var decryptor = new RedbAesGcmXmlDecryptor(sp);

        var act = () => decryptor.Decrypt(encrypted.EncryptedElement);
        act.Should().Throw<System.Security.Cryptography.AuthenticationTagMismatchException>();
    }

    [Fact]
    public void AesGcmDecryptor_RejectsWrongAlgorithm()
    {
        var keyProvider = new RedbMasterKeyProvider(NewKey());
        var sp = new ServiceCollection().AddSingleton(keyProvider).BuildServiceProvider();
        var decryptor = new RedbAesGcmXmlDecryptor(sp);

        var bogus = new XElement("encryptedKey",
            new XElement("encryptionAlgorithm", "rot13"),
            new XElement("value", Convert.ToBase64String(new byte[64])));

        var act = () => decryptor.Decrypt(bogus);
        act.Should().Throw<InvalidOperationException>().WithMessage("*Unsupported algorithm*");
    }

    [Fact]
    public void MasterKeyProvider_RejectsWrongLength()
    {
        var act = () => new RedbMasterKeyProvider(new byte[16]);
        act.Should().Throw<ArgumentException>().WithMessage("*32 bytes*");
    }

    // ── ProtectKeysWithRedbIdentity wiring ──

    [Fact]
    public void ProtectKeys_MasterKey_RegistersAesGcmEncryptor()
    {
        var key = Convert.ToBase64String(NewKey());
        var options = new RedbIdentityOptions
        {
            DataProtection = new DataProtectionOptions { MasterKey = key }
        };

        var sp = BuildDataProtectionGraph(options);

        var kmo = sp.GetRequiredService<IOptions<KeyManagementOptions>>().Value;
        kmo.XmlEncryptor.Should().BeOfType<RedbAesGcmXmlEncryptor>();
        sp.GetService<RedbMasterKeyProvider>().Should().NotBeNull();
    }

    [Fact]
    public void ProtectKeys_CustomEncryptorFactory_TakesPrecedence()
    {
        var fakeEncryptor = new FakeXmlEncryptor();
        var options = new RedbIdentityOptions
        {
            DataProtection = new DataProtectionOptions
            {
                MasterKey = Convert.ToBase64String(NewKey()), // would otherwise win
                CustomEncryptorFactory = _ => fakeEncryptor
            }
        };

        var sp = BuildDataProtectionGraph(options);

        var kmo = sp.GetRequiredService<IOptions<KeyManagementOptions>>().Value;
        kmo.XmlEncryptor.Should().BeSameAs(fakeEncryptor);
    }

    [Fact]
    public void ProtectKeys_NoEncryptor_ProductionGate_Throws()
    {
        var options = new RedbIdentityOptions
        {
            AllowEphemeralKeys = false,
            DataProtection = new DataProtectionOptions { RequireAtRestEncryption = true }
        };

        var act = () => BuildDataProtectionGraph(options);
        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*key-ring is unprotected at rest*");
    }

    [Fact]
    public void ProtectKeys_NoEncryptor_DevMode_AllowedWhenEphemeralKeysAllowed()
    {
        var options = new RedbIdentityOptions
        {
            AllowEphemeralKeys = true,
            DataProtection = new DataProtectionOptions { RequireAtRestEncryption = true }
        };

        var sp = BuildDataProtectionGraph(options);

        var kmo = sp.GetRequiredService<IOptions<KeyManagementOptions>>().Value;
        kmo.XmlEncryptor.Should().BeNull();
    }

    [Fact]
    public void ProtectKeys_NoEncryptor_GateOff_Allowed()
    {
        var options = new RedbIdentityOptions
        {
            AllowEphemeralKeys = false,
            DataProtection = new DataProtectionOptions { RequireAtRestEncryption = false }
        };

        var sp = BuildDataProtectionGraph(options);

        var kmo = sp.GetRequiredService<IOptions<KeyManagementOptions>>().Value;
        kmo.XmlEncryptor.Should().BeNull();
    }

    [Fact]
    public void ProtectKeys_MasterKey_RejectsWrongLength()
    {
        var options = new RedbIdentityOptions
        {
            DataProtection = new DataProtectionOptions
            {
                MasterKey = Convert.ToBase64String(new byte[16]) // 128-bit, not 256
            }
        };

        var act = () => BuildDataProtectionGraph(options);
        act.Should().Throw<InvalidOperationException>().WithMessage("*32 bytes*");
    }

    [Fact]
    public void ProtectKeys_MasterKey_RejectsBadBase64()
    {
        var options = new RedbIdentityOptions
        {
            DataProtection = new DataProtectionOptions { MasterKey = "%not-base64%" }
        };

        var act = () => BuildDataProtectionGraph(options);
        act.Should().Throw<InvalidOperationException>().WithMessage("*base64*");
    }

    [Fact]
    public void ProtectKeys_Cert_PfxPathMissing_Throws()
    {
        var options = new RedbIdentityOptions
        {
            DataProtection = new DataProtectionOptions
            {
                Certificate = new DataProtectionCertificateOptions
                {
                    PfxPath = "C:/this/path/does/not/exist.pfx"
                }
            }
        };

        var act = () => BuildDataProtectionGraph(options);
        act.Should().Throw<InvalidOperationException>().WithMessage("*does not exist*");
    }

    // ── DataProtectionOptions.HasEncryptorConfigured ──

    [Theory]
    [InlineData(false, null, null, null, false)] // nothing
    [InlineData(true, "AAAA", null, null, true)] // master key
    [InlineData(false, null, "thumb", null, true)] // cert thumbprint
    [InlineData(false, null, null, "/p.pfx", true)] // cert pfx
    public void HasEncryptorConfigured_ReflectsAllSources(
        bool useFactory, string? masterKey, string? thumbprint, string? pfxPath, bool expected)
    {
        var dp = new DataProtectionOptions
        {
            MasterKey = masterKey,
            Certificate = new DataProtectionCertificateOptions
            {
                Thumbprint = thumbprint,
                PfxPath = pfxPath
            }
        };
        if (useFactory)
            dp.CustomEncryptorFactory = _ => new FakeXmlEncryptor();

        dp.HasEncryptorConfigured.Should().Be(expected || useFactory);
    }

    // ── helpers ──

    /// <summary>
    /// Builds a tiny DI graph that mirrors what <c>AddRedbIdentityServer</c> does for
    /// DataProtection — just enough to inspect the resulting <see cref="KeyManagementOptions"/>.
    /// </summary>
    private static IServiceProvider BuildDataProtectionGraph(RedbIdentityOptions options)
    {
        var services = new ServiceCollection();
        services.AddDataProtection()
            .PersistKeysToRedb()
            .ProtectKeysWithRedbIdentity(options);
        // PersistKeysToRedb registers RedbXmlRepository which depends on IServiceScopeFactory —
        // ServiceCollection provides one out of the box, so no extra registration needed.
        return services.BuildServiceProvider();
    }

    private sealed class FakeXmlEncryptor : IXmlEncryptor
    {
        public EncryptedXmlInfo Encrypt(XElement plaintextElement)
            => new(new XElement("fake"), typeof(FakeXmlEncryptor));
    }
}
