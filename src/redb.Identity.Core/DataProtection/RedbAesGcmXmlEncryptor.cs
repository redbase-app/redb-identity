using System.Security.Cryptography;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;

namespace redb.Identity.Core.DataProtection;

/// <summary>
/// C10 — AES-GCM XML encryptor for the DataProtection key-ring.
/// <para>
/// Encrypts each key-ring <see cref="XElement"/> with AES-256-GCM using a 32-byte master
/// key supplied by the caller (typically from <c>RedbIdentityOptions.DataProtection.MasterKey</c>).
/// The decryptor type recorded in the descriptor is <see cref="RedbAesGcmXmlDecryptor"/>;
/// ASP.NET DataProtection instantiates it via <c>IActivator</c> on key load, so the decryptor
/// pulls the master key from DI through the same <see cref="RedbMasterKeyProvider"/> singleton.
/// </para>
/// <para>
/// Wire format (single base64 token):
/// <c>[12-byte nonce][16-byte tag][ciphertext]</c>.
/// </para>
/// </summary>
internal sealed class RedbAesGcmXmlEncryptor : IXmlEncryptor
{
    internal const string AlgorithmId = "aes-gcm-256";
    internal const int NonceSize = 12;
    internal const int TagSize = 16;

    private readonly RedbMasterKeyProvider _keyProvider;

    public RedbAesGcmXmlEncryptor(RedbMasterKeyProvider keyProvider)
    {
        ArgumentNullException.ThrowIfNull(keyProvider);
        _keyProvider = keyProvider;
    }

    public EncryptedXmlInfo Encrypt(XElement plaintextElement)
    {
        ArgumentNullException.ThrowIfNull(plaintextElement);

        var plaintextBytes = System.Text.Encoding.UTF8.GetBytes(
            plaintextElement.ToString(SaveOptions.DisableFormatting));

        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var ciphertext = new byte[plaintextBytes.Length];
        var tag = new byte[TagSize];

        using (var aes = new AesGcm(_keyProvider.Key, TagSize))
        {
            aes.Encrypt(nonce, plaintextBytes, ciphertext, tag);
        }

        // Pack nonce | tag | ciphertext into a single base64 blob — keeps the XML compact
        // and the decryptor doesn't need to juggle separate child elements.
        var blob = new byte[NonceSize + TagSize + ciphertext.Length];
        Buffer.BlockCopy(nonce, 0, blob, 0, NonceSize);
        Buffer.BlockCopy(tag, 0, blob, NonceSize, TagSize);
        Buffer.BlockCopy(ciphertext, 0, blob, NonceSize + TagSize, ciphertext.Length);

        var encrypted = new XElement("encryptedKey",
            new XElement("encryptionAlgorithm", AlgorithmId),
            new XElement("value", Convert.ToBase64String(blob)));

        return new EncryptedXmlInfo(encrypted, typeof(RedbAesGcmXmlDecryptor));
    }
}

/// <summary>
/// Companion decryptor for <see cref="RedbAesGcmXmlEncryptor"/>.
/// Resolved by ASP.NET DataProtection's <c>IActivator</c> at key-load time.
/// </summary>
internal sealed class RedbAesGcmXmlDecryptor : IXmlDecryptor
{
    private readonly RedbMasterKeyProvider _keyProvider;

    public RedbAesGcmXmlDecryptor(IServiceProvider services)
    {
        ArgumentNullException.ThrowIfNull(services);
        _keyProvider = (RedbMasterKeyProvider?)services.GetService(typeof(RedbMasterKeyProvider))
            ?? throw new InvalidOperationException(
                "RedbAesGcmXmlDecryptor was activated but no RedbMasterKeyProvider is registered. " +
                "This indicates the key-ring contains entries encrypted under the AES-GCM master key " +
                "but the master key is no longer configured. Restore RedbIdentityOptions.DataProtection.MasterKey.");
    }

    public XElement Decrypt(XElement encryptedElement)
    {
        ArgumentNullException.ThrowIfNull(encryptedElement);

        var algorithm = encryptedElement.Element("encryptionAlgorithm")?.Value;
        if (!string.Equals(algorithm, RedbAesGcmXmlEncryptor.AlgorithmId, StringComparison.Ordinal))
            throw new InvalidOperationException(
                $"Unsupported algorithm '{algorithm}' for {nameof(RedbAesGcmXmlDecryptor)}; expected '{RedbAesGcmXmlEncryptor.AlgorithmId}'.");

        var b64 = encryptedElement.Element("value")?.Value
            ?? throw new InvalidOperationException("Encrypted XML element is missing <value> child.");

        var blob = Convert.FromBase64String(b64);
        if (blob.Length < RedbAesGcmXmlEncryptor.NonceSize + RedbAesGcmXmlEncryptor.TagSize)
            throw new InvalidOperationException("Encrypted blob is too short to contain nonce + tag.");

        var nonce = new byte[RedbAesGcmXmlEncryptor.NonceSize];
        var tag = new byte[RedbAesGcmXmlEncryptor.TagSize];
        var ciphertext = new byte[blob.Length - RedbAesGcmXmlEncryptor.NonceSize - RedbAesGcmXmlEncryptor.TagSize];
        Buffer.BlockCopy(blob, 0, nonce, 0, RedbAesGcmXmlEncryptor.NonceSize);
        Buffer.BlockCopy(blob, RedbAesGcmXmlEncryptor.NonceSize, tag, 0, RedbAesGcmXmlEncryptor.TagSize);
        Buffer.BlockCopy(blob, RedbAesGcmXmlEncryptor.NonceSize + RedbAesGcmXmlEncryptor.TagSize,
            ciphertext, 0, ciphertext.Length);

        var plaintext = new byte[ciphertext.Length];
        using (var aes = new AesGcm(_keyProvider.Key, RedbAesGcmXmlEncryptor.TagSize))
        {
            aes.Decrypt(nonce, ciphertext, tag, plaintext);
        }

        return XElement.Parse(System.Text.Encoding.UTF8.GetString(plaintext));
    }
}

/// <summary>
/// Holds the raw 32-byte AES-256 master key. Singleton; the byte array is owned by this
/// instance and is not exposed via mutable accessors.
/// </summary>
internal sealed class RedbMasterKeyProvider
{
    private readonly byte[] _key;

    public RedbMasterKeyProvider(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length != 32)
            throw new ArgumentException("AES-256 master key must be exactly 32 bytes.", nameof(key));
        _key = (byte[])key.Clone();
    }

    /// <summary>Direct access to the raw key bytes. Do not mutate.</summary>
    public byte[] Key => _key;
}
