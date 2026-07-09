using System.Security.Cryptography.X509Certificates;
using redb.Identity.Core.Configuration;

namespace redb.Identity.Core.DataProtection;

/// <summary>
/// C10 — loads an X.509 certificate from configuration. Supports two sources:
/// <list type="bullet">
///   <item><b>PFX file on disk</b> via <see cref="DataProtectionCertificateOptions.PfxPath"/>
///   (+ optional <see cref="DataProtectionCertificateOptions.PfxPassword"/>).</item>
///   <item><b>Local certificate store</b> by thumbprint via
///   <see cref="DataProtectionCertificateOptions.Thumbprint"/> in
///   <see cref="DataProtectionCertificateOptions.StoreName"/> /
///   <see cref="DataProtectionCertificateOptions.StoreLocation"/>.</item>
/// </list>
/// PFX-on-disk wins when both are set.
/// </summary>
internal static class CertificateLoader
{
    public static X509Certificate2 Load(DataProtectionCertificateOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (!string.IsNullOrWhiteSpace(options.PfxPath))
            return LoadFromPfx(options.PfxPath!, options.PfxPassword);

        if (!string.IsNullOrWhiteSpace(options.Thumbprint))
            return LoadFromStore(options.Thumbprint!, options.StoreName, options.StoreLocation);

        throw new InvalidOperationException(
            "DataProtection.Certificate is not configured: set Thumbprint or PfxPath.");
    }

    private static X509Certificate2 LoadFromPfx(string path, string? password)
    {
        if (!File.Exists(path))
            throw new InvalidOperationException(
                $"DataProtection.Certificate.PfxPath '{path}' does not exist.");

        // X509KeyStorageFlags.EphemeralKeySet keeps the private key in memory only — avoids
        // writing key material to %APPDATA%/.dotnet on every load (Linux/macOS especially).
        // MachineKeySet is not used because Identity may run as a service account that
        // doesn't have write access to the machine key store.
        try
        {
            return X509CertificateLoader.LoadPkcs12FromFile(
                path,
                password,
                X509KeyStorageFlags.EphemeralKeySet);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                $"Failed to load PFX from '{path}'. Verify the file is a valid PKCS#12 archive " +
                "and the password (if any) is correct.", ex);
        }
    }

    private static X509Certificate2 LoadFromStore(string thumbprint, string storeName, string storeLocation)
    {
        // Thumbprints are typically pasted from MMC with spaces / mixed case — normalise.
        var normalised = new string(thumbprint.Where(char.IsLetterOrDigit).ToArray()).ToUpperInvariant();

        if (!Enum.TryParse<StoreLocation>(storeLocation, ignoreCase: true, out var loc))
            throw new InvalidOperationException(
                $"DataProtection.Certificate.StoreLocation '{storeLocation}' is not a valid X509 StoreLocation. " +
                "Use 'CurrentUser' or 'LocalMachine'.");

        StoreName parsedStoreName;
        if (Enum.TryParse<StoreName>(storeName, ignoreCase: true, out var sn))
        {
            parsedStoreName = sn;
            using var store = new X509Store(parsedStoreName, loc);
            return FindByThumbprint(store, normalised, storeName, storeLocation);
        }

        // Custom store name (e.g. operator's own store) — X509Store ctor takes the string as-is.
        using var customStore = new X509Store(storeName, loc);
        return FindByThumbprint(customStore, normalised, storeName, storeLocation);
    }

    private static X509Certificate2 FindByThumbprint(
        X509Store store, string normalisedThumbprint, string storeName, string storeLocation)
    {
        store.Open(OpenFlags.ReadOnly);
        // validOnly=false: an expired cert is still useful for DECRYPTING old key-ring entries
        // (the new ones will be encrypted with whatever cert is configured next).
        var matches = store.Certificates.Find(
            X509FindType.FindByThumbprint, normalisedThumbprint, validOnly: false);
        if (matches.Count == 0)
            throw new InvalidOperationException(
                $"No certificate found with thumbprint '{normalisedThumbprint}' " +
                $"in {storeLocation}\\{storeName}.");
        var cert = matches[0];
        if (!cert.HasPrivateKey)
            throw new InvalidOperationException(
                $"Certificate '{normalisedThumbprint}' in {storeLocation}\\{storeName} " +
                "does not have an accessible private key — DataProtection key-ring decryption " +
                "would fail. Grant the service account read access to the private key, or " +
                "supply a PFX file via DataProtection.Certificate.PfxPath.");
        return cert;
    }
}
