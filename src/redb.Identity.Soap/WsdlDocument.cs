using System.Reflection;

namespace redb.Identity.Soap;

/// <summary>
/// Locates the WSDL shipped alongside this assembly.
/// <para>
/// The file is content, not an embedded resource, on purpose: an operator can read it, and a client
/// developer can hand it to a generator, without the service running. The consumer rewrites the
/// <c>soap:address</c> to the caller's own URL when it serves the document, so a copy fetched from a
/// live endpoint always points back at that endpoint.
/// </para>
/// </summary>
internal static class WsdlDocument
{
    /// <summary>File name as shipped, next to the assembly and inside the <c>.tpkg</c>.</summary>
    public const string FileName = "identity-sts.wsdl";

    /// <summary>Directory the file is copied into.</summary>
    public const string Directory = "Wsdl";

    /// <summary>
    /// The WSDL itself, as XML.
    /// <para>
    /// The embedded copy is read first, and in a Tsak worker it is the only one that exists: a module's
    /// assembly is loaded straight from its <c>.tpkg</c> with <c>LoadFromStream</c>, so it never lands
    /// on disk and <see cref="Assembly.Location"/> is empty. Resolving a path next to the assembly
    /// therefore found nothing in production while working perfectly in every test, and the facade
    /// answered <c>405</c> to the <c>GET</c> that a client generator makes first.
    /// </para>
    /// <para>
    /// The file beside the assembly is still read when it is there, which covers a plain file
    /// deployment and anyone who replaced the contract without rebuilding.
    /// </para>
    /// <para>
    /// A missing document is not a reason to refuse service: the four operations answer exactly the
    /// same either way, so the consumer serves 404 for the document and keeps taking requests.
    /// </para>
    /// </summary>
    public static string? ReadContent()
    {
        var assembly = Assembly.GetExecutingAssembly();

        var resourceName = Array.Find(
            assembly.GetManifestResourceNames(),
            n => n.EndsWith(FileName, StringComparison.OrdinalIgnoreCase));

        if (resourceName is not null)
        {
            using var stream = assembly.GetManifestResourceStream(resourceName);
            if (stream is not null)
            {
                using var reader = new StreamReader(stream);
                return reader.ReadToEnd();
            }
        }

        var path = ResolvePath();
        return path is null ? null : File.ReadAllText(path);
    }

    /// <summary>
    /// The path to the WSDL next to this assembly, when the assembly came from a file at all. Empty in
    /// a Tsak worker, for the reason given on <see cref="ReadContent"/>.
    /// </summary>
    public static string? ResolvePath()
    {
        var assemblyDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
        if (string.IsNullOrEmpty(assemblyDir)) return null;

        var path = Path.Combine(assemblyDir, Directory, FileName);
        return File.Exists(path) ? path : null;
    }
}
