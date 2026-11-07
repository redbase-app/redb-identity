namespace redb.Identity.Web.Configuration;

/// <summary>
/// N8-3 / N8-4 (BFF UX): operator-controlled UI links rendered in the global footer.
/// All fields are optional \u2014 if the corresponding URL is null/empty the link is
/// simply omitted from the rendered footer rather than producing a broken anchor.
/// Bound from <c>Identity:Web:Links</c> in <c>appsettings.json</c>.
/// </summary>
public sealed class IdentityWebLinksOptions
{
    /// <summary>External URL of the Terms of Service page. Empty/null \u2192 link hidden.</summary>
    public string? TermsOfService { get; set; }

    /// <summary>External URL of the Privacy Policy page. Empty/null \u2192 link hidden.</summary>
    public string? PrivacyPolicy { get; set; }

    /// <summary>Optional support / contact page (e-mail or URL). Empty/null \u2192 hidden.</summary>
    public string? Support { get; set; }
}
