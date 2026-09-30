using System.Net;
using System.Text.RegularExpressions;
using FluentAssertions;

namespace redb.Identity.Tests.Infrastructure;

/// <summary>
/// The browser half of a logout without an <c>id_token_hint</c>: <c>/connect/logout</c> answers with a
/// confirmation page whose form carries a state bound to the session, and posting that form back is the
/// confirmation. Tests that sign out by cookie go through here, the way a person clicking the button does.
/// </summary>
internal static class LogoutFlow
{
    private static readonly Regex HiddenInput = new(
        "<input type=\"hidden\" name=\"([^\"]+)\" value=\"([^\"]*)\" />", RegexOptions.Compiled);

    public static bool IsConfirmationPage(string html) =>
        html.Contains("name=\"logout_state\"", StringComparison.Ordinal);

    /// <summary>Every hidden field of the confirmation form, HTML-decoded: the state and the relying party's own parameters.</summary>
    public static Dictionary<string, string> HiddenFields(string html)
    {
        var fields = new Dictionary<string, string>();
        foreach (Match m in HiddenInput.Matches(html))
            fields[m.Groups[1].Value] = WebUtility.HtmlDecode(m.Groups[2].Value);
        return fields;
    }

    /// <summary>Confirms the page in <paramref name="page"/> as the same browser and returns the final logout response.</summary>
    public static async Task<HttpResponseMessage> ConfirmAsync(HttpClient browser, HttpResponseMessage page)
    {
        var html = await page.Content.ReadAsStringAsync();
        IsConfirmationPage(html).Should().BeTrue(
            "a logout by cookie without an id_token_hint answers with the confirmation page first; got {0}: {1}",
            (int)page.StatusCode, html.Length > 300 ? html[..300] : html);
        return await browser.PostAsync("/connect/logout", new FormUrlEncodedContent(HiddenFields(html)));
    }

    /// <summary>GET <paramref name="pathAndQuery"/> with the browser's cookie, then confirm. Returns the final response.</summary>
    public static async Task<HttpResponseMessage> SignOutAsync(HttpClient browser, string pathAndQuery = "/connect/logout")
    {
        var page = await browser.GetAsync(pathAndQuery);
        return await ConfirmAsync(browser, page);
    }
}
