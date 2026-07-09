using System.Net;

namespace redb.Identity.Http.Processors;

/// <summary>
/// Shared HTML page templates for identity UI pages (login, consent, logout).
/// Uses base styles from <see cref="IdentityTransportOptions"/> for consistent branding.
/// </summary>
internal static class IdentityPageTemplates
{
    /// <summary>
    /// Wraps inner HTML content in the standard identity page shell
    /// (head, body, card container, logo, shared CSS).
    /// </summary>
    internal static string WrapPage(string title, string cardContent, IdentityTransportOptions opts)
    {
        var logoHtml = string.IsNullOrEmpty(opts.Branding.LogoUrl)
            ? ""
            : $"""<img src="{WebUtility.HtmlEncode(opts.Branding.LogoUrl)}" alt="Logo" class="logo" />""";

        var customCss = string.IsNullOrEmpty(opts.Branding.CustomCss)
            ? ""
            : opts.Branding.CustomCss;

        return $$"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="utf-8" />
                <meta name="viewport" content="width=device-width, initial-scale=1" />
                <title>{{WebUtility.HtmlEncode(title)}} — redb.Identity</title>
                <style>
                    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                           display: flex; align-items: center; justify-content: center;
                           min-height: 100vh; margin: 0; background: #f5f5f5; }
                    .card { background: #fff; padding: 2rem; border-radius: 8px;
                            box-shadow: 0 2px 8px rgba(0,0,0,0.1); width: 380px; }
                    .logo { display: block; max-width: 120px; margin: 0 auto 1rem; }
                    h1 { font-size: 1.4rem; margin: 0 0 1.5rem; text-align: center; }
                    label { display: block; margin-bottom: 0.3rem; font-size: 0.9rem; font-weight: 500; }
                    input[type=text], input[type=password] {
                        width: 100%; padding: 0.5rem; margin-bottom: 1rem;
                        border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
                    .btn { padding: 0.6rem; border: none; border-radius: 4px;
                           font-size: 1rem; cursor: pointer; }
                    .btn-primary { width: 100%; background: {{opts.Branding.PrimaryColor}}; color: #fff; }
                    .btn-primary:hover { background: {{opts.Branding.PrimaryColorHover}}; }
                    .btn-secondary { background: #e5e7eb; color: #333; }
                    .btn-secondary:hover { background: #d1d5db; }
                    .actions { display: flex; gap: 0.75rem; }
                    .actions .btn { flex: 1; }
                    .error { color: #dc2626; font-size: 0.85rem; margin-bottom: 1rem; }
                    .app-name { font-weight: 600; color: {{opts.Branding.PrimaryColor}}; }
                    p { color: #555; font-size: 0.95rem; line-height: 1.5; }
                    ul { padding-left: 1.2rem; margin: 0.5rem 0 1.5rem; }
                    li { margin-bottom: 0.3rem; font-size: 0.9rem; }
                    {{customCss}}
                </style>
            </head>
            <body>
                <div class="card">
                    {{logoHtml}}
                    {{cardContent}}
                </div>
            </body>
            </html>
            """;
    }
}
