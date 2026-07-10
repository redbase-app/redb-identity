using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using FluentAssertions;
using MailKit.Net.Imap;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using redb.Identity.Contracts.Routes;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Services;
using redb.Route.Components;
using redb.Route.Core;
using redb.Route.Mail;
using Xunit;
using Xunit.Abstractions;

namespace redb.Identity.Tests.FullStack;

/// <summary>
/// N-4 (Session C): SMTP integration test for <see cref="SmtpEmailNotificationChannel"/>.
/// Drives the channel end-to-end through the real redb.Route.Mail SMTP producer against
/// the GreenMail container shipped in <c>redb.Route/docker-compose.tests.yml</c>
/// (SMTP 127.0.0.1:3025, IMAP 127.0.0.1:3143). Verifies that:
/// <list type="bullet">
///   <item>the <c>direct-vm://identity-email-send</c> route + <c>Smtp.Send(...)</c> DSL wire correctly;</item>
///   <item>the channel populates <c>redbMail.To/Subject/From/ContentType/TextBody</c> headers
///         such that <c>SmtpProducer.BuildMimeMessage</c> sends a proper multipart message;</item>
///   <item>the rendered <c>password-reset</c> template lands in the recipient mailbox with the
///         reset link substituted from the supplied variables.</item>
/// </list>
/// <para>
/// The test is gated on greenmail port reachability — when greenmail is not running the test
/// is skipped (not failed) so local CI runs without the container still pass.
/// </para>
/// </summary>
[Trait("Category", "Integration")]
[Trait("Requires", "Greenmail")]
public sealed class FullStackPasswordRecoverySmtpTests
{
    private const string GreenmailHost = "127.0.0.1";
    private const int GreenmailSmtpPort = 3025;
    private const int GreenmailImapPort = 3143;
    private const string ApiBase = "http://127.0.0.1:8080";

    private readonly ITestOutputHelper _output;

    public FullStackPasswordRecoverySmtpTests(ITestOutputHelper output) => _output = output;

    [Fact]
    public async Task SmtpEmailNotificationChannel_PasswordResetTemplate_LandsInGreenmailInbox()
    {
        SkipIfGreenmailUnavailable();

        // Each run uses a unique recipient so we don't depend on inbox cleanup. Greenmail
        // creates the account on first delivery when -Dgreenmail.setup.test.all is set.
        var recipientUser = $"e2e-recovery-{Guid.NewGuid():N}";
        var recipient = $"{recipientUser}@localhost";
        await ProvisionGreenmailUserAsync(recipientUser, "secret");

        // direct-vm:// endpoints need a SharedVmRegistry singleton in the route
        // context's service provider — production wires it in AddRedbRoute(); for the
        // standalone test we register it manually.
        var sc = new ServiceCollection();
        sc.AddSingleton<SharedVmRegistry>();
        await using var sp = sc.BuildServiceProvider();

        await using var ctx = new RouteContext(sp);
        ctx.AddComponent(new SmtpComponent());
        ctx.AddRoutes(r =>
        {
            // 1:1 mirror of IdentityCoreRouteBuilder's EmailSend route. Kept inline so this
            // test does not pull in the whole IdentityCoreRouteBuilder graph (OpenIddict,
            // EF, etc.) — the unit under test is the channel + route wiring, not the full
            // identity host.
            r.From(IdentityEndpoints.EmailSend)
                .RouteId(IdentityEndpoints.RouteIds.EmailSend)
                .To(Smtp.Send(GreenmailHost)
                    .Port(GreenmailSmtpPort)
                    .Security("None")
                    .From("noreply@redb.local")
                    .ContentType("text/html")
                    .AlternativeBody());
        });
        await ctx.Start();

        var options = Options.Create(new RedbIdentityOptions
        {
            Smtp = new SmtpOptions
            {
                Enabled = true,
                Host = GreenmailHost,
                Port = GreenmailSmtpPort,
                Security = "None",
                FromAddress = "noreply@redb.local",
            }
        });

        var registry = new InlineEmailTemplateRegistry();
        using var channel = new SmtpEmailNotificationChannel(ctx, registry, options, NullLoggerFactory.Instance);

        var resetToken = Guid.NewGuid().ToString("N");
        var resetLink = $"https://app.redb.local/reset?jti=test-jti&token={resetToken}";
        var vars = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["userName"] = recipient,
            ["resetLink"] = resetLink,
            ["ttlMinutes"] = "30",
        };

        await channel.SendTemplateAsync(recipient, IdentityEmailTemplates.PasswordReset, vars);

        // Greenmail is in-process for the SMTP listener but the delivery + indexing is
        // async; a small grace window prevents a flaky read of an empty INBOX.
        var (subject, htmlBody, textBody) = await ReadFirstMessageAsync(recipientUser, "secret");

        _output.WriteLine($"Subject: {subject}");
        _output.WriteLine($"HTML body length: {htmlBody?.Length ?? 0}");

        subject.Should().NotBeNullOrWhiteSpace("the channel must populate redbMail.Subject from the rendered template");
        htmlBody.Should().NotBeNull("the channel sets ContentType=text/html so the body is rendered as HTML alternative");
        htmlBody!.Should().Contain(resetToken, "the rendered HTML must embed the {resetLink} substitution");
        // The default registry ships a plain-text alternative; assert it survived the round-trip.
        textBody.Should().NotBeNullOrWhiteSpace("the rendered text body should be included as the multipart text/plain alternative");
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    private static void SkipIfGreenmailUnavailable()
    {
        var reachable = false;
        try
        {
            using var probe = new TcpClient();
            var task = probe.ConnectAsync(GreenmailHost, GreenmailSmtpPort);
            reachable = task.Wait(TimeSpan.FromMilliseconds(500)) && probe.Connected;
        }
        catch { /* fall through — reachable stays false */ }

        // xUnit 2.9 does not have first-class test-skipping; this integration test
        // (Trait Category=Integration, Requires=Greenmail) MUST be filtered out when
        // greenmail is not running. Failing loudly is the correct behaviour for the
        // CI lane that opts in to the Integration category — silently passing would
        // hide a broken SMTP wiring.
        Assert.True(reachable,
            $"Greenmail not reachable on {GreenmailHost}:{GreenmailSmtpPort}. " +
            "Start with: docker compose -f redb.Route/docker-compose.tests.yml up greenmail -d, " +
            "or filter this test out via `--filter Category!=Integration`.");
    }

    private static async Task ProvisionGreenmailUserAsync(string login, string password)
    {
        // Idempotent — greenmail returns 200 on first create and 409/400 on duplicate; both fine.
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };
        var json = $"{{\"email\":\"{login}@localhost\",\"login\":\"{login}\",\"password\":\"{password}\"}}";
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        try { using var _ = await http.PostAsync($"{ApiBase}/api/user", content); }
        catch { /* greenmail REST is best-effort here — the SMTP listener creates the account on delivery anyway. */ }
    }

    private static async Task<(string? Subject, string? HtmlBody, string? TextBody)> ReadFirstMessageAsync(
        string login, string password)
    {
        // Poll up to ~3 s for the message to be indexed by greenmail's IMAP listener.
        Exception? lastError = null;
        for (var attempt = 0; attempt < 15; attempt++)
        {
            try
            {
                using var imap = new ImapClient();
                await imap.ConnectAsync(GreenmailHost, GreenmailImapPort, MailKit.Security.SecureSocketOptions.None);
                await imap.AuthenticateAsync(login, password);
                var inbox = imap.Inbox;
                await inbox.OpenAsync(MailKit.FolderAccess.ReadOnly);
                if (inbox.Count > 0)
                {
                    var msg = await inbox.GetMessageAsync(0);
                    await imap.DisconnectAsync(true);
                    return (msg.Subject, msg.HtmlBody, msg.TextBody);
                }
                await imap.DisconnectAsync(true);
            }
            catch (Exception ex) { lastError = ex; }

            await Task.Delay(200);
        }
        throw new Xunit.Sdk.XunitException(
            $"No message arrived in {login}@localhost INBOX within 3 s. Last error: {lastError?.Message}");
    }
}
