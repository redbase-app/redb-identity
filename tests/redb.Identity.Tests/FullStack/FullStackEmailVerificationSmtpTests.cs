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
/// N-4 (Session C, N4-6): SMTP integration test for the <c>email-verification</c> template.
/// Mirrors <see cref="FullStackPasswordRecoverySmtpTests"/> but exercises the e-mail
/// verification template (<see cref="IdentityEmailTemplates.EmailVerification"/>) end-to-end
/// through <see cref="SmtpEmailNotificationChannel"/> against the GreenMail container.
/// Verifies that the rendered HTML body embeds the supplied <c>verifyLink</c> substitution
/// and that the multipart text/plain alternative survives the round-trip.
/// </summary>
[Trait("Category", "Integration")]
[Trait("Requires", "Greenmail")]
public sealed class FullStackEmailVerificationSmtpTests
{
    private const string GreenmailHost = "127.0.0.1";
    private const int GreenmailSmtpPort = 3025;
    private const int GreenmailImapPort = 3143;
    private const string ApiBase = "http://127.0.0.1:8080";

    private readonly ITestOutputHelper _output;

    public FullStackEmailVerificationSmtpTests(ITestOutputHelper output) => _output = output;

    [Fact]
    public async Task SmtpEmailNotificationChannel_EmailVerificationTemplate_LandsInGreenmailInbox()
    {
        SkipIfGreenmailUnavailable();

        var recipientUser = $"e2e-verify-{Guid.NewGuid():N}";
        var recipient = $"{recipientUser}@localhost";
        await ProvisionGreenmailUserAsync(recipientUser, "secret");

        var sc = new ServiceCollection();
        sc.AddSingleton<SharedVmRegistry>();
        await using var sp = sc.BuildServiceProvider();

        await using var ctx = new RouteContext(sp);
        ctx.AddComponent(new SmtpComponent());
        ctx.AddRoutes(r =>
        {
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

        var verifyToken = Guid.NewGuid().ToString("N");
        var verifyLink = $"https://app.redb.local/verify-email?jti=verify-jti&token={verifyToken}";
        var vars = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["userName"] = recipient,
            ["verifyLink"] = verifyLink,
            ["ttlHours"] = "24",
        };

        await channel.SendTemplateAsync(recipient, IdentityEmailTemplates.EmailVerification, vars);

        var (subject, htmlBody, textBody) = await ReadFirstMessageAsync(recipientUser, "secret");

        _output.WriteLine($"Subject: {subject}");
        _output.WriteLine($"HTML body length: {htmlBody?.Length ?? 0}");

        subject.Should().NotBeNullOrWhiteSpace("the channel must populate redbMail.Subject from the rendered template");
        htmlBody.Should().NotBeNull("the channel sets ContentType=text/html so the body is rendered as HTML alternative");
        htmlBody!.Should().Contain(verifyToken, "the rendered HTML must embed the {verifyLink} substitution");
        textBody.Should().NotBeNullOrWhiteSpace("the rendered text body should be included as the multipart text/plain alternative");
    }

    // ── Helpers (verbatim from FullStackPasswordRecoverySmtpTests; kept inline so each
    //   integration test file is self-contained and can be removed independently) ──

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

        Assert.True(reachable,
            $"Greenmail not reachable on {GreenmailHost}:{GreenmailSmtpPort}. " +
            "Start with: docker compose -f redb.Route/docker-compose.tests.yml up greenmail -d, " +
            "or filter this test out via `--filter Category!=Integration`.");
    }

    private static async Task ProvisionGreenmailUserAsync(string login, string password)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };
        var json = $"{{\"email\":\"{login}@localhost\",\"login\":\"{login}\",\"password\":\"{password}\"}}";
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        try { using var _ = await http.PostAsync($"{ApiBase}/api/user", content); }
        catch { /* greenmail REST is best-effort here — SMTP listener creates the account on delivery anyway. */ }
    }

    private static async Task<(string? Subject, string? HtmlBody, string? TextBody)> ReadFirstMessageAsync(
        string login, string password)
    {
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
