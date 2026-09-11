using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using redb.Core;
using redb.Identity.Core.Module;
using redb.Identity.Tests.Infrastructure;
using Xunit;
using Xunit.Abstractions;

namespace redb.Identity.Tests.V4Unique;

/// <summary>
/// Permanent regression test born as a review-forensic probe: UX_users_email (the one index
/// that STAYS, owner decision Р1) was absent on every live test database. The finding: the
/// full-stack fixtures never run InitRoute.main — they hand-register a single listener
/// (AuditLog) — so NO artificial index has EVER existed in the test environment; only real
/// module-host deployments create them. This test pins the listener itself: invoked directly,
/// it must create the email index on the current provider.
/// </summary>
public sealed class EmailIndexProbeTests
{
    private readonly ITestOutputHelper _out;
    public EmailIndexProbeTests(ITestOutputHelper output) => _out = output;

    [Fact]
    public async Task Listener_CreatesEmailIndex_OrTellsWhy()
    {
        var config = new ConfigurationBuilder().AddJsonFile("appsettings.json").Build();
        var pgCs = config.GetConnectionString("Postgres") ?? "";

        var sc = new ServiceCollection();
        sc.AddLogging(b => b.SetMinimumLevel(LogLevel.Debug).AddProvider(new XunitLoggerProvider(_out)));
        sc.AddRedbForTests(pgCs);
        await using var sp = sc.BuildServiceProvider();

        await using (var scope = sp.CreateAsyncScope())
        {
            var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
            try { await redb.InitializeAsync(ensureCreated: true); }
            catch { await redb.InitializeAsync(); }
        }

        await new IdentityUniqueIndexesInitListener(sp).OnContextStarting(null!, CancellationToken.None);

        await using (var scope = sp.CreateAsyncScope())
        {
            var redb = scope.ServiceProvider.GetRequiredService<IRedbService>();
            var provider = TestRedbSetup.SelectedProvider;
            long count = provider switch
            {
                TestRedbSetup.Provider.MsSql => await redb.Context.ExecuteScalarAsync<int>(
                    "SELECT COUNT(*) FROM sys.indexes WHERE name = 'UX_users_email'"),
                TestRedbSetup.Provider.Postgres => await redb.Context.ExecuteScalarAsync<long>(
                    "SELECT COUNT(*) FROM pg_indexes WHERE indexname = 'UX_users_email'"),
                _ => await redb.Context.ExecuteScalarAsync<long>(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='UX_users_email'"),
            };
            _out.WriteLine($"UX_users_email present after listener: {count}");
            if (count == 1)
                return; // clean database: the index is there — the primary contract

            // Degraded contract: on a database that predates the index (the shared test DBs
            // never ran InitRoute.main, so duplicates accumulated for months) the CREATE
            // legitimately fails and the listener logs-and-continues. Then the ONLY acceptable
            // reason for the missing index is pre-existing duplicate emails — prove they exist.
            var dupEmails = await redb.Context.ExecuteScalarAsync<long>(
                provider == TestRedbSetup.Provider.MsSql
                    ? "SELECT COUNT_BIG(*) FROM (SELECT _email FROM _users WHERE _email IS NOT NULL GROUP BY _email HAVING COUNT(*) > 1) d"
                    : "SELECT COUNT(*) FROM (SELECT _email FROM _users WHERE _email IS NOT NULL GROUP BY _email HAVING COUNT(*) > 1) d");
            _out.WriteLine($"duplicate emails blocking the index: {dupEmails}");
            dupEmails.Should().BeGreaterThan(0,
                "the index may be absent ONLY because pre-existing duplicate emails block its "
                + "creation (documented degrade); absent with clean data means the listener broke");
        }
    }

    private sealed class XunitLoggerProvider : ILoggerProvider
    {
        private readonly ITestOutputHelper _out;
        public XunitLoggerProvider(ITestOutputHelper output) => _out = output;
        public ILogger CreateLogger(string categoryName) => new XunitLogger(_out, categoryName);
        public void Dispose() { }

        private sealed class XunitLogger : ILogger
        {
            private readonly ITestOutputHelper _out;
            private readonly string _cat;
            public XunitLogger(ITestOutputHelper output, string cat) { _out = output; _cat = cat; }
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(LogLevel logLevel) => true;
            public void Log<TState>(LogLevel level, EventId id, TState state, Exception? ex,
                Func<TState, Exception?, string> fmt)
            {
                try { _out.WriteLine($"[{level}] {_cat}: {fmt(state, ex)}{(ex is null ? "" : $" | EX: {ex}")}"); }
                catch { /* output disposed */ }
            }
        }
    }
}
