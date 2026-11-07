namespace redb.Identity.Tests.V4Unique;

// The former ResetBackfillConvergenceAsync helper is gone on purpose: resetting the shared
// convergence flag RACED parallel test classes and fixture boots (a neighbour's pass
// re-writes the flag between our reset and our run — exactly the ordering-dependent
// failures of 2026-09-08). And a full gate-free pass raced too: parallel classes each
// repairing ALL schemes collided on each other's rows (false-duplicate unique collisions,
// stale-snapshot overwrites). The backfill tests therefore call the single-scheme seams
// (V4UniqueBackfillListener.Run*SchemeAsync) — no flag manipulation, no foreign rows.

/// <summary>
/// Routes ILogger output into xunit's per-test output (Console is swallowed by the
/// runner). Lets the backfill listener's candidates/repaired/duplicates counters and
/// scheme-level errors show up in a failing test's log.
/// </summary>
internal sealed class XunitTestLoggerProvider : Microsoft.Extensions.Logging.ILoggerProvider
{
    private readonly Xunit.Abstractions.ITestOutputHelper _out;
    public XunitTestLoggerProvider(Xunit.Abstractions.ITestOutputHelper output) => _out = output;
    public Microsoft.Extensions.Logging.ILogger CreateLogger(string categoryName) => new XunitLogger(_out, categoryName);
    public void Dispose() { }

    private sealed class XunitLogger : Microsoft.Extensions.Logging.ILogger
    {
        private readonly Xunit.Abstractions.ITestOutputHelper _out;
        private readonly string _cat;
        public XunitLogger(Xunit.Abstractions.ITestOutputHelper output, string cat) { _out = output; _cat = cat; }
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(Microsoft.Extensions.Logging.LogLevel logLevel) => true;
        public void Log<TState>(Microsoft.Extensions.Logging.LogLevel level, Microsoft.Extensions.Logging.EventId id,
            TState state, Exception? ex, Func<TState, Exception?, string> fmt)
        {
            try { _out.WriteLine($"[{level}] {_cat}: {fmt(state, ex)}{(ex is null ? "" : $" | EX: {ex}")}"); }
            catch { /* output already disposed - the run is over */ }
        }
    }
}
