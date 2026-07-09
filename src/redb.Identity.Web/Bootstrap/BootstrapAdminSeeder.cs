using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using redb.Identity.Web.Configuration;

namespace redb.Identity.Web.Bootstrap;

/// <summary>
/// Once-per-cluster startup task that calls Identity's <c>/internal/bootstrap-admin</c>
/// endpoint with <c>X-Bootstrap-Secret</c>. Idempotent: 410 Gone on repeat is treated as success.
/// Disabled by default; turn on via <c>Bootstrap:Enabled=true</c> + supply secret via env/user-secrets.
/// </summary>
public sealed class BootstrapAdminSeeder : BackgroundService
{
    private readonly IOptions<BootstrapOptions> _opts;
    private readonly IHttpClientFactory _httpFactory;
    private readonly ILogger<BootstrapAdminSeeder> _log;
    private readonly IHostApplicationLifetime _lifetime;

    public BootstrapAdminSeeder(
        IOptions<BootstrapOptions> opts,
        IHttpClientFactory httpFactory,
        ILogger<BootstrapAdminSeeder> log,
        IHostApplicationLifetime lifetime)
    {
        _opts = opts;
        _httpFactory = httpFactory;
        _log = log;
        _lifetime = lifetime;
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        var startedTcs = new TaskCompletionSource();
        await using var reg = _lifetime.ApplicationStarted.Register(() => startedTcs.TrySetResult());
        await startedTcs.Task.WaitAsync(ct);

        var b = _opts.Value;
        if (!b.Enabled)
        {
            _log.LogInformation("Bootstrap disabled — skipping admin seeding");
            return;
        }
        if (string.IsNullOrEmpty(b.Secret))
        {
            _log.LogError("Bootstrap.Enabled=true but Secret is empty — set IDENTITY__BOOTSTRAP__SECRET. Skipping.");
            return;
        }
        if (string.IsNullOrEmpty(b.Endpoint))
        {
            _log.LogError("Bootstrap.Endpoint is empty — skipping");
            return;
        }

        const int maxAttempts = 10;
        var delay = TimeSpan.FromSeconds(2);
        for (var attempt = 1; attempt <= maxAttempts && !ct.IsCancellationRequested; attempt++)
        {
            try
            {
                if (await TryBootstrapAsync(ct)) return;
            }
            catch (HttpRequestException ex)
            {
                _log.LogWarning(ex, "Bootstrap attempt {Attempt}/{Max} failed (Identity may not be ready) — retrying in {Delay}",
                    attempt, maxAttempts, delay);
            }
            await Task.Delay(delay, ct);
            delay = TimeSpan.FromSeconds(Math.Min(delay.TotalSeconds * 1.5, 30));
        }

        _log.LogError("Bootstrap gave up after {Max} attempts", maxAttempts);
    }

    private async Task<bool> TryBootstrapAsync(CancellationToken ct)
    {
        var b = _opts.Value;
        var http = _httpFactory.CreateClient("Bootstrap");
        http.Timeout = TimeSpan.FromSeconds(30);

        using var req = new HttpRequestMessage(HttpMethod.Post, b.Endpoint);
        req.Headers.Add("X-Bootstrap-Secret", b.Secret);
        req.Content = JsonContent.Create(new { });

        using var resp = await http.SendAsync(req, ct);

        if (resp.StatusCode == HttpStatusCode.Gone)
        {
            _log.LogInformation("Bootstrap already completed — Identity returned 410 Gone");
            return true;
        }

        if (resp.StatusCode == HttpStatusCode.Created)
        {
            var body = await resp.Content.ReadAsStringAsync(ct);
            _log.LogWarning("=== BOOTSTRAP COMPLETE — STORE THE CLIENT_SECRET FROM THE PAYLOAD BELOW ===");
            _log.LogWarning("{Body}", body);
            _log.LogWarning("=== Persist client_secret to user-secrets / Vault — Identity will NOT show it again ===");
            return true;
        }

        var errBody = await resp.Content.ReadAsStringAsync(ct);
        _log.LogError("Bootstrap failed: HTTP {Status} {Body}", (int)resp.StatusCode, errBody);
        return false;
    }
}
