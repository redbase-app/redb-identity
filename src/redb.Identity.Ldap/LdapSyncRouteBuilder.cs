using Microsoft.Extensions.Logging;
using redb.Route.Core;
using redb.Route.Ldap;
using static redb.Route.Ldap.LdapDsl;

namespace redb.Identity.Ldap;

/// <summary>
/// Route definition that watches an LDAP directory for changes and syncs
/// user profiles (and optionally group memberships) to the Identity system.
/// </summary>
public sealed class LdapSyncRouteBuilder : RouteBuilder
{
    private readonly LdapSyncOptions _options;
    private readonly ILogger<LdapSyncRouteBuilder>? _logger;

    public LdapSyncRouteBuilder(LdapSyncOptions options, ILogger<LdapSyncRouteBuilder>? logger = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _options.Validate();
        _logger = logger;
    }

    protected override void Configure()
    {
        From(BuildWatchUri())
            .RouteId(_options.RouteId)
            .Log($"LDAP sync: ${{header.{LdapHeaders.ChangeType}}} ${{header.{LdapHeaders.Dn}}}")
            .Bean<LdapSyncHandler>(async (handler, exchange, ct) =>
            {
                if (exchange.In.Body is LdapEntry entry)
                {
                    try
                    {
                        await handler.ProcessEntryAsync(entry, ct);
                    }
                    catch (Exception ex) when (ex is not OperationCanceledException)
                    {
                        _logger?.LogError(ex, "Failed to process LDAP entry: {Dn}", entry.Dn);
                    }
                }
                else
                {
                    _logger?.LogDebug("Unexpected body type in sync route: {Type}",
                        exchange.In.Body?.GetType());
                }
            });
    }

    private string BuildWatchUri()
    {
        var builder = Watch(_options.UserBaseDn)
            .Server(_options.Server)
            .Port(_options.Port)
            .Filter(_options.UserFilter)
            .PollInterval(_options.PollIntervalMs)
            .ChangeTracking(ParseChangeTrackingMode());

        if (_options.InitialLoad)
            builder.InitialLoad();

        if (_options.DetectDeletions)
            builder.DetectDeletions();

        if (_options.FullSyncInterval > 0)
            builder.FullSyncInterval(_options.FullSyncInterval);

        // Connection settings
        if (!string.IsNullOrWhiteSpace(_options.BindDn))
            builder.BindDn(_options.BindDn);

        if (!string.IsNullOrWhiteSpace(_options.BindPassword))
            builder.BindPassword(_options.BindPassword);

        if (_options.UseSsl)
            builder.Ssl();

        if (_options.UseStartTls)
            builder.StartTls();

        if (_options.SkipCertificateValidation)
            builder.SkipCertificateValidation();

        if (_options.Attributes.Length > 0)
            builder.Attributes(_options.Attributes);

        return builder.Build();
    }

    private LdapChangeTrackingMode ParseChangeTrackingMode() =>
        _options.ChangeTrackingMode?.ToLowerInvariant() switch
        {
            "modifytimestamp" => LdapChangeTrackingMode.ModifyTimestamp,
            "usn" => LdapChangeTrackingMode.Usn,
            "persistent" => LdapChangeTrackingMode.Persistent,
            _ => throw new InvalidOperationException(
                $"Unknown ChangeTrackingMode: '{_options.ChangeTrackingMode}'.")
        };
}
