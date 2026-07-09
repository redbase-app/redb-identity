using Microsoft.Extensions.Logging;
using redb.Core;
using redb.Core.Models.Contracts;
using redb.Core.Models.Entities;
using redb.Core.Models.Users;
using redb.Core.Query;
using redb.Identity.Core.Models;
using redb.Identity.Core.Services;
using redb.Route.Ldap;

namespace redb.Identity.Ldap;

/// <summary>
/// Processes LDAP change events from the Watch consumer.
/// Creates/updates/disables users and optionally syncs group memberships.
/// Designed to be resolved from DI via <c>Bean&lt;LdapSyncHandler&gt;</c> in the route.
/// </summary>
public sealed class LdapSyncHandler
{
    private readonly IRedbService _redb;
    private readonly LdapSyncOptions _options;
    private readonly LdapAttributeMapper _mapper;
    private readonly LdapGroupMapper? _groupMapper;
    private readonly ILogger<LdapSyncHandler> _logger;
    private readonly TimeProvider _timeProvider;

    public LdapSyncHandler(
        IRedbService redb,
        LdapSyncOptions options,
        ILogger<LdapSyncHandler> logger,
        LdapGroupMapper? groupMapper = null,
        TimeProvider? timeProvider = null)
    {
        _redb = redb ?? throw new ArgumentNullException(nameof(redb));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _groupMapper = groupMapper;
        _timeProvider = timeProvider ?? TimeProvider.System;

        var mapperOptions = new LdapProviderOptions
        {
            UserBaseDn = "dc=sync", // placeholder — mapper only uses AttributeMap
            AttributeMap = options.AttributeMap,
            AdditionalClaimsMap = options.AdditionalClaimsMap
        };
        _mapper = new LdapAttributeMapper(mapperOptions);
    }

    /// <summary>
    /// Process a single LDAP change entry.
    /// </summary>
    public async Task ProcessEntryAsync(LdapEntry entry, CancellationToken ct = default)
    {
        if (entry is null) return;

        var changeType = entry.ChangeType ?? "modified";

        _logger.LogDebug("Processing LDAP sync event: {ChangeType} {Dn}", changeType, entry.Dn);

        switch (changeType)
        {
            case "added":
            case "modified":
                await UpsertUserAsync(entry, ct).ConfigureAwait(false);
                break;

            case "deleted":
                await HandleDeletionAsync(entry, ct).ConfigureAwait(false);
                break;

            default:
                _logger.LogWarning("Unknown LDAP change type: {ChangeType} for DN={Dn}", changeType, entry.Dn);
                break;
        }
    }

    private async Task UpsertUserAsync(LdapEntry entry, CancellationToken ct)
    {
        var authResult = _mapper.MapToResult(entry);
        var externalId = authResult.ExternalId ?? entry.Dn;

        // Find existing user by external ID stored in UserProps
        var existingProps = await _redb.Query<UserProps>()
            .WhereRedb(o => o.ValueString == $"{_options.ProviderName}:{externalId}")
            .FirstOrDefaultAsync()
            .ConfigureAwait(false);

        IRedbUser coreUser;

        if (existingProps is not null)
        {
            // Update existing user
            var userId = existingProps.key
                ?? throw new InvalidOperationException("Sync props has null key.");
            coreUser = await _redb.UserProvider.GetUserByIdAsync(userId)
                .ConfigureAwait(false)
                ?? throw new InvalidOperationException(
                    $"User id={userId} referenced by sync props but not found in _users.");

            var updateReq = new UpdateUserRequest();
            var needsUpdate = false;

            if (authResult.DisplayName is not null && authResult.DisplayName != coreUser.Name)
            { updateReq.Name = authResult.DisplayName; needsUpdate = true; }
            if (authResult.Email is not null && authResult.Email != coreUser.Email)
            { updateReq.Email = authResult.Email; needsUpdate = true; }
            if (authResult.Phone is not null && authResult.Phone != coreUser.Phone)
            { updateReq.Phone = authResult.Phone; needsUpdate = true; }

            if (needsUpdate)
                await _redb.UserProvider.UpdateUserAsync(coreUser, updateReq).ConfigureAwait(false);

            _logger.LogDebug("Synced existing user '{ExternalId}' (id={UserId})", externalId, coreUser.Id);
        }
        else
        {
            // Create new user
            var login = externalId;
            coreUser = await _redb.UserProvider.CreateUserAsync(new CreateUserRequest
            {
                Login = login,
                Password = Guid.NewGuid().ToString("N") + "Aa1!",
                Name = authResult.DisplayName ?? login,
                Email = authResult.Email,
                Phone = authResult.Phone,
                Enabled = true,
                CodeString = _options.ProviderName
            }).ConfigureAwait(false);

            _logger.LogInformation("Created user '{ExternalId}' (id={UserId}) from LDAP sync",
                externalId, coreUser.Id);
        }

        // Upsert UserProps with sync marker
        // S12: skip fallback query for newly created users (existingProps is null + user just created)
        RedbObject<UserProps>? oidcObj;
        if (existingProps is not null)
        {
            oidcObj = existingProps;
        }
        else if (existingProps is null && coreUser is not null)
        {
            // New user: create props directly, skip query for just-created user
            oidcObj = new RedbObject<UserProps>(new UserProps());
            oidcObj.name = externalId;
            oidcObj.key = coreUser.Id;
            oidcObj.value_guid = Guid.NewGuid();
        }
        else
        {
            oidcObj = new RedbObject<UserProps>(new UserProps());
            oidcObj.name = externalId;
            oidcObj.key = coreUser!.Id;
            oidcObj.value_guid = Guid.NewGuid();
        }

        oidcObj.Props.ExternalIdentities ??= new Dictionary<string, ExternalIdentity>();
        oidcObj.Props.ExternalIdentities[_options.ProviderName] = new ExternalIdentity
        {
            Sub = externalId,
            LinkedAt = _timeProvider.GetUtcNow()
        };
        oidcObj.value_string = $"{_options.ProviderName}:{externalId}"; // sync lookup key
        oidcObj.note = entry.Dn; // store DN for deletion lookup

        if (authResult.GivenName is not null) oidcObj.Props.GivenName = authResult.GivenName;
        if (authResult.FamilyName is not null) oidcObj.Props.FamilyName = authResult.FamilyName;

        if (authResult.AdditionalClaims is { Count: > 0 })
        {
            oidcObj.Props.CustomClaims ??= new Dictionary<string, string>();
            foreach (var (key, value) in authResult.AdditionalClaims)
                oidcObj.Props.CustomClaims[key] = value;
        }

        await _redb.SaveAsync(oidcObj).ConfigureAwait(false);

        // Group sync
        if (_options.SyncGroups && _groupMapper is not null)
        {
            await _groupMapper.SyncUserGroupsAsync(coreUser.Id, entry, ct).ConfigureAwait(false);
        }
    }

    private async Task HandleDeletionAsync(LdapEntry entry, CancellationToken ct)
    {
        if (!_options.DisableDeletedUsers) return;

        // Try to extract externalId from entry attributes (if available)
        var authResult = entry.Attributes?.Count > 0 ? _mapper.MapToResult(entry) : null;
        var externalId = authResult?.ExternalId;

        RedbObject<UserProps>? props = null;

        // Primary: search by externalId (entry with attributes)
        if (externalId is not null)
        {
            props = await _redb.Query<UserProps>()
                .WhereRedb(o => o.ValueString == $"{_options.ProviderName}:{externalId}")
                .FirstOrDefaultAsync()
                .ConfigureAwait(false);
        }

        // Fallback: search by DN stored in note (deletion event — only DN available)
        if (props is null)
        {
            props = await _redb.Query<UserProps>()
                .WhereRedb(o => o.Note == entry.Dn
                    && o.ValueString!.StartsWith($"{_options.ProviderName}:"))
                .FirstOrDefaultAsync()
                .ConfigureAwait(false);
        }

        if (props?.key is not { } deletedUserId)
        {
            _logger.LogWarning("No local user found for deleted LDAP entry: {Dn}", entry.Dn);
            return;
        }

        var user = await _redb.UserProvider.GetUserByIdAsync(deletedUserId).ConfigureAwait(false);
        if (user is null || !user.Enabled) return;

        await _redb.UserProvider.UpdateUserAsync(user, new UpdateUserRequest { Enabled = false })
            .ConfigureAwait(false);

        _logger.LogInformation("Disabled user '{Login}' (id={UserId}) — deleted from LDAP",
            user.Login, user.Id);
    }
}
