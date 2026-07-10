using System.Collections.Immutable;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using redb.Core.Models.Entities;
using redb.Core.Query;
using redb.Identity.Core.Models;
using redb.Identity.Tests.Infrastructure;
using Xunit;
using Xunit.Abstractions;

namespace redb.Identity.Tests.Bugs;

/// <summary>
/// Direct OpenIddict manager test to isolate the 4-scopes DbException.
/// Uses the production bootstrap fixture's service provider to access managers directly.
/// </summary>
[Collection("ProductionBootstrap")]
public class FourScopesManagerTest
{
    private readonly ProductionBootstrapFixture _fx;
    private readonly ITestOutputHelper _output;

    public FourScopesManagerTest(ProductionBootstrapFixture fx, ITestOutputHelper output)
    {
        _fx = fx;
        _output = output;
    }

    [Theory]
    [InlineData("openid profile email", "3 scopes")]
    [InlineData("openid profile email phone", "4 scopes")]
    public async Task CreateAuthorization_ViaManager(string scopeStr, string label)
    {
        _output.WriteLine($"Testing {label}: {scopeStr}");
        var scopes = scopeStr.Split(' ');

        var authManager = _fx.ServiceProvider.GetRequiredService<IOpenIddictAuthorizationManager>();
        var appManager = _fx.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

        // Find the test app
        var app = await appManager.FindByClientIdAsync(ProductionBootstrapFixture.TestClientIdPublic)
            ?? throw new Exception("Test app not found");
        var appId = await appManager.GetIdAsync(app);
        _output.WriteLine($"  App id: {appId}");

        // Find test user — the OpenIddict subject is now the user's value_guid.
        var coreUser = await _fx.Redb.UserProvider.GetUserByLoginAsync(ProductionBootstrapFixture.TestUsername)
            ?? throw new Exception("Test user not found");
        var oidcObj = await _fx.Redb.Query<UserProps>()
            .WhereRedb(o => o.Key == coreUser.Id)
            .FirstOrDefaultAsync()
            ?? throw new Exception($"UserProps row missing for user {coreUser.Id} — bootstrap should seed value_guid");
        if (oidcObj.value_guid is null || oidcObj.value_guid == Guid.Empty)
            throw new Exception("UserProps.value_guid not set — bootstrap must populate the per-user GUID");
        var userId = oidcObj.value_guid.Value.ToString("D");
        _output.WriteLine($"  User id (bigint): {coreUser.Id}");
        _output.WriteLine($"  Subject (GUID):   {userId}");

        try
        {
            // Step 1: FindAsync (same as OpenIddict's ProcessSignIn)
            _output.WriteLine("  Step 1: FindAsync...");
            var existing = new List<object>();
            await foreach (var auth in authManager.FindAsync(
                userId, appId,
                OpenIddictConstants.Statuses.Valid,
                OpenIddictConstants.AuthorizationTypes.Permanent,
                scopes.ToImmutableArray()))
            {
                existing.Add(auth);
            }
            _output.WriteLine($"  FindAsync returned {existing.Count} results");

            // Step 2: CreateAsync (same as OpenIddict's ProcessSignIn when no existing auth)
            _output.WriteLine("  Step 2: CreateAsync...");
            var descriptor = new OpenIddictAuthorizationDescriptor
            {
                ApplicationId = appId,
                Subject = userId,
                Status = OpenIddictConstants.Statuses.Valid,
                Type = OpenIddictConstants.AuthorizationTypes.Permanent,
            };
            foreach (var scope in scopes)
                descriptor.Scopes.Add(scope);

            var created = await authManager.CreateAsync(descriptor);
            var createdId = await authManager.GetIdAsync(created);
            _output.WriteLine($"  Created authorization id={createdId}");

            // Step 3: Load it back
            _output.WriteLine("  Step 3: FindByIdAsync...");
            var loaded = await authManager.FindByIdAsync(createdId!);
            loaded.Should().NotBeNull();
            _output.WriteLine($"  Loaded successfully");

            // Cleanup
            await authManager.DeleteAsync(created);
            _output.WriteLine($"  Cleaned up");
        }
        catch (Exception ex)
        {
            _output.WriteLine("=== EXCEPTION ===");
            var current = ex;
            int depth = 0;
            while (current != null)
            {
                _output.WriteLine($"--- Depth {depth} ---");
                _output.WriteLine($"Type: {current.GetType().FullName}");
                _output.WriteLine($"Message: {current.Message}");
                _output.WriteLine($"Stack:\n{current.StackTrace}");
                current = current.InnerException;
                depth++;
            }
            throw;
        }
    }

    [Fact]
    public async Task CreateToken_WithFourScopeAuthorization()
    {
        _output.WriteLine("Testing: create token referencing 4-scope authorization");
        var scopes = new[] { "openid", "profile", "email", "phone" };

        var authManager = _fx.ServiceProvider.GetRequiredService<IOpenIddictAuthorizationManager>();
        var tokenManager = _fx.ServiceProvider.GetRequiredService<IOpenIddictTokenManager>();
        var appManager = _fx.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

        var app = await appManager.FindByClientIdAsync(ProductionBootstrapFixture.TestClientIdPublic)
            ?? throw new Exception("Test app not found");
        var appId = await appManager.GetIdAsync(app);

        var coreUser = await _fx.Redb.UserProvider.GetUserByLoginAsync(ProductionBootstrapFixture.TestUsername)
            ?? throw new Exception("Test user not found");
        var oidcObj = await _fx.Redb.Query<UserProps>()
            .WhereRedb(o => o.Key == coreUser.Id)
            .FirstOrDefaultAsync()
            ?? throw new Exception($"UserProps row missing for user {coreUser.Id}");
        if (oidcObj.value_guid is null || oidcObj.value_guid == Guid.Empty)
            throw new Exception("UserProps.value_guid not set");
        var userId = oidcObj.value_guid.Value.ToString("D");

        object? auth = null;
        object? token = null;

        try
        {
            // Create authorization with 4 scopes
            _output.WriteLine("  Creating authorization with 4 scopes...");
            var authDescriptor = new OpenIddictAuthorizationDescriptor
            {
                ApplicationId = appId,
                Subject = userId,
                Status = OpenIddictConstants.Statuses.Valid,
                Type = OpenIddictConstants.AuthorizationTypes.AdHoc,
            };
            foreach (var scope in scopes)
                authDescriptor.Scopes.Add(scope);
            auth = await authManager.CreateAsync(authDescriptor);
            var authId = await authManager.GetIdAsync(auth);
            _output.WriteLine($"  Authorization created: {authId}");

            // Create token referencing this authorization
            _output.WriteLine("  Creating token...");
            var tokenDescriptor = new OpenIddictTokenDescriptor
            {
                ApplicationId = appId,
                AuthorizationId = authId,
                Subject = userId,
                Status = OpenIddictConstants.Statuses.Valid,
                Type = OpenIddictConstants.TokenTypeHints.AuthorizationCode,
            };
            token = await tokenManager.CreateAsync(tokenDescriptor);
            var tokenId = await tokenManager.GetIdAsync(token);
            _output.WriteLine($"  Token created: {tokenId}");

            // Now try to find the token by authorization
            _output.WriteLine("  Finding tokens by authorization...");
            var tokens = new List<object>();
            await foreach (var t in tokenManager.FindByAuthorizationIdAsync(authId!))
                tokens.Add(t);
            _output.WriteLine($"  Found {tokens.Count} tokens");

            // Cleanup
            if (token != null) await tokenManager.DeleteAsync(token);
            if (auth != null) await authManager.DeleteAsync(auth);
            _output.WriteLine("  Cleaned up");
        }
        catch (Exception ex)
        {
            _output.WriteLine("=== EXCEPTION ===");
            var current = ex;
            while (current != null)
            {
                _output.WriteLine($"Type: {current.GetType().FullName}");
                _output.WriteLine($"Message: {current.Message}");
                _output.WriteLine($"Stack:\n{current.StackTrace}");
                current = current.InnerException;
            }

            // Try cleanup even on failure
            try { if (token != null) await tokenManager.DeleteAsync(token); } catch { }
            try { if (auth != null) await authManager.DeleteAsync(auth); } catch { }
            throw;
        }
    }
}
