using System.Collections.Immutable;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using NSubstitute;
using redb.Identity.Core.Configuration;
using redb.Identity.Core.Keys;
using redb.Identity.Core.Module;
using redb.Route.Abstractions;
using Xunit;

namespace redb.Identity.Tests.Configuration;

/// <summary>
/// What the props signing-key store is seeded with at context start. OpenIddict encrypts authorization
/// codes, refresh tokens, device and user codes and its own state tokens whatever
/// <see cref="RedbIdentityOptions.DisableAccessTokenEncryption"/> says (that option leaves only access
/// tokens as plain JWS) and refuses to build its options without an encryption credential. A store seeded
/// with a signing key and no encryption key is therefore a server that cannot start, so the listener seeds
/// both kinds unconditionally.
/// </summary>
public sealed class SigningKeyInitListenerTests
{
    [Fact]
    public async Task Seeds_the_encryption_key_even_when_access_token_encryption_is_disabled()
    {
        var store = Substitute.For<ISigningKeyStore>();
        store.GetAllAsync(Arg.Any<CancellationToken>()).Returns(ImmutableArray<SigningKeyMaterial>.Empty);

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(Options.Create(new RedbIdentityOptions
        {
            UsePropsSigningKeyStore = true,
            DisableAccessTokenEncryption = true,
        }));
        services.AddSingleton(store);
        await using var sp = services.BuildServiceProvider();

        await new SigningKeyInitListener(sp).OnContextStarting(Substitute.For<IRouteContext>(), CancellationToken.None);

        await store.Received(1).EnsureBootstrappedAsync("signing", Arg.Any<CancellationToken>());
        await store.Received(1).EnsureBootstrappedAsync("encryption", Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Does_nothing_when_the_props_store_is_off()
    {
        var store = Substitute.For<ISigningKeyStore>();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(Options.Create(new RedbIdentityOptions { UsePropsSigningKeyStore = false }));
        services.AddSingleton(store);
        await using var sp = services.BuildServiceProvider();

        await new SigningKeyInitListener(sp).OnContextStarting(Substitute.For<IRouteContext>(), CancellationToken.None);

        await store.DidNotReceive().EnsureBootstrappedAsync(Arg.Any<string>(), Arg.Any<CancellationToken>());
    }
}
