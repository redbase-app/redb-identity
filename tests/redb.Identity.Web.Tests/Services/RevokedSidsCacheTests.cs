using FluentAssertions;
using redb.Identity.Contracts.Sessions;
using redb.Identity.Web.Services;
using Xunit;

namespace redb.Identity.Web.Tests.Services;

/// <summary>
/// W6-0 unit tests for <see cref="RevokedSidsCache"/>. Validates blacklist semantics:
/// expired entries are ignored, sid and sub indexes are independent, cursor advances
/// monotonically.
/// </summary>
public sealed class RevokedSidsCacheTests
{
    private static RevokedSidEntry Entry(
        string? sid, string? sub, DateTimeOffset expires, DateTimeOffset? revokedAt = null)
        => new()
        {
            Sid = sid,
            Sub = sub,
            ClientId = null,
            RevokedAt = revokedAt ?? DateTimeOffset.UtcNow,
            ExpiresAt = expires,
        };

    [Fact]
    public void New_cache_has_no_cursor_and_revokes_nothing()
    {
        var cache = new RevokedSidsCache();
        cache.Cursor.Should().BeNull();
        cache.IsRevoked("any-sid", "any-sub").Should().BeFalse();
    }

    [Fact]
    public void Apply_sid_entry_makes_IsRevoked_true_for_that_sid_only()
    {
        var cache = new RevokedSidsCache();
        var future = DateTimeOffset.UtcNow.AddHours(1);

        cache.Apply(new[] { Entry("sid-1", null, future) });

        cache.IsRevoked("sid-1", null).Should().BeTrue();
        cache.IsRevoked("sid-2", null).Should().BeFalse();
        cache.IsRevoked(null, "user-1").Should().BeFalse();
    }

    [Fact]
    public void Apply_sub_only_entry_revokes_all_sessions_for_sub()
    {
        var cache = new RevokedSidsCache();
        var future = DateTimeOffset.UtcNow.AddHours(1);

        cache.Apply(new[] { Entry(null, "user-42", future) });

        cache.IsRevoked(null, "user-42").Should().BeTrue();
        // Any sid presented alongside user-42 is also dropped.
        cache.IsRevoked("random-sid", "user-42").Should().BeTrue();
        cache.IsRevoked(null, "user-99").Should().BeFalse();
    }

    [Fact]
    public void Expired_entries_are_ignored_on_apply()
    {
        var cache = new RevokedSidsCache();
        var past = DateTimeOffset.UtcNow.AddMinutes(-1);

        cache.Apply(new[] { Entry("expired-sid", "expired-sub", past) });

        cache.IsRevoked("expired-sid", null).Should().BeFalse();
        cache.IsRevoked(null, "expired-sub").Should().BeFalse();
    }

    [Fact]
    public void SetCursor_is_monotonic()
    {
        var cache = new RevokedSidsCache();
        var t1 = DateTimeOffset.UtcNow;
        var t2 = t1.AddSeconds(10);

        cache.SetCursor(t2);
        cache.Cursor.Should().Be(t2);

        // Older cursor must not overwrite newer one.
        cache.SetCursor(t1);
        cache.Cursor.Should().Be(t2);
    }

    [Fact]
    public void Apply_takes_max_expiry_when_same_sid_appears_twice()
    {
        var cache = new RevokedSidsCache();
        var earlier = DateTimeOffset.UtcNow.AddMinutes(5);
        var later = DateTimeOffset.UtcNow.AddHours(2);

        cache.Apply(new[]
        {
            Entry("sid-x", null, earlier),
            Entry("sid-x", null, later),
        });

        cache.IsRevoked("sid-x", null).Should().BeTrue();

        // Apply an older expiry — must not shorten the existing window.
        cache.Apply(new[] { Entry("sid-x", null, earlier) });
        cache.IsRevoked("sid-x", null).Should().BeTrue();
    }
}
