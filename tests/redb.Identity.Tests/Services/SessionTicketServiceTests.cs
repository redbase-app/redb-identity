using FluentAssertions;
using Microsoft.AspNetCore.DataProtection;
using redb.Identity.Http.Security;
using Xunit;

namespace redb.Identity.Tests.Services;

public class SessionTicketServiceTests
{
    private readonly SessionTicketService _sut;

    public SessionTicketServiceTests()
    {
        var provider = new EphemeralDataProtectionProvider();
        _sut = new SessionTicketService(provider);
    }

    [Fact]
    public void Protect_Unprotect_RoundTrip()
    {
        var ticket = _sut.Protect(42, 100, "admin");
        ticket.Should().NotBeNullOrEmpty();

        var result = _sut.Unprotect(ticket, TimeSpan.FromHours(1));
        result.Should().NotBeNull();
        result!.UserId.Should().Be(42);
        result.SessionId.Should().Be(100);
        result.Username.Should().Be("admin");
    }

    [Fact]
    public void Unprotect_ExpiredTicket_ReturnsNull()
    {
        var ticket = _sut.Protect(1, 10, "user");

        // MaxAge=0 means any ticket is expired immediately
        var result = _sut.Unprotect(ticket, TimeSpan.Zero);
        result.Should().BeNull();
    }

    [Fact]
    public void Unprotect_TamperedTicket_ReturnsNull()
    {
        var ticket = _sut.Protect(1, 10, "user");
        var tampered = ticket + "AAAA";

        var result = _sut.Unprotect(tampered, TimeSpan.FromHours(1));
        result.Should().BeNull();
    }

    [Fact]
    public void Unprotect_GarbageInput_ReturnsNull()
    {
        var result = _sut.Unprotect("not-a-valid-ticket", TimeSpan.FromHours(1));
        result.Should().BeNull();
    }

    [Fact]
    public void Protect_DifferentUsers_ProduceDifferentTickets()
    {
        var t1 = _sut.Protect(1, 10, "alice");
        var t2 = _sut.Protect(2, 20, "bob");
        t1.Should().NotBe(t2);
    }

    [Fact]
    public void Unprotect_WithinMaxAge_Succeeds()
    {
        var ticket = _sut.Protect(99, 50, "longuser");
        var result = _sut.Unprotect(ticket, TimeSpan.FromHours(8));
        result.Should().NotBeNull();
        result!.UserId.Should().Be(99);
    }

    [Fact]
    public void Protect_UnicodeUsername_RoundTrips()
    {
        var ticket = _sut.Protect(7, 77, "Zoë-Café-user");
        var result = _sut.Unprotect(ticket, TimeSpan.FromHours(1));
        result.Should().NotBeNull();
        result!.Username.Should().Be("Zoë-Café-user");
    }

    [Fact]
    public void Protect_V2_SessionId_RoundTrips()
    {
        var ticket = _sut.Protect(42, 999, "admin");
        var result = _sut.Unprotect(ticket, TimeSpan.FromHours(1));
        result.Should().NotBeNull();
        result!.UserId.Should().Be(42);
        result.SessionId.Should().Be(999);
        result.Username.Should().Be("admin");
    }

    [Fact]
    public void Protect_V2_ZeroSessionId_RoundTrips()
    {
        var ticket = _sut.Protect(42, 0, "admin");
        var result = _sut.Unprotect(ticket, TimeSpan.FromHours(1));
        result.Should().NotBeNull();
        result!.SessionId.Should().Be(0);
    }
}
