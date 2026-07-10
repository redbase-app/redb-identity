using FluentAssertions;
using MyCSharp.HttpUserAgentParser;
using MyCSharp.HttpUserAgentParser.Providers;
using redb.Identity.Core.Services;
using redb.Route.Abstractions;
using redb.Route.Core;
using Xunit;

namespace redb.Identity.Tests.Services;

public class DeviceMetadataExtractorTests
{
    private static readonly IHttpUserAgentParserProvider Parser = new HttpUserAgentParserDefaultProvider();

    private static IExchange ExchangeWith(string? ua, string? remoteIp)
    {
        var msg = new Message();
        if (ua is not null) msg.Headers["User-Agent"] = ua;
        if (remoteIp is not null) msg.Headers["redbHttp.RemoteAddress"] = remoteIp;
        return new Exchange(msg);
    }

    [Fact]
    public void Null_Exchange_Returns_Empty()
    {
        var result = DeviceMetadataExtractor.Extract(null, Parser);
        result.Should().Be(DeviceMetadata.Empty);
    }

    [Fact]
    public void Chrome_On_Windows_Yields_Friendly_Label()
    {
        const string ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36";
        var ex = ExchangeWith(ua, "203.0.113.7");

        var result = DeviceMetadataExtractor.Extract(ex, Parser);

        result.IpAddress.Should().Be("203.0.113.7");
        result.UserAgent.Should().Be(ua);
        result.DeviceLabel.Should().NotBeNull();
        result.DeviceLabel!.Should().Contain("Chrome").And.Contain("Windows");
    }

    [Fact]
    public void Safari_On_IPhone_Yields_IOS_Label()
    {
        const string ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1";
        var ex = ExchangeWith(ua, "2001:db8::1");

        var result = DeviceMetadataExtractor.Extract(ex, Parser);

        result.DeviceLabel.Should().NotBeNull();
        result.DeviceLabel!.Should().Contain("Safari");
    }

    [Fact]
    public void Empty_UserAgent_Yields_Null_Label()
    {
        var ex = ExchangeWith(ua: "", remoteIp: "10.0.0.5");

        var result = DeviceMetadataExtractor.Extract(ex, Parser);

        result.IpAddress.Should().Be("10.0.0.5");
        result.UserAgent.Should().Be("");
        result.DeviceLabel.Should().BeNull();
    }

    [Fact]
    public void Missing_Parser_Populates_Raw_Fields_But_No_Label()
    {
        const string ua = "Mozilla/5.0 something";
        var ex = ExchangeWith(ua, "1.2.3.4");

        var result = DeviceMetadataExtractor.Extract(ex, parser: null);

        result.IpAddress.Should().Be("1.2.3.4");
        result.UserAgent.Should().Be(ua);
        result.DeviceLabel.Should().BeNull();
    }

    [Fact]
    public void Oversized_UserAgent_Is_Truncated_To_512_Chars()
    {
        var ua = new string('A', 1024);
        var ex = ExchangeWith(ua, "1.2.3.4");

        var result = DeviceMetadataExtractor.Extract(ex, Parser);

        result.UserAgent.Should().NotBeNull();
        result.UserAgent!.Length.Should().Be(512);
    }

    [Fact]
    public void Non_Http_Transport_With_No_Headers_Returns_All_Nulls()
    {
        var ex = ExchangeWith(ua: null, remoteIp: null);

        var result = DeviceMetadataExtractor.Extract(ex, Parser);

        result.IpAddress.Should().BeNull();
        result.UserAgent.Should().BeNull();
        result.DeviceLabel.Should().BeNull();
    }

    [Fact]
    public void Curl_UserAgent_Returns_Snippet_Or_Label_Without_Throwing()
    {
        var ex = ExchangeWith(ua: "curl/8.0.1", remoteIp: "127.0.0.1");

        var result = DeviceMetadataExtractor.Extract(ex, Parser);

        // curl is classified as a "Robot" by ua-parser; we only assert that the extractor
        // produces *some* non-null label (either a parser-derived string or a safe fallback),
        // and that it does not crash or leak the raw UA verbatim beyond 64 chars.
        result.UserAgent.Should().Be("curl/8.0.1");
        result.DeviceLabel.Should().NotBeNullOrWhiteSpace();
    }
}
