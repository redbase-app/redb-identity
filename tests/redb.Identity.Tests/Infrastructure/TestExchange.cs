using redb.Route.Abstractions;

namespace redb.Identity.Tests.Infrastructure;

/// <summary>
/// Minimal <see cref="IMessage"/> for unit tests.
/// </summary>
internal sealed class TestMessage : IMessage
{
    public object? Body { get; set; }
    public string? ContentType { get; set; }
    public IDictionary<string, object?> Headers { get; } = new Dictionary<string, object?>();

    public T? GetHeader<T>(string key)
        => Headers.TryGetValue(key, out var v) && v is T t ? t : default;

    public IMessage Clone()
    {
        var clone = new TestMessage { Body = Body, ContentType = ContentType };
        foreach (var h in Headers)
            clone.Headers[h.Key] = h.Value;
        return clone;
    }
}

/// <summary>
/// Minimal <see cref="IExchange"/> for unit tests.
/// </summary>
internal sealed class TestExchange : IExchange
{
    public IMessage In { get; set; } = new TestMessage();
    public IMessage? Out { get; set; }
    public ExchangePattern Pattern { get; set; } = ExchangePattern.InOnly;
    public IDictionary<string, object?> Properties { get; } = new Dictionary<string, object?>();
    public T? GetProperty<T>(string key)
        => Properties.TryGetValue(key, out var v) && v is T t ? t : default;
    public Exception? Exception { get; set; }
    public bool ExceptionHandled { get; set; }
    public string? RouteId { get; set; }
    public string ExchangeId { get; } = Guid.NewGuid().ToString();
    public bool IsStopped { get; private set; }
    public void Stop() => IsStopped = true;
    public IExchange Clone() => throw new NotSupportedException("Clone not needed in tests");
    public ValueTask DisposeAsync() => default;
}
