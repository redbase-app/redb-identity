namespace redb.Identity.Contracts.Common;

/// <summary>
/// Paginated result wrapper.
/// </summary>
public class PagedResult<T>
{
    public required List<T> Items { get; set; }
    public int Total { get; set; }
    public int Offset { get; set; }
    public int Count { get; set; }
}
