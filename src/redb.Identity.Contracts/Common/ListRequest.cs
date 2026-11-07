namespace redb.Identity.Contracts.Common;

/// <summary>
/// Pagination parameters for list operations.
/// </summary>
public class ListRequest
{
    public int Offset { get; set; }
    public int Count { get; set; } = 20;
}
