using Xunit;

namespace redb.Identity.Tests.Infrastructure;

[CollectionDefinition("Postgres")]
public class PostgresCollection : ICollectionFixture<PostgresFixture>
{
}
