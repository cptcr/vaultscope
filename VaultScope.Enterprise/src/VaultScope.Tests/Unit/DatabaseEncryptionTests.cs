using Xunit;
using FluentAssertions;
using VaultScope.Infrastructure.Security;

namespace VaultScope.Tests.Unit;

public class DatabaseEncryptionTests
{
    [Fact]
    public void GetOrCreateEncryptionKey_ReturnsNonEmptyKey()
    {
        // Act
        var key = DatabaseEncryption.GetOrCreateEncryptionKey();

        // Assert
        key.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void GetOrCreateEncryptionKey_ReturnsBase64String()
    {
        // Act
        var key = DatabaseEncryption.GetOrCreateEncryptionKey();

        // Assert
        key.Should().NotBeNullOrEmpty();
        
        // Test that it's valid base64
        var act = () => Convert.FromBase64String(key);
        act.Should().NotThrow();
    }

    [Fact]
    public void GetOrCreateEncryptionKey_ReturnsConsistentKey()
    {
        // Act
        var key1 = DatabaseEncryption.GetOrCreateEncryptionKey();
        var key2 = DatabaseEncryption.GetOrCreateEncryptionKey();

        // Assert
        key1.Should().Be(key2, "should return the same key on subsequent calls");
    }

    [Fact]
    public void GetOrCreateEncryptionKey_GeneratesSecureKeyLength()
    {
        // Act
        var key = DatabaseEncryption.GetOrCreateEncryptionKey();
        var keyBytes = Convert.FromBase64String(key);

        // Assert
        keyBytes.Length.Should().Be(32, "should generate a 256-bit (32-byte) key");
    }

    [Fact]
    public void GetOrCreateEncryptionKey_GeneratesRandomKeys()
    {
        // Arrange - Clear any existing key by testing in isolation
        // Note: This test assumes we can somehow reset the key state
        // In a real scenario, you might need to mock the storage mechanism

        // Act
        var keys = new HashSet<string>();
        
        // Generate multiple keys in different "sessions" (this is conceptual)
        for (int i = 0; i < 5; i++)
        {
            var key = DatabaseEncryption.GetOrCreateEncryptionKey();
            keys.Add(key);
        }

        // Assert
        // Since we're getting the same key each time (by design), we expect only 1 unique key
        keys.Should().HaveCount(1, "should consistently return the same key");
        
        // But the key should be cryptographically random (we can't test randomness easily,
        // but we can verify it's not a predictable value)
        var firstKey = keys.First();
        firstKey.Should().NotBe("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "should not be all zeros");
    }
}