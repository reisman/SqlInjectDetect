using Microsoft.VisualStudio.TestTools.UnitTesting;
using SqlInjectDetect;

namespace SqlInjectDetectTests;

[TestClass]
public sealed class SqlInjectDetectorTests
{
    [TestMethod]
    public void ContainsSqlInjection_ValidInput_ReturnsFalse()
    {
        // Arrange
        var validInputs = new[]
        {
            "John Doe",
            "user@example.com",
            "123456",
            "Product Name",
            "Some normal text",
            "O'Connor", // Valid apostrophe in name
            "test-value",
            ""
        };

        // Act & Assert
        foreach (var input in validInputs)
        {
            Assert.IsFalse(SqlInjectDetector.ContainsSqlInjection(input), $"Input '{input}' should be valid");
        }
    }

    [TestMethod]
    public void ContainsSqlInjection_SqlComments_ReturnsTrue()
    {
        // Arrange
        var maliciousInputs = new[]
        {
            "'; -- comment",
            "test /* comment */ value",
            "input -- DROP TABLE users",
            "value # this is a comment",
            "'; /* multi line \n comment */ --"
        };

        // Act & Assert
        foreach (var input in maliciousInputs)
        {
            Assert.IsTrue(SqlInjectDetector.ContainsSqlInjection(input), $"Input '{input}' should be detected as malicious");
        }
    }

    [TestMethod]
    public void ContainsSqlInjection_UnionBasedAttacks_ReturnsTrue()
    {
        // Arrange
        var unionAttacks = new[]
        {
            "' UNION SELECT * FROM users",
            "1' UNION ALL SELECT username, password FROM admin",
            "test UNION select 1,2,3",
            "value' union all select null, version() --"
        };

        // Act & Assert
        foreach (var input in unionAttacks)
        {
            Assert.IsTrue(SqlInjectDetector.ContainsSqlInjection(input), $"Union attack '{input}' should be detected");
        }
    }

    [TestMethod]
    public void ContainsSqlInjection_QuoteEscapeAttempts_ReturnsTrue()
    {
        // Arrange
        var quoteEscapes = new[]
        {
            "test';",
            "value\";",
            "input\\'",
            "text\\\"",
            "name''; DROP TABLE users; --"
        };

        // Act & Assert
        foreach (var input in quoteEscapes)
        {
            Assert.IsTrue(SqlInjectDetector.ContainsSqlInjection(input), $"Quote escape '{input}' should be detected");
        }
    }

    [TestMethod]
    public void ContainsSqlInjection_DangerousKeywords_ReturnsTrue()
    {
        // Arrange
        var dangerousInputs = new[]
        {
            "SELECT * FROM users",
            "DROP TABLE customers",
            "INSERT INTO admin",
            "UPDATE users SET",
            "DELETE FROM orders",
            "EXEC sp_helpdb",
            "CREATE TABLE test",
            "ALTER TABLE users",
            "EXECUTE xp_cmdshell"
        };

        // Act & Assert
        foreach (var input in dangerousInputs)
        {
            Assert.IsTrue(SqlInjectDetector.ContainsSqlInjection(input), $"Dangerous keyword '{input}' should be detected");
        }
    }

    [TestMethod]
    public void ContainsSqlInjection_HexEncodedContent_ReturnsTrue()
    {
        // Arrange
        var hexInputs = new[]
        {
            "0x41646D696E",
            "value 0x53514C",
            "test 0xDEADBEEF input"
        };

        // Act & Assert
        foreach (var input in hexInputs)
        {
            Assert.IsTrue(SqlInjectDetector.ContainsSqlInjection(input), $"Hex encoded '{input}' should be detected");
        }
    }

    [TestMethod]
    public void ContainsSqlInjection_StatementChaining_ReturnsTrue()
    {
        // Arrange
        var chainingInputs = new[]
        {
            "test'; DROP TABLE users;",
            "value; SELECT * FROM admin",
            "input; DELETE FROM orders; --",
            "name'; INSERT INTO logs VALUES ('hack'); --"
        };

        // Act & Assert
        foreach (var input in chainingInputs)
        {
            Assert.IsTrue(SqlInjectDetector.ContainsSqlInjection(input), $"Statement chaining '{input}' should be detected");
        }
    }

    [TestMethod]
    public void ContainsSqlInjection_ComplexAttacks_ReturnsTrue()
    {
        // Arrange
        var complexAttacks = new[]
        {
            "'; DROP TABLE users; --",
            "admin'--",
            "' OR '1'='1",
            "' OR 1=1 --",
            "1' OR '1'='1' /*",
            "'; EXEC sp_configure 'show advanced options', 1; --",
            "' UNION SELECT null, username, password FROM users WHERE '1'='1",
            "test' AND 1=CONVERT(int, (SELECT TOP 1 name FROM sysobjects WHERE xtype='U'))"
        };

        // Act & Assert
        foreach (var input in complexAttacks)
        {
            Assert.IsTrue(SqlInjectDetector.ContainsSqlInjection(input), $"Complex attack '{input}' should be detected");
        }
    }

    [TestMethod]
    public void ContainsSqlInjection_NullAndEmpty_ReturnsFalse()
    {
        // Act & Assert
        Assert.IsFalse(SqlInjectDetector.ContainsSqlInjection(null));
        Assert.IsFalse(SqlInjectDetector.ContainsSqlInjection(""));
        Assert.IsFalse(SqlInjectDetector.ContainsSqlInjection("   "));
    }

    [TestMethod]
    public void ContainsSqlInjection_EdgeCases_ReturnsExpectedResult()
    {
        // Arrange & Act & Assert
        
        // These should be safe
        Assert.IsFalse(SqlInjectDetector.ContainsSqlInjection("O'Connor")); // Valid name with apostrophe
        Assert.IsFalse(SqlInjectDetector.ContainsSqlInjection("It's a test")); // Valid contraction
        Assert.IsFalse(SqlInjectDetector.ContainsSqlInjection("Price: $19.99")); // Valid price
        
        // These should be detected
        Assert.IsTrue(SqlInjectDetector.ContainsSqlInjection("test' OR '1'='1")); // Classic injection
        Assert.IsTrue(SqlInjectDetector.ContainsSqlInjection("javascript:alert(1)")); // Script injection
        Assert.IsTrue(SqlInjectDetector.ContainsSqlInjection("char(65)")); // Function call
    }

    [TestMethod]
    public void ContainsSqlInjection_Performance_HandlesHighVolume()
    {
        // Arrange
        var testInputs = new[]
        {
            "normal input",
            "'; DROP TABLE users; --",
            "user@example.com",
            "' UNION SELECT * FROM admin",
            "regular text here",
            "SELECT * FROM sensitive_data"
        };

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        
        // Act - Test with high volume
        for (int i = 0; i < 10000; i++)
        {
            foreach (var input in testInputs)
            {
                SqlInjectDetector.ContainsSqlInjection(input);
            }
        }
        
        stopwatch.Stop();
        
        // Assert - Should complete reasonably quickly (less than 5 seconds for 60k calls)
        Assert.IsTrue(stopwatch.ElapsedMilliseconds < 5000, 
            $"Performance test took too long: {stopwatch.ElapsedMilliseconds}ms for 60,000 calls");
    }
}