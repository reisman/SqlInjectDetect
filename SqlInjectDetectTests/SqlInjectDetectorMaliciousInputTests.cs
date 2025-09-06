using FluentAssertions;
using SqlInjectDetect;

namespace SqlInjectDetectTests;

[TestClass]
public sealed class SqlInjectDetectorMaliciousInputTests
{
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
            SqlInjectDetector.ContainsSqlInjection(input).Should().BeTrue($"Input '{input}' should be detected as malicious");
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
            SqlInjectDetector.ContainsSqlInjection(input).Should().BeTrue($"Union attack '{input}' should be detected");
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
            SqlInjectDetector.ContainsSqlInjection(input).Should().BeTrue($"Quote escape '{input}' should be detected");
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
            SqlInjectDetector.ContainsSqlInjection(input).Should().BeTrue($"Dangerous keyword '{input}' should be detected");
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
            SqlInjectDetector.ContainsSqlInjection(input).Should().BeTrue($"Hex encoded '{input}' should be detected");
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
            SqlInjectDetector.ContainsSqlInjection(input).Should().BeTrue($"Statement chaining '{input}' should be detected");
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
            SqlInjectDetector.ContainsSqlInjection(input).Should().BeTrue($"Complex attack '{input}' should be detected");
        }
    }
    
    [TestMethod]
    public void ContainsSqlInjection_MaliciousPartNames_ReturnsTrue()
    {
        // Arrange - Part names with SQL injection attempts
        var maliciousPartNames = new[]
        {
            "Brake Pad'; DROP TABLE parts; --",
            "Oil Filter' OR '1'='1",
            "Spark Plug'; INSERT INTO orders VALUES ('hack'); --",
            "Air Filter' UNION SELECT * FROM customers",
            "Engine Block'; DELETE FROM inventory; --",
            "Transmission'; EXEC xp_cmdshell 'dir'; --",
            "Radiator' AND 1=CONVERT(int, SUBSTRING((SELECT TOP 1 name FROM sysobjects), 1, 1)); --",
            "Battery'; UPDATE prices SET cost=0; --",
            "Tire' OR EXISTS(SELECT * FROM users WHERE admin=1); --",
            "Filter/**/UNION/**/SELECT/**/password/**/FROM/**/users",
            "Part Name'; WAITFOR DELAY '00:00:05'; --",
            "Alternator' OR ASCII(SUBSTRING((SELECT TOP 1 password FROM users), 1, 1)) > 65; --"
        };

        // Act & Assert
        foreach (var maliciousName in maliciousPartNames)
        {
            SqlInjectDetector.ContainsSqlInjection(maliciousName).Should().BeTrue(
                $"Malicious part name '{maliciousName}' should be detected as injection");
        }
    }

    [TestMethod]
    public void ContainsSqlInjection_MaliciousPartNumbers_ReturnsTrue()
    {
        // Arrange - Part numbers with SQL injection attempts
        var maliciousPartNumbers = new[]
        {
            "ABC-123'; DROP TABLE inventory; --",
            "P/N: 123' OR 1=1; --",
            "OEM#: 456'; SELECT * FROM admin_users; --",
            "SKU-789' UNION ALL SELECT username, password FROM users; --",
            "Model-X'; INSERT INTO logs VALUES ('compromised'); --",
            "BMW-123'; EXEC sp_configure 'show advanced options', 1; --",
            "FORD'; DELETE FROM orders WHERE 1=1; --",
            "GM' OR (SELECT COUNT(*) FROM information_schema.tables) > 0; --",
            "VW-456' AND 1=CAST((SELECT @@version) AS int); --",
            "PART'; BULK INSERT temp FROM 'c:\\temp\\data.txt'; --",
            "123'; SHUTDOWN WITH NOWAIT; --",
            "AUDI' OR CHAR(65)=CHAR(65); --"
        };

        // Act & Assert
        foreach (var maliciousNumber in maliciousPartNumbers)
        {
            SqlInjectDetector.ContainsSqlInjection(maliciousNumber).Should().BeTrue(
                $"Malicious part number '{maliciousNumber}' should be detected as injection");
        }
    }
}
