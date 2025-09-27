using FluentAssertions;
using SqlInjectDetect;

namespace SqlInjectDetectTests;

[TestClass]
public sealed class SqlInjectDetectorEvasionTests
{
    [TestMethod]
    public void ContainsSqlInjection_WAFBypassTechniques_ReturnsTrue()
    {
        // Arrange - WAF bypass techniques that should still be detectable
        var wafBypassInjections = new[]
        {
            // Case variation bypass (should still be detected due to case-insensitive regex)
            "SeLeCt * FrOm users",
            "uNiOn SeLeCt 1,2,3",
            "InSeRt InTo users",
            
            // Comment insertion bypass (should be detected)
            "SEL/**/ECT * FR/**/OM users",
            "UN/**/ION SE/**/LECT 1,2",
            "IN/**/SERT IN/**/TO users",
            "UPD/**/ATE use/**/rs SET",
            
            // Whitespace variation bypass (should be detected)
            "SELECT\t*\tFROM\tusers",
            "SELECT\n*\nFROM\nusers",
            "SELECT\r*\rFROM\rusers",
            
            // SQL keywords that should be caught
            "' UNION SELECT * FROM users --",
            "'; DELETE FROM users; --",
            "' OR 1=1; DROP TABLE users; --",
            
            // Function names that should be detected
            "SELECT database()",
            "SELECT version()",
            "SELECT @@version",
            "SELECT user()",
            
            // Hex encoding (should be caught)
            "SELECT 0x53454c454354",
            "SELECT 0x41646D696E",
            
            // SQL with suspicious functions
            "SELECT CHAR(65,68,77,73,78)",
            "SELECT ascii('a')",
            "SELECT substring(password,1,1) FROM users",
            
            // Alternative operators that should be detected
            "1 union distinct select 1,2,3",
            "1 union all select 1,2,3",
            "' OR '1'='1' --"
        };

        // Act & Assert
        foreach (var injection in wafBypassInjections)
        {
            SqlInjectDetector.ContainsSqlInjection(injection).Should().BeTrue(
                $"WAF bypass injection '{injection}' should be detected");
        }
    }

    [TestMethod]
    public void ContainsSqlInjection_PolyglotPayloads_ReturnsTrue()
    {
        // Arrange - Polyglot payloads that work across multiple contexts
        var polyglotInjections = new[]
        {
            // SQL + XSS polyglot
            "'; alert(String.fromCharCode(88,83,83)); --",
            "'><script>alert('XSS')</script>; SELECT * FROM users; --",
            
            // SQL + NoSQL polyglot
            "'; return true; } db.users.find({ $where: function() { return true; } }); --",
            "'||this.constructor.constructor('return process')().env||'",
            
            // SQL + LDAP polyglot
            "admin)(&(objectclass=*))'; SELECT * FROM users; --",
            "'||(uid=admin)(objectclass=*)'; DROP TABLE users; --",
            
            // SQL + Command injection polyglot
            "'; SELECT * FROM users; EXEC xp_cmdshell('dir'); --",
            "'`; echo 'command'; SELECT * FROM users; --`",
            
            // SQL + Template injection polyglot
            "'{{7*7}}'; SELECT * FROM users; --",
            "'${T(java.lang.System).exit(1)}'; DELETE FROM users; --",
            
            // SQL + Path traversal polyglot
            "'../../etc/passwd'; SELECT load_file('/etc/passwd'); --",
            "'..\\..\\windows\\system32\\drivers\\etc\\hosts'; SELECT * FROM users; --",
            
            // Multi-database polyglot
            "'; SELECT version()::text || pg_sleep(1); SELECT @@version; WAITFOR DELAY '00:00:01'; --",
            "' UNION SELECT null,version(),null FROM dual UNION SELECT null,@@version,null; --",
            
            // Multi-encoding polyglot
            "'; SELECT 0x73656c656374 || CHAR(32) || version(); --",
            "'%3B%20SELECT%20*%20FROM%20users%3B%20--",
            
            // JSON + SQL polyglot
            "{ \"id\": \"1'; DROP TABLE users; --\", \"name\": \"admin\" }",
            "\"; SELECT * FROM users WHERE id = '1",
            
            // XML + SQL polyglot
            "'</user><admin>'; SELECT * FROM users; --</admin>",
            "']); } catch(e) {} SELECT * FROM users; try { var x = ['",
        };

        // Act & Assert
        foreach (var injection in polyglotInjections)
        {
            SqlInjectDetector.ContainsSqlInjection(injection).Should().BeTrue(
                $"Polyglot injection '{injection}' should be detected");
        }
    }

    [TestMethod]
    public void ContainsSqlInjection_TimingAttackVariations_ReturnsTrue()
    {
        // Arrange - Various timing attack patterns
        var timingAttacks = new[]
        {
            // SQL Server timing
            "'; IF (1=1) WAITFOR DELAY '00:00:05'; --",
            "'; IF (SELECT COUNT(*) FROM users) > 0 WAITFOR DELAY '00:00:03'; --",
            "'; IF (ASCII(SUBSTRING((SELECT password FROM users WHERE id=1),1,1))) > 100 WAITFOR DELAY '00:00:02'; --",
            
            // MySQL timing
            "'; SELECT SLEEP(5); --",
            "'; SELECT IF(1=1, SLEEP(3), 0); --",
            "'; SELECT BENCHMARK(5000000, MD5('test')); --",
            
            // PostgreSQL timing
            "'; SELECT pg_sleep(5); --",
            "'; SELECT CASE WHEN (1=1) THEN pg_sleep(3) ELSE pg_sleep(0) END; --",
            "'; SELECT generate_series(1,1000000) FROM users; --",
            
            // Oracle timing
            "'; SELECT count(*) FROM all_objects,all_objects,all_objects; --",
            "'; BEGIN DBMS_LOCK.SLEEP(5); END; --",
            
            // Generic timing patterns
            "'; SELECT (SELECT count(*) FROM information_schema.columns A, information_schema.columns B, information_schema.columns C); --",
            "' AND (SELECT * FROM (SELECT count(*),concat(version(),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a); --",
            
            // Conditional timing
            "' AND IF(1=1, (SELECT SLEEP(5)), 0); --",
            "' AND (SELECT CASE WHEN (SUBSTRING(@@version,1,1)='5') THEN pg_sleep(5) ELSE pg_sleep(0) END); --",
            
            // Heavy query timing
            "'; SELECT count(*) FROM information_schema.columns t1, information_schema.columns t2; --",
            "' AND (SELECT count(*) FROM sysobjects) > 0; WAITFOR DELAY '00:00:05'; --"
        };

        // Act & Assert
        foreach (var attack in timingAttacks)
        {
            SqlInjectDetector.ContainsSqlInjection(attack).Should().BeTrue(
                $"Timing attack '{attack}' should be detected");
        }
    }

    [TestMethod]
    public void ContainsSqlInjection_TemplateInjection_ReturnsTrue()
    {
        // Arrange - Template injection patterns with SQL elements that should be detected
        var templateInjections = new[]
        {
            // Template injection combined with SQL injection
            "'; SELECT * FROM users; {{7*7}} --",
            "{{config}}'; DROP TABLE users; --",
            "'; UNION SELECT username, password FROM admin; ${7*7} --",
            
            // SQL injection in template contexts
            "${T(java.lang.System).getProperty('user.name')}'; SELECT version(); --",
            "{{_self.env.registerUndefinedFilterCallback('exec')}}'; DELETE FROM users; --",
            
            // Template syntax with SQL keywords
            "'; SELECT load_file('/etc/passwd'); {{dump(app)}} --",
            "{php}echo 'test';{/php}'; DROP DATABASE test; --",
            
            // Mixed template and SQL injection
            "'; CREATE TABLE evil AS SELECT * FROM users; {{7*7}} --",
            "$class.inspect('java.lang.System').type.getProperty('user.name')'; INSERT INTO logs VALUES ('hacked'); --",
            
            // SQL functions in template context
            "'; SELECT char(65,68,77,73,78); {{lookup . 'constructor'}} --",
            "{{#with 'constructor'}}'; SELECT @@version; {{#with split}}{{pop (push 'alert(1)')}}{{/with}}{{/with}} --"
        };

        // Act & Assert
        foreach (var injection in templateInjections)
        {
            SqlInjectDetector.ContainsSqlInjection(injection).Should().BeTrue(
                $"Template injection '{injection}' should be detected");
        }
    }

    [TestMethod]
    public void ContainsSqlInjection_FunctionBasedAttacks_ReturnsTrue()
    {
        // Arrange - Function-based injection attacks
        var functionAttacks = new[]
        {
            // SQL function chaining
            "'; SELECT ascii(substring(version(),1,1)); --",
            "'; SELECT char(65)||char(68)||char(77)||char(73)||char(78); --",
            "'; SELECT concat(user(),':',password) FROM mysql.user; --",
            
            // Nested function calls
            "'; SELECT substr(load_file('/etc/passwd'),1,100); --",
            "'; SELECT hex(unhex('admin')); --",
            "'; SELECT cast((SELECT password FROM users LIMIT 1) as char); --",
            
            // Conditional functions
            "'; SELECT if(1=1,version(),null); --",
            "'; SELECT case when 1=1 then version() else null end; --",
            "'; SELECT iif(1=1,@@version,'false'); --",
            
            // Aggregate functions
            "'; SELECT group_concat(username,':',password SEPARATOR '|') FROM users; --",
            "'; SELECT string_agg(username||':'||password, '|') FROM users; --",
            "'; SELECT listagg(username||':'||password, '|') WITHIN GROUP (ORDER BY id) FROM users; --",
            
            // Mathematical functions
            "'; SELECT power(2,31)-1; --",
            "'; SELECT floor(rand()*1000); --",
            "'; SELECT abs(-1); --",
            
            // String manipulation functions
            "'; SELECT repeat('A',1000); --",
            "'; SELECT reverse('admin'); --",
            "'; SELECT replace('XadminX','X',''); --",
            "'; SELECT stuff('admin',1,0,'X'); --",
            
            // Date/Time functions
            "'; SELECT now(); --",
            "'; SELECT current_timestamp; --",
            "'; SELECT extract(year from now()); --",
            
            // System functions
            "'; SELECT current_user(); --",
            "'; SELECT session_user(); --",
            "'; SELECT database(); --",
            "'; SELECT connection_id(); --"
        };

        // Act & Assert
        foreach (var attack in functionAttacks)
        {
            SqlInjectDetector.ContainsSqlInjection(attack).Should().BeTrue(
                $"Function-based attack '{attack}' should be detected");
        }
    }
}