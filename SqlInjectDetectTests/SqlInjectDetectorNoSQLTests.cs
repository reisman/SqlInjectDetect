using FluentAssertions;
using SqlInjectDetect;

namespace SqlInjectDetectTests;

[TestClass]
public sealed class SqlInjectDetectorNoSQLTests
{
    [TestMethod]
    public void ContainsSqlInjection_MongoDBInjection_ReturnsTrue()
    {
        // Arrange - MongoDB injection patterns that contain SQL-like elements
        var mongoInjections = new[]
        {
            // MongoDB JavaScript injection with SQL elements
            "'; return this.username == 'admin' && this.password != '' //",
            "admin'; return true; //",
            "'; return '' == '' //",
            "'; SELECT * FROM users; return true; //",
            
            // MongoDB with embedded SQL
            "{ \"$where\": \"'; DROP TABLE users; return true;\" }",
            "{ \"$where\": \"return this.username == 'admin' || '1'='1'\" }",
            
            // MongoDB function injection with SQL
            "function() { return true; }; SELECT * FROM users; //",
            "function() { return this.username.match(/admin/); DROP TABLE users; }",
            
            // NoSQL with SQL keywords
            "admin'; SELECT version(); return true; //",
            "{ \"query\": \"'; DELETE FROM users; --\" }",
            
            // NoSQL sleep/delay with SQL injection
            "{ \"$where\": \"sleep(1000) || true; SELECT * FROM users;\" }",
            "function() { var start = new Date(); while((new Date().getTime() - start) < 1000) {} SELECT password FROM users; return true; }"
        };

        // Act & Assert
        foreach (var injection in mongoInjections)
        {
            SqlInjectDetector.ContainsSqlInjection(injection).Should().BeTrue(
                $"MongoDB injection '{injection}' should be detected");
        }
    }

    [TestMethod]
    public void ContainsSqlInjection_CouchDBInjection_ReturnsTrue()
    {
        // Arrange - CouchDB injection patterns with SQL elements
        var couchdbInjections = new[]
        {
            // CouchDB with embedded SQL injection
            "function(doc) { if(doc.type == 'user') emit(doc._id, doc); SELECT * FROM users; }",
            "function(doc) { emit(doc._id, null); DROP TABLE users; }",
            
            // CouchDB with SQL keywords
            "'; SELECT version(); function(doc) { emit(doc._id, doc); }",
            "'; DELETE FROM users; --",
            
            // CouchDB design document with SQL
            "{ \"map\": \"function(doc) { emit(doc._id, doc.password); SELECT password FROM users; }\" }",
            "{ \"reduce\": \"'; DROP TABLE users; function(keys, values, rereduce) { return sum(values); }\" }",
            
            // CouchDB HTTP injection with SQL
            "/_all_dbs'; SELECT * FROM information_schema.tables; --",
            "/_users/_all_docs'; UNION SELECT username, password FROM admin; --"
        };

        // Act & Assert
        foreach (var injection in couchdbInjections)
        {
            SqlInjectDetector.ContainsSqlInjection(injection).Should().BeTrue(
                $"CouchDB injection '{injection}' should be detected");
        }
    }

    [TestMethod]
    public void ContainsSqlInjection_JSONInjection_ReturnsTrue()
    {
        // Arrange - JSON-based injection patterns with SQL elements
        var jsonInjections = new[]
        {
            // JSON with embedded SQL
            "{ \"query\": \"SELECT * FROM users WHERE id = 1; DROP TABLE users; --\" }",
            "{ \"filter\": \"'; DELETE FROM users; --\" }",
            "{ \"search\": \"' UNION SELECT username, password FROM admin --\" }",
            
            // JSON with SQL in values
            "{ \"username\": \"admin'; DROP TABLE users; --\" }",
            "{ \"password\": \"' OR 1=1; --\" }",
            "{ \"id\": \"1; SELECT * FROM users; --\" }",
            
            // JSON with dangerous functions
            "{ \"validate\": \"function() { return true; }; SELECT version(); --\" }",
            "{ \"transform\": \"'; EXEC xp_cmdshell('dir'); --\" }",
            
            // JSON with template injection that includes SQL
            "{ \"template\": \"'; SELECT * FROM users; --\" }",
            "{ \"expr\": \"'; UPDATE users SET password='hacked'; --\" }"
        };

        // Act & Assert
        foreach (var injection in jsonInjections)
        {
            SqlInjectDetector.ContainsSqlInjection(injection).Should().BeTrue(
                $"JSON injection '{injection}' should be detected");
        }
    }

    [TestMethod]
    public void ContainsSqlInjection_LDAPInjection_ReturnsTrue()
    {
        // Arrange - LDAP injection patterns with SQL elements
        var ldapInjections = new[]
        {
            // LDAP with embedded SQL
            "admin)(&(objectclass=*)); SELECT * FROM users; --",
            "*)(|(objectclass=*)); DROP TABLE users; --",
            "admin)(&(uid=*)); DELETE FROM admin; --",
            
            // Combined LDAP and SQL injection
            "'; SELECT version(); (uid=admin",
            "admin'; UNION SELECT username, password FROM users; --(uid=*",
            
            // LDAP with SQL comments
            "admin)(objectclass=*))%00; -- SQL injection here",
            "*))%00'; SELECT * FROM information_schema.tables; --",
            
            // LDAP filter with SQL keywords
            "admin*)(mail=*)); SELECT password FROM users WHERE username='admin'; --"
        };

        // Act & Assert
        foreach (var injection in ldapInjections)
        {
            SqlInjectDetector.ContainsSqlInjection(injection).Should().BeTrue(
                $"LDAP injection '{injection}' should be detected");
        }
    }

    [TestMethod]
    public void ContainsSqlInjection_XPathInjection_ReturnsTrue()
    {
        // Arrange - XPath injection patterns that include SQL-like elements
        var xpathInjections = new[]
        {
            // XPath boolean injection (using patterns that should be detected)
            "' or '1'='1",
            "' or 1=1 or '1'='1",
            "admin'--",
            
            // XPath with SQL keywords
            "' or substring(//user[1]/password,1,1)='a'; SELECT version(); --",
            "' or contains(//user/password,'admin'); DROP TABLE users; --",
            
            // XPath with embedded SQL
            "//user[username/text()='admin' or '1'='1']; SELECT * FROM users; --",
            "//user | //admin'; UNION SELECT username, password FROM users; --",
            
            // XPath function with SQL injection
            "' or count(//user)=1 or '1'='1'; DELETE FROM users; --",
            "' or string-length(//user[1]/password)>5 or '1'='1'; SELECT @@version; --",
            
            // XPath with SQL comments and keywords
            "//user[position()=1]/password'; -- SELECT * FROM users",
            "//user[1] | //admin[1]'; SELECT load_file('/etc/passwd'); --"
        };

        // Act & Assert
        foreach (var injection in xpathInjections)
        {
            SqlInjectDetector.ContainsSqlInjection(injection).Should().BeTrue(
                $"XPath injection '{injection}' should be detected");
        }
    }
}