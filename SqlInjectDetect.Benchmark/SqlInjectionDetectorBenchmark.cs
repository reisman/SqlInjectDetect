using BenchmarkDotNet.Attributes;
using SqlInjectDetect;

namespace SqlInjectDetect.Benchmark;

[MemoryDiagnoser]
public class SqlInjectionDetectorBenchmark
{
    private readonly string[] _validInputs = 
    {
        "John Doe", "user@example.com", "123456", "Product Name", "Some normal text", "O'Connor", 
        "test-value", "Injection insert step", "Engine Block V8", "Brake Pad Set - Front", "PN-555.123.456"
    };

    private readonly string[] _maliciousInputs = 
    {
        "' OR 1=1 --", "'; DROP TABLE users; --", "1' UNION ALL SELECT username, password FROM admin",
        "SELECT * FROM users WHERE id = '1' OR '1'='1'", "EXEC xp_cmdshell('dir')", "javascript:alert(1)",
        "1; WAITFOR DELAY '0:0:5'--", "1' AND 1=CAST(@@version AS INT)--", "1' OR '1'='1'/*", 
        "1' OR '1'='1' ({", "1' OR '1'='1' AND 'a'='a"
    };

    [Benchmark(Baseline = true)]
    public void CheckValidInputs()
    {
        foreach (var input in _validInputs)
        {
            SqlInjectDetector.ContainsSqlInjection(input);
        }
    }

    [Benchmark]
    public void CheckMaliciousInputs()
    {
        foreach (var input in _maliciousInputs)
        {
            SqlInjectDetector.ContainsSqlInjection(input);
        }
    }
}
