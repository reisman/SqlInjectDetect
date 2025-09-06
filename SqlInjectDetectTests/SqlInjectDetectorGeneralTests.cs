using Microsoft.VisualStudio.TestTools.UnitTesting;
using SqlInjectDetect;

namespace SqlInjectDetectTests;

[TestClass]
public sealed class SqlInjectDetectorGeneralTests
{
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
