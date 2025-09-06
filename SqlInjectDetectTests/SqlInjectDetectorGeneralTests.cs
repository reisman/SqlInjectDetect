using FluentAssertions;
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
        SqlInjectDetector.ContainsSqlInjection("O'Connor").Should().BeFalse(); // Valid name with apostrophe
        SqlInjectDetector.ContainsSqlInjection("It's a test").Should().BeFalse(); // Valid contraction
        SqlInjectDetector.ContainsSqlInjection("Price: $19.99").Should().BeFalse(); // Valid price
        
        // These should be detected
        SqlInjectDetector.ContainsSqlInjection("test' OR '1'='1").Should().BeTrue(); // Classic injection
        SqlInjectDetector.ContainsSqlInjection("javascript:alert(1)").Should().BeTrue(); // Script injection
        SqlInjectDetector.ContainsSqlInjection("char(65)").Should().BeTrue(); // Function call
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
        stopwatch.ElapsedMilliseconds.Should().BeLessThan(5000, 
            $"Performance test took too long: {stopwatch.ElapsedMilliseconds}ms for 60,000 calls");
    }
}
