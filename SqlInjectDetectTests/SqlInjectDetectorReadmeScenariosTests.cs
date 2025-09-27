using FluentAssertions;
using SqlInjectDetect;

namespace SqlInjectDetectTests;

[TestClass]
public class SqlInjectDetectorReadmeScenariosTests
{
    [TestMethod]
    public void ContainsSqlInjection_IdentifierInjection_ReturnsTrue()
    {
        // Scenario: Identifier context (e.g., ORDER BY)
        var input = "name; SELECT * FROM users; --";
        SqlInjectDetector.ContainsSqlInjection(input).Should().BeTrue($"Identifier injection '{input}' should be detected");
    }

    [TestMethod]
    public void ContainsSqlInjection_BooleanBasedBlindInjection_ReturnsTrue()
    {
        // Scenario: Boolean-based blind injection with CASE
        var input = "' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 1/0 END) > 0 --";
        SqlInjectDetector.ContainsSqlInjection(input).Should().BeTrue($"Boolean-based blind injection '{input}' should be detected");
    }

    [TestMethod]
    public void ContainsSqlInjection_ErrorBasedInjectionWithParsename_ReturnsTrue()
    {
        // Scenario: Error-based injection using PARSENAME
        var input = "' AND 1=CONVERT(int, PARSENAME(CONVERT(varchar, @@version), 2))--";
        SqlInjectDetector.ContainsSqlInjection(input).Should().BeTrue($"Error-based injection with PARSENAME '{input}' should be detected");
    }

    [TestMethod]
    public void ContainsSqlInjection_SecondOrderPayload_ReturnsTrue()
    {
        // Scenario: Payload for a second-order injection
        var input = "' + (SELECT TOP 1 password FROM users) + '";
        SqlInjectDetector.ContainsSqlInjection(input).Should().BeTrue($"Second-order injection payload '{input}' should be detected");
    }
}
