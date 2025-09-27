using FluentAssertions;
using SqlInjectDetect;

namespace SqlInjectDetectTests;

[TestClass]
public class SqlInjectDetectorBase64Tests
{
    [TestMethod]
    public void ContainsSqlInjection_Base64EncodedSelect_ReturnsTrue()
    {
        // Arrange
        var input = "SELECT FROM_BASE64('c2VsZWN0IHVzZXIoKQ==');"; // "select user()"

        // Act
        var result = SqlInjectDetector.ContainsSqlInjection(input);

        // Assert
        result.Should().BeTrue();
    }
}

