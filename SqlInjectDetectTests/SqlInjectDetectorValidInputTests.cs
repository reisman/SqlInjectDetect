using FluentAssertions;
using SqlInjectDetect;

namespace SqlInjectDetectTests;

[TestClass]
public sealed class SqlInjectDetectorValidInputTests
{
    [TestMethod]
    public void ContainsSqlInjection_ValidInput_ReturnsFalse()
    {
        // Arrange
        var validInputs = new[]
        {
            "John Doe",
            "user@example.com",
            "123456",
            "Product Name",
            "Some normal text",
            "O'Connor", // Valid apostrophe in name
            "test-value",
            "Injection insert step",
            ""
        };

        // Act & Assert
        foreach (var input in validInputs)
        {
            SqlInjectDetector.ContainsSqlInjection(input).Should().BeFalse($"Input '{input}' should be valid");
        }
    }

    [TestMethod]
    public void ContainsSqlInjection_NullAndEmpty_ReturnsFalse()
    {
        // Act & Assert
        SqlInjectDetector.ContainsSqlInjection(null).Should().BeFalse();
        SqlInjectDetector.ContainsSqlInjection("").Should().BeFalse();
        SqlInjectDetector.ContainsSqlInjection("   ").Should().BeFalse();
    }

    [TestMethod]
    public void ContainsSqlInjection_RealisticPartNames_ReturnsFalse()
    {
        // Arrange - Realistic part names that should be valid
        var validPartNames = new[]
        {
            "Engine Block V8",
            "Brake Pad Set - Front",
            "Oil Filter WIX 51515",
            "Spark Plug NGK BKR6E",
            "Air Filter K&N 33-2304",
            "Transmission Fluid ATF+4",
            "Windshield Wiper 22\"",
            "LED Headlight H7 6000K",
            "Tire P225/65R17",
            "Battery 12V 65Ah",
            "Alternator 140A",
            "Radiator Cap 1.3 Bar",
            "Fuel Pump Assembly",
            "Oxygen Sensor Bank 1",
            "Catalytic Converter",
            "Power Steering Fluid",
            "Cabin Air Filter",
            "Serpentine Belt 6PK1865",
            "Shock Absorber - Rear",
            "CV Joint Kit"
        };

        // Act & Assert
        foreach (var partName in validPartNames)
        {
            SqlInjectDetector.ContainsSqlInjection(partName).Should().BeFalse(
                $"Valid part name '{partName}' should not be flagged as injection");
        }
    }

    [TestMethod]
    public void ContainsSqlInjection_RealisticPartNumbers_ReturnsFalse()
    {
        // Arrange - Realistic part numbers that should be valid
        var validPartNumbers = new[]
        {
            "ABC-123-456",
            "P/N: 98765-4321",
            "OEM#: 1K0-819-644",
            "SKU: FILTER-001",
            "Model: AF-789X",
            "BMW-11427566327",
            "FORD-3F2Z-6731-AA",
            "GM-12345678",
            "VW-1J0-698-151-C",
            "AUDI-8E0-260-805-AH",
            "MB-A0009884701",
            "TOYOTA-90915-YZZD4",
            "HONDA-15400-PLM-A02",
            "NISSAN-15208-65F0C",
            "MAZDA-PE01-13-Z40",
            "SUBARU-15208AA15A",
            "VOLVO-30788685",
            "SAAB-93186554",
            "FIAT-46544820",
            "MINI-11427622446"
        };

        // Act & Assert
        foreach (var partNumber in validPartNumbers)
        {
            SqlInjectDetector.ContainsSqlInjection(partNumber).Should().BeFalse(
                $"Valid part number '{partNumber}' should not be flagged as injection");
        }
    }

    [TestMethod]
    public void ContainsSqlInjection_SpecialCharactersInValidParts_ReturnsFalse()
    {
        // Arrange - Valid part names/numbers with special characters that might be confused with injection
        var validPartsWithSpecialChars = new[]
        {
            "M&M Carburetor Kit",
            "A/C Compressor Assembly",
            "3M™ Adhesive Tape",
            "Bürkert® Flow Sensor",
            "Gates® T-Belt Kit",
            "NGK® Iridium IX™",
            "K&N® Air Filter",
            "Bendix® Advanced+™",
            "Motorcraft® FL-820-S",
            "Champion® RC12YC",
            "Fel-Pro® 60847",
            "ACDelco® 213-4608",
            "Bosch® 0 280 158 827",
            "Denso® 234-4261",
            "Fram® PH3600",
            "WIX® 33333",
            "STP® S4967",
            "Mobil 1™ 0W-20"
        };

        // Act & Assert
        foreach (var validPart in validPartsWithSpecialChars)
        {
            SqlInjectDetector.ContainsSqlInjection(validPart).Should().BeFalse(
                $"Valid part with special characters '{validPart}' should not be flagged");
        }
    }

    [TestMethod]
    public void ContainsSqlInjection_UnicodeAndInternationalCharacters_ReturnsFalse()
    {
        // Arrange
        var validInputs = new[]
        {
            "José",
            "François",
            "你好",
            "こんにちは",
            "안녕하세요",
            "你好世界",
            "123 Main St, Сент-Луис, MO",
            "item-你好"
        };

        // Act & Assert
        foreach (var input in validInputs)
        {
            SqlInjectDetector.ContainsSqlInjection(input).Should().BeFalse($"Input '{input}' should be valid");
        }
    }
    
    [TestMethod]
    public void ContainsSqlInjection_ValidPartDataWithSpecialChars_ReturnsFalse()
    {
        // Arrange - Part data with special characters that should be considered valid.
        var validPartData = new[]
        {
            "PN-555.123.456",
            "SKU.123-ABC.789",
            "PART-NO: 123.456-789/A",
            "ID_123-456.v2",
            "REF: 987-654.321.B",
            "Engine Control Module (ECM) - P/N 12345.67890",
            "Sensor, Oxygen - Bosch 15717.02",
            "Brake Rotor, Drilled/Slotted - 320.4001.12",
            "Filter-Set: Oil, Air, Cabin - MANN-FILTER CUK 2939-2",
            "Assembly-123.45.6-rev.2"
        };

        // Act & Assert
        foreach (var partData in validPartData)
        {
            SqlInjectDetector.ContainsSqlInjection(partData).Should().BeFalse(
                $"Valid part data '{partData}' should not be flagged as injection");
        }
    }
}
