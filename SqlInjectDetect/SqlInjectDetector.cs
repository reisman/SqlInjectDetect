using System.Text.RegularExpressions;

namespace SqlInjectDetect;

public static class SqlInjectDetector
{
    // Compiled regex patterns for performance
    private static readonly Regex SqlCommentPattern = new(@"(/\*.*?\*/|\s--\s|--$|\s#\s|#$)", 
        RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Singleline);
    
    private static readonly Regex UnionPattern = new(@"\bunion(\s+all)?\s+select\b", 
        RegexOptions.Compiled | RegexOptions.IgnoreCase);
    
    private static readonly Regex SqlKeywordPattern = new(@"\b(select|insert|update|delete|drop|create|alter|exec|execute|declare|bulk|shutdown|waitfor|if|while|begin|end|try|catch|case|when|then|else|having|group\s+by|order\s+by|like|escape)\b", 
        RegexOptions.Compiled | RegexOptions.IgnoreCase);
    
    private static readonly Regex HexPattern = new(@"\b0x[0-9a-f]+\b", 
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex StoredProcPattern = new(@"\b(sp_|xp_)\w*", 
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex SqlFunctionPattern = new(@"\b(char|ascii|substring|cast|convert|nchar|stuff|replace|reverse|space|len|datalength|system_user|db_name|user_name|host_name)\s*\(", 
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex UrlEncodedPattern = new(@"%[0-9a-f]{2}", 
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex SqlOperatorPattern = new(@"(\|\||&&|\+\s*\(|exists\s*\()", 
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public static bool ContainsSqlInjection(string? sql)
    {
        if (string.IsNullOrWhiteSpace(sql))
            return false;

        // Normalize input for analysis
        var normalizedSql = sql.Trim();
        
        // Try to decode URL encoded content for analysis
        var decodedSql = TryUrlDecode(normalizedSql);
        
        // Check both original and decoded versions
        foreach (var testSql in new[] { normalizedSql, decodedSql })
        {
            if (string.IsNullOrEmpty(testSql)) continue;
            if (testSql != normalizedSql && testSql == normalizedSql) continue; // Skip duplicates
            
            if (HasSqlComments(testSql) ||
                HasUnionBasedInjection(testSql) ||
                HasQuoteEscapeAttempts(testSql) ||
                HasDangerousKeywords(testSql) ||
                HasHexEncodedContent(testSql) ||
                HasSqlStatementChaining(testSql) ||
                HasStoredProcedureCalls(testSql) ||
                HasClassicInjectionPatterns(testSql) ||
                HasSqlFunctions(testSql) ||
                HasSqlOperators(testSql) ||
                HasAdvancedPatterns(testSql))
            {
                return true;
            }
        }

        return false;
    }

    private static string TryUrlDecode(string input)
    {
        try
        {
            if (UrlEncodedPattern.IsMatch(input))
            {
                return Uri.UnescapeDataString(input);
            }
        }
        catch
        {
            // If URL decoding fails, return original
        }
        return input;
    }

    private static bool HasSqlComments(string sql)
    {
        // A more precise check for comments, ensuring they are not part of a larger string.
        return (sql.Contains("/*") && sql.Contains("*/")) ||
               Regex.IsMatch(sql, @"\s--\s|--$") ||
               Regex.IsMatch(sql, @"\s#\s|#$");
    }

    private static bool HasUnionBasedInjection(string sql)
    {
        return UnionPattern.IsMatch(sql);
    }

    private static bool HasQuoteEscapeAttempts(string sql)
    {
        return sql.Contains("';") || sql.Contains("\";") || 
               sql.Contains("\\'") || sql.Contains("\\\"") ||
               (sql.Contains("''") && sql.Length > 10);
    }

    private static bool HasDangerousKeywords(string sql)
    {
        return SqlKeywordPattern.IsMatch(sql);
    }

    private static bool HasHexEncodedContent(string sql)
    {
        return HexPattern.IsMatch(sql);
    }

    private static bool HasSqlStatementChaining(string sql)
    {
        var semicolonIndex = sql.IndexOf(';');
        if (semicolonIndex >= 0 && semicolonIndex < sql.Length - 1)
        {
            var afterSemicolon = sql.Substring(semicolonIndex + 1).Trim();
            return !string.IsNullOrEmpty(afterSemicolon) && 
                   (SqlKeywordPattern.IsMatch(afterSemicolon) || afterSemicolon.StartsWith("--"));
        }
        return false;
    }

    private static bool HasStoredProcedureCalls(string sql)
    {
        return StoredProcPattern.IsMatch(sql);
    }

    private static bool HasSqlFunctions(string sql)
    {
        return SqlFunctionPattern.IsMatch(sql);
    }

    private static bool HasSqlOperators(string sql)
    {
        return SqlOperatorPattern.IsMatch(sql);
    }

    private static bool HasAdvancedPatterns(string sql)
    {
        var lowerSql = sql.ToLowerInvariant();
        
        return lowerSql.Contains("information_schema") ||
               lowerSql.Contains("sysobjects") ||
               lowerSql.Contains("master..") ||
               lowerSql.Contains("@@version") ||
               lowerSql.Contains("@@servername") ||
               lowerSql.Contains("system_user") ||
               lowerSql.Contains("db_name") ||
               lowerSql.Contains("user_name") ||
               lowerSql.Contains("host_name") ||
               lowerSql.Contains("xp_cmdshell") ||
               lowerSql.Contains("sp_configure") ||
               lowerSql.Contains("bulk insert") ||
               lowerSql.Contains("shutdown") ||
               lowerSql.Contains("waitfor delay") ||
               lowerSql.Contains("/**/") ||
               lowerSql.Contains("begin try") ||
               lowerSql.Contains("end try") ||
               lowerSql.Contains("begin catch") ||
               lowerSql.Contains("end catch");
    }

    private static bool HasClassicInjectionPatterns(string sql)
    {
        var lowerSql = sql.ToLowerInvariant();
        
        return lowerSql.Contains("' or '1'='1") ||
               lowerSql.Contains("' or 1=1") ||
               lowerSql.Contains("admin'--") ||
               lowerSql.Contains("' or ''='") ||
               lowerSql.Contains("javascript:") ||
               lowerSql.Contains("vbscript:") ||
               lowerSql.Contains("char(") ||
               lowerSql.Contains("ascii(") ||
               lowerSql.Contains("convert(");
    }
}
