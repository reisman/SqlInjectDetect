using System.Text.RegularExpressions;

namespace SqlInjectDetect;

public sealed class SqlInjectDetector
{
    // Compiled regex patterns for performance
    private static readonly Regex SqlCommentPattern = new(@"(/\*.*?\*/|--.*|#.*)", 
        RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Singleline);
    
    private static readonly Regex UnionPattern = new(@"\bunion(\s+all)?\s+select\b", 
        RegexOptions.Compiled | RegexOptions.IgnoreCase);
    
    private static readonly Regex SqlKeywordPattern = new(@"\b(select|insert|update|delete|drop|create|alter|exec|execute)\b", 
        RegexOptions.Compiled | RegexOptions.IgnoreCase);
    
    private static readonly Regex HexPattern = new(@"\b0x[0-9a-f]+\b", 
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex StoredProcPattern = new(@"\b(sp_|xp_)\w*", 
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // Dangerous keywords that should trigger detection
    private static readonly HashSet<string> DangerousKeywords = new(StringComparer.OrdinalIgnoreCase)
    {
        "select", "insert", "update", "delete", "drop", "create", "alter", 
        "exec", "execute", "union", "script", "javascript", "vbscript",
        "char", "ascii", "substring", "cast", "convert"
    };

    public bool ContainsSqlInjection(string? sql)
    {
        if (string.IsNullOrWhiteSpace(sql))
            return false;

        // Normalize input for analysis
        var normalizedSql = sql.Trim();
        
        // Check for common SQL injection patterns
        if (HasSqlComments(normalizedSql) ||
            HasUnionBasedInjection(normalizedSql) ||
            HasQuoteEscapeAttempts(normalizedSql) ||
            HasDangerousKeywords(normalizedSql) ||
            HasHexEncodedContent(normalizedSql) ||
            HasSqlStatementChaining(normalizedSql) ||
            HasStoredProcedureCalls(normalizedSql) ||
            HasClassicInjectionPatterns(normalizedSql))
        {
            return true;
        }

        return false;
    }

    private bool HasSqlComments(string sql)
    {
        return SqlCommentPattern.IsMatch(sql);
    }

    private bool HasUnionBasedInjection(string sql)
    {
        return UnionPattern.IsMatch(sql);
    }

    private bool HasQuoteEscapeAttempts(string sql)
    {
        // Look for quote manipulation attempts that are likely malicious
        return sql.Contains("';") || sql.Contains("\";") || 
               sql.Contains("\\'") || sql.Contains("\\\"") ||
               (sql.Contains("''") && sql.Length > 10); // Only flag double quotes in longer strings
    }

    private bool HasDangerousKeywords(string sql)
    {
        // Check if the string contains SQL keywords
        return SqlKeywordPattern.IsMatch(sql);
    }

    private bool HasHexEncodedContent(string sql)
    {
        return HexPattern.IsMatch(sql);
    }

    private bool HasSqlStatementChaining(string sql)
    {
        // Check for multiple statements (semicolon followed by SQL keywords)
        var semicolonIndex = sql.IndexOf(';');
        if (semicolonIndex >= 0 && semicolonIndex < sql.Length - 1)
        {
            var afterSemicolon = sql.Substring(semicolonIndex + 1).Trim();
            return !string.IsNullOrEmpty(afterSemicolon) && 
                   (SqlKeywordPattern.IsMatch(afterSemicolon) || afterSemicolon.StartsWith("--"));
        }
        return false;
    }

    private bool HasStoredProcedureCalls(string sql)
    {
        return StoredProcPattern.IsMatch(sql);
    }

    private bool HasClassicInjectionPatterns(string sql)
    {
        // Classic injection patterns
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