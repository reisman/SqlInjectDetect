using System.Text.RegularExpressions;

namespace SqlInjectDetect;

public static class SqlInjectDetector
{
    // A single, comprehensive, compiled regex for performance.
    // This pattern combines multiple checks for comments, keywords, functions, and classic injection strings.
    private static readonly Regex CombinedSqlInjectionPattern = new Regex(
        // Comments: /*...*/, --, #
        @"/\*.*?\*/|\s--\s|--$|\s#\s|#$|" +

        // Union-based
        @"\bunion(\s+all)?\s+select\b|" +

        // Dangerous keywords followed by syntax, not just the keyword alone.
        // This reduces false positives for valid text containing words like "select" or "insert".
        @"\b(select\s+.+from|insert\s+into|update\s+.+set|delete\s+from|drop\s+(table|database)|create\s+(table|database)|alter\s+table|exec\s+.+|execute\s+.+|declare\s+@|bulk\s+insert|shutdown|waitfor\s+delay)\b|" +
        
        // Standalone keywords that are still suspicious but can be part of normal language.
        // We will look for more context rather than just the keyword.
        @"\b(begin\s+transaction|begin\s+try|end\s+try|end\s+transaction|if\s*\(|while\s*\(|case\s+when|group\s+by|order\s+by)\b|" +

        // System tables/views that are highly suspicious
        @"\b(information_schema|sysobjects|xp_cmdshell|xp_dirtree|sp_configure|openrowset|openquery|dbcc)\b|" +

        // Hex encoding
        @"\b0x[0-9a-f]+\b|" +

        // Stored procedures
        @"\b(sp_|xp_)\w*|" +

        // SQL functions and system variables often used in attacks
        @"\b(char|ascii|substring|cast|convert|nchar|stuff|replace|reverse|space|len|datalength|system_user|db_name|user_name|host_name|load_file|utl_http.request|@@version|@@servername)\s*\(|" +

        // Operators and chaining
        @"(\|\||&&|\+\s*\(|exists\s*\()|" +

        // Classic injection patterns
        @"' or '1'='1|' or 1=1|admin'--|' or ''='|" +
        
        // Scripting attempts
        @"javascript:|vbscript:",
        RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Singleline);

    private static readonly Regex UrlEncodedPattern = new(@"%[0-9a-f]{2}", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public static bool ContainsSqlInjection(string? sql)
    {
        if (string.IsNullOrWhiteSpace(sql)) return false;

        var normalizedSql = sql.Trim();

        // Perform cheaper, non-regex checks first.
        if (HasQuoteEscapeAttempts(normalizedSql) || HasSqlStatementChaining(normalizedSql))
        {
            return true;
        }

        // Use the main combined regex for a single, efficient pass.
        if (CombinedSqlInjectionPattern.IsMatch(normalizedSql))
        {
            return true;
        }

        // Only decode and re-check if the string contains URL-encoded characters.
        // This avoids the overhead of decoding for the majority of inputs.
        if (UrlEncodedPattern.IsMatch(normalizedSql))
        {
            var decodedSql = TryUrlDecode(normalizedSql);
            if (decodedSql != normalizedSql) // Check only if decoding produced a new string
            {
                if (HasQuoteEscapeAttempts(decodedSql) || 
                    HasSqlStatementChaining(decodedSql) || 
                    CombinedSqlInjectionPattern.IsMatch(decodedSql))
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static string TryUrlDecode(string input)
    {
        try
        {
            // The pattern check is already done, so we can just try to unescape.
            return Uri.UnescapeDataString(input);
        }
        catch
        {
            // If decoding fails (e.g., malformed input), return the original string.
            return input;
        }
    }

    private static bool HasQuoteEscapeAttempts(string sql)
    {
        // Simple quote checks remain fast.
        // Check for a single quote followed by a semicolon or a double quote followed by a semicolon.
        // Also check for escaped quotes.
        // The check for `''` is narrowed to likely attack patterns to avoid false positives on names like "O'Connor".
        return sql.Contains("';") || sql.Contains("\";") ||
               sql.Contains("\\'") || sql.Contains("\\\"") ||
               (sql.Contains("''") && sql.Length > 10); // Heuristic to avoid flagging simple escaped quotes in short strings
    }

    private static bool HasSqlStatementChaining(string sql)
    {
        var semicolonIndex = sql.IndexOf(';');
        if (semicolonIndex > -1 && semicolonIndex < sql.Length - 1)
        {
            // Check if there's another command after a semicolon
            var subsequent = sql.Substring(semicolonIndex + 1).TrimStart();
            if (subsequent.Length > 0)
            {
                // A simple check for a keyword is enough to be suspicious.
                return subsequent.StartsWith("--", StringComparison.Ordinal) ||
                       subsequent.StartsWith("select", StringComparison.OrdinalIgnoreCase) ||
                       subsequent.StartsWith("insert", StringComparison.OrdinalIgnoreCase) ||
                       subsequent.StartsWith("update", StringComparison.OrdinalIgnoreCase) ||
                       subsequent.StartsWith("delete", StringComparison.OrdinalIgnoreCase) ||
                       subsequent.StartsWith("drop", StringComparison.OrdinalIgnoreCase);
            }
        }
        return false;
    }
}
