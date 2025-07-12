using System.Text.RegularExpressions;

namespace VaultScope.Security.Validators;

public static class InputSanitizer
{
    private static readonly Regex HtmlTagRegex = new(@"<[^>]*>", RegexOptions.Compiled);
    private static readonly Regex ScriptRegex = new(@"<script[^>]*>.*?</script>", RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Singleline);
    private static readonly Regex SqlKeywordsRegex = new(@"\b(union|select|insert|update|delete|drop|create|alter|exec|execute|script|javascript|vbscript)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    
    public static string SanitizeHtml(string input)
    {
        if (string.IsNullOrEmpty(input))
            return string.Empty;
        
        input = ScriptRegex.Replace(input, string.Empty);
        input = HtmlTagRegex.Replace(input, string.Empty);
        
        return System.Net.WebUtility.HtmlEncode(input);
    }
    
    public static string SanitizeForLog(string input)
    {
        if (string.IsNullOrEmpty(input))
            return string.Empty;
        
        input = input.Replace('\r', '_').Replace('\n', '_');
        
        if (input.Length > 1000)
            input = input[..1000] + "...";
        
        return input;
    }
    
    public static bool ContainsSqlKeywords(string input)
    {
        if (string.IsNullOrEmpty(input))
            return false;
        
        return SqlKeywordsRegex.IsMatch(input);
    }
    
    public static string SanitizeFilePath(string path)
    {
        if (string.IsNullOrEmpty(path))
            return string.Empty;
        
        var invalidChars = Path.GetInvalidFileNameChars()
            .Concat(Path.GetInvalidPathChars())
            .Concat(new[] { ':', '*', '?', '"', '<', '>', '|' })
            .Distinct();
        
        foreach (var c in invalidChars)
        {
            path = path.Replace(c, '_');
        }
        
        path = Regex.Replace(path, @"\.{2,}", "_");
        path = path.Replace("../", "_/").Replace("..\\", "_\\");
        
        return path.Trim();
    }
    
    public static string TruncateForDisplay(string input, int maxLength = 100)
    {
        if (string.IsNullOrEmpty(input) || input.Length <= maxLength)
            return input;
        
        return input[..(maxLength - 3)] + "...";
    }
}