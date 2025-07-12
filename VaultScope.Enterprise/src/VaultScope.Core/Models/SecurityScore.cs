namespace VaultScope.Core.Models;

public class SecurityScore
{
    public double OverallScore { get; set; }
    
    public string Grade { get; set; } = "F";
    
    public Dictionary<string, CategoryScore> CategoryScores { get; set; } = new();
    
    public List<string> Strengths { get; set; } = new();
    
    public List<string> Weaknesses { get; set; } = new();
    
    public List<string> Recommendations { get; set; } = new();
    
    public DateTime CalculatedAt { get; set; } = DateTime.UtcNow;
    
    public static string CalculateGrade(double score)
    {
        return score switch
        {
            >= 90 => "A+",
            >= 85 => "A",
            >= 80 => "A-",
            >= 75 => "B+",
            >= 70 => "B",
            >= 65 => "B-",
            >= 60 => "C+",
            >= 55 => "C",
            >= 50 => "C-",
            >= 45 => "D+",
            >= 40 => "D",
            >= 35 => "D-",
            _ => "F"
        };
    }
}

public class CategoryScore
{
    public string Category { get; set; } = string.Empty;
    
    public double Score { get; set; }
    
    public int TestsPassed { get; set; }
    
    public int TotalTests { get; set; }
    
    public List<string> FailedTests { get; set; } = new();
}