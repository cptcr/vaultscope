using VaultScope.Core.Models;

namespace VaultScope.Infrastructure.Data.Entities;

public class SecurityScoreEntity : BaseEntity
{
    public double OverallScore { get; set; }
    public string Grade { get; set; } = string.Empty;
    public DateTime CalculatedAt { get; set; }
    
    // Stored as JSON or separate table
    public List<CategoryScoreEntity> CategoryScores { get; set; } = new();
    
    // Stored as semicolon-separated strings
    public List<string> Strengths { get; set; } = new();
    public List<string> Weaknesses { get; set; } = new();
    public List<string> Recommendations { get; set; } = new();
    
    // Foreign key
    public Guid ScanResultId { get; set; }
    public ScanResultEntity ScanResult { get; set; } = null!;
    
    public static SecurityScoreEntity FromDomainModel(SecurityScore model, Guid scanResultId)
    {
        return new SecurityScoreEntity
        {
            OverallScore = model.OverallScore,
            Grade = model.Grade,
            CalculatedAt = model.CalculatedAt,
            CategoryScores = model.CategoryScores.Select(c => new CategoryScoreEntity
            {
                Category = c.Key,
                Score = c.Value.Score,
                TestsPassed = c.Value.TestsPassed,
                TotalTests = c.Value.TotalTests,
                FailedTests = c.Value.FailedTests
            }).ToList(),
            Strengths = model.Strengths,
            Weaknesses = model.Weaknesses,
            Recommendations = model.Recommendations,
            ScanResultId = scanResultId
        };
    }
    
    public SecurityScore ToDomainModel()
    {
        return new SecurityScore
        {
            OverallScore = OverallScore,
            Grade = Grade,
            CalculatedAt = CalculatedAt,
            CategoryScores = CategoryScores.ToDictionary(
                c => c.Category,
                c => new CategoryScore
                {
                    Category = c.Category,
                    Score = c.Score,
                    TestsPassed = c.TestsPassed,
                    TotalTests = c.TotalTests,
                    FailedTests = c.FailedTests
                }
            ),
            Strengths = Strengths,
            Weaknesses = Weaknesses,
            Recommendations = Recommendations
        };
    }
}

public class CategoryScoreEntity
{
    public string Category { get; set; } = string.Empty;
    public double Score { get; set; }
    public int TestsPassed { get; set; }
    public int TotalTests { get; set; }
    public List<string> FailedTests { get; set; } = new();
}