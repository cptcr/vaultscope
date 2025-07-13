using Microsoft.EntityFrameworkCore;
using VaultScope.Core.Models;
using VaultScope.Infrastructure.Data;
using VaultScope.Infrastructure.Data.Repositories;
using Xunit;
using FluentAssertions;

namespace VaultScope.Tests.Integration;

public class DatabaseOperationsTests : IDisposable
{
    private readonly VaultScopeDbContext _context;
    private readonly ScanResultRepository _repository;

    public DatabaseOperationsTests()
    {
        var options = new DbContextOptionsBuilder<VaultScopeDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new VaultScopeDbContext(options);
        _repository = new ScanResultRepository(_context);
        
        // Ensure database is created
        _context.Database.EnsureCreated();
    }

    [Fact]
    public async Task AddAsync_ValidScanResult_ShouldPersistToDatabase()
    {
        // Arrange
        var scanResult = CreateTestScanResult();

        // Act
        var result = await _repository.AddAsync(scanResult);

        // Assert
        result.Should().NotBeNull();
        result.Id.Should().Be(scanResult.Id);
        result.TargetUrl.Should().Be(scanResult.TargetUrl);
        result.Vulnerabilities.Should().HaveCount(2);
        result.SecurityScore.Should().NotBeNull();
        result.TestedEndpoints.Should().HaveCount(3);

        // Verify in database
        var dbEntity = await _context.ScanResults
            .Include(s => s.Vulnerabilities)
            .Include(s => s.SecurityScore)
            .Include(s => s.Endpoints)
            .FirstOrDefaultAsync(s => s.Id == scanResult.Id);

        dbEntity.Should().NotBeNull();
        dbEntity!.Vulnerabilities.Should().HaveCount(2);
        dbEntity.SecurityScore.Should().NotBeNull();
        dbEntity.Endpoints.Should().HaveCount(3);
    }

    [Fact]
    public async Task GetByIdAsync_ExistingScanResult_ShouldReturnWithAllRelations()
    {
        // Arrange
        var scanResult = CreateTestScanResult();
        await _repository.AddAsync(scanResult);

        // Act
        var result = await _repository.GetByIdAsync(scanResult.Id);

        // Assert
        result.Should().NotBeNull();
        result!.Id.Should().Be(scanResult.Id);
        result.TargetUrl.Should().Be(scanResult.TargetUrl);
        result.Vulnerabilities.Should().HaveCount(2);
        result.SecurityScore.Should().NotBeNull();
        result.SecurityScore.OverallScore.Should().Be(75.5);
        result.TestedEndpoints.Should().HaveCount(3);
    }

    [Fact]
    public async Task GetByIdAsync_NonExistentScanResult_ShouldReturnNull()
    {
        // Arrange
        var nonExistentId = Guid.NewGuid();

        // Act
        var result = await _repository.GetByIdAsync(nonExistentId);

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public async Task GetAllAsync_WithMultipleScanResults_ShouldReturnAllOrdered()
    {
        // Arrange
        var scanResult1 = CreateTestScanResult();
        scanResult1.StartTime = DateTime.UtcNow.AddHours(-2);
        
        var scanResult2 = CreateTestScanResult();
        scanResult2.StartTime = DateTime.UtcNow.AddHours(-1);
        
        var scanResult3 = CreateTestScanResult();
        scanResult3.StartTime = DateTime.UtcNow;

        await _repository.AddAsync(scanResult1);
        await _repository.AddAsync(scanResult2);
        await _repository.AddAsync(scanResult3);

        // Act
        var results = await _repository.GetAllAsync(skip: 0, take: 10);

        // Assert
        results.Should().HaveCount(3);
        // Should be ordered by StartTime descending (most recent first)
        results[0].Id.Should().Be(scanResult3.Id);
        results[1].Id.Should().Be(scanResult2.Id);
        results[2].Id.Should().Be(scanResult1.Id);
    }

    [Fact]
    public async Task GetAllAsync_WithPagination_ShouldReturnCorrectPage()
    {
        // Arrange
        for (int i = 0; i < 5; i++)
        {
            var scanResult = CreateTestScanResult();
            scanResult.StartTime = DateTime.UtcNow.AddHours(-i);
            await _repository.AddAsync(scanResult);
        }

        // Act
        var page1 = await _repository.GetAllAsync(skip: 0, take: 2);
        var page2 = await _repository.GetAllAsync(skip: 2, take: 2);
        var page3 = await _repository.GetAllAsync(skip: 4, take: 2);

        // Assert
        page1.Should().HaveCount(2);
        page2.Should().HaveCount(2);
        page3.Should().HaveCount(1); // Only 5 total records

        // Ensure no overlapping records
        var allIds = page1.Concat(page2).Concat(page3).Select(s => s.Id).ToList();
        allIds.Should().OnlyHaveUniqueItems();
    }

    [Fact]
    public async Task GetByTargetUrlAsync_WithMatchingUrl_ShouldReturnResults()
    {
        // Arrange
        var targetUrl = "http://localhost:3000";
        var scanResult1 = CreateTestScanResult();
        scanResult1.TargetUrl = targetUrl;
        
        var scanResult2 = CreateTestScanResult();
        scanResult2.TargetUrl = targetUrl;
        
        var scanResult3 = CreateTestScanResult();
        scanResult3.TargetUrl = "http://localhost:8080";

        await _repository.AddAsync(scanResult1);
        await _repository.AddAsync(scanResult2);
        await _repository.AddAsync(scanResult3);

        // Act
        var results = await _repository.GetByTargetUrlAsync(targetUrl);

        // Assert
        results.Should().HaveCount(2);
        results.Should().OnlyContain(r => r.TargetUrl == targetUrl);
    }

    [Fact]
    public async Task GetRecentScansAsync_ShouldReturnMostRecentScans()
    {
        // Arrange
        for (int i = 0; i < 15; i++)
        {
            var scanResult = CreateTestScanResult();
            scanResult.StartTime = DateTime.UtcNow.AddHours(-i);
            await _repository.AddAsync(scanResult);
        }

        // Act
        var recentScans = await _repository.GetRecentScansAsync(count: 10);

        // Assert
        recentScans.Should().HaveCount(10);
        
        // Should be ordered by StartTime descending
        for (int i = 0; i < recentScans.Count - 1; i++)
        {
            recentScans[i].StartTime.Should().BeAfter(recentScans[i + 1].StartTime);
        }
    }

    [Fact]
    public async Task UpdateAsync_ExistingScanResult_ShouldUpdateAllProperties()
    {
        // Arrange
        var scanResult = CreateTestScanResult();
        await _repository.AddAsync(scanResult);

        // Modify the scan result
        scanResult.Status = ScanStatus.Completed;
        scanResult.EndTime = DateTime.UtcNow;
        scanResult.ErrorMessage = "Test error";
        scanResult.TotalRequestsMade = 150;
        
        // Add a new vulnerability
        scanResult.Vulnerabilities.Add(new Vulnerability
        {
            Type = "New Vulnerability",
            Severity = VulnerabilitySeverity.Low,
            Title = "New Issue",
            AffectedEndpoint = "http://localhost:3000/api/new"
        });

        // Act
        await _repository.UpdateAsync(scanResult);

        // Assert
        var updatedResult = await _repository.GetByIdAsync(scanResult.Id);
        updatedResult.Should().NotBeNull();
        updatedResult!.Status.Should().Be(ScanStatus.Completed);
        updatedResult.EndTime.Should().NotBeNull();
        updatedResult.ErrorMessage.Should().Be("Test error");
        updatedResult.TotalRequestsMade.Should().Be(150);
        updatedResult.Vulnerabilities.Should().HaveCount(3); // Original 2 + 1 new
    }

    [Fact]
    public async Task UpdateAsync_NonExistentScanResult_ShouldThrowException()
    {
        // Arrange
        var nonExistentScanResult = CreateTestScanResult();

        // Act & Assert
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => _repository.UpdateAsync(nonExistentScanResult));
    }

    [Fact]
    public async Task DeleteAsync_ExistingScanResult_ShouldRemoveFromDatabase()
    {
        // Arrange
        var scanResult = CreateTestScanResult();
        await _repository.AddAsync(scanResult);

        // Verify it exists
        var existingResult = await _repository.GetByIdAsync(scanResult.Id);
        existingResult.Should().NotBeNull();

        // Act
        await _repository.DeleteAsync(scanResult.Id);

        // Assert
        var deletedResult = await _repository.GetByIdAsync(scanResult.Id);
        deletedResult.Should().BeNull();

        // Verify related entities are also deleted (cascade)
        var vulnerabilities = await _context.Vulnerabilities
            .Where(v => v.ScanResultId == scanResult.Id)
            .ToListAsync();
        vulnerabilities.Should().BeEmpty();

        var securityScore = await _context.SecurityScores
            .Where(s => s.ScanResultId == scanResult.Id)
            .FirstOrDefaultAsync();
        securityScore.Should().BeNull();

        var endpoints = await _context.Endpoints
            .Where(e => e.ScanResultId == scanResult.Id)
            .ToListAsync();
        endpoints.Should().BeEmpty();
    }

    [Fact]
    public async Task DeleteAsync_NonExistentScanResult_ShouldNotThrow()
    {
        // Arrange
        var nonExistentId = Guid.NewGuid();

        // Act & Assert
        await _repository.DeleteAsync(nonExistentId); // Should not throw
    }

    [Fact]
    public async Task GetTotalCountAsync_ShouldReturnCorrectCount()
    {
        // Arrange
        for (int i = 0; i < 7; i++)
        {
            var scanResult = CreateTestScanResult();
            await _repository.AddAsync(scanResult);
        }

        // Act
        var totalCount = await _repository.GetTotalCountAsync();

        // Assert
        totalCount.Should().Be(7);
    }

    [Fact]
    public async Task GetVulnerabilityStatisticsAsync_ShouldReturnCorrectStatistics()
    {
        // Arrange
        var scanResult1 = CreateTestScanResult();
        scanResult1.Vulnerabilities.Clear();
        scanResult1.Vulnerabilities.Add(new Vulnerability { Type = "SQL Injection", Severity = VulnerabilitySeverity.Critical });
        scanResult1.Vulnerabilities.Add(new Vulnerability { Type = "XSS", Severity = VulnerabilitySeverity.High });

        var scanResult2 = CreateTestScanResult();
        scanResult2.Vulnerabilities.Clear();
        scanResult2.Vulnerabilities.Add(new Vulnerability { Type = "SQL Injection", Severity = VulnerabilitySeverity.High });
        scanResult2.Vulnerabilities.Add(new Vulnerability { Type = "Missing Headers", Severity = VulnerabilitySeverity.Medium });
        scanResult2.Vulnerabilities.Add(new Vulnerability { Type = "Info Disclosure", Severity = VulnerabilitySeverity.Low });

        await _repository.AddAsync(scanResult1);
        await _repository.AddAsync(scanResult2);

        // Act
        var statistics = await _repository.GetVulnerabilityStatisticsAsync();

        // Assert
        statistics.Should().NotBeEmpty();
        statistics["Total"].Should().Be(5); // Total vulnerabilities
        statistics["Critical"].Should().Be(1);
        statistics["High"].Should().Be(2);
        statistics["Medium"].Should().Be(1);
        statistics["Low"].Should().Be(1);
        statistics["Type_SQL Injection"].Should().Be(2);
        statistics["Type_XSS"].Should().Be(1);
        statistics["Type_Missing Headers"].Should().Be(1);
        statistics["Type_Info Disclosure"].Should().Be(1);
    }

    [Fact]
    public async Task DatabaseInitialization_ShouldCreateAllTables()
    {
        // Act - Database should be initialized in constructor
        var canConnect = await _context.Database.CanConnectAsync();

        // Assert
        canConnect.Should().BeTrue();
        
        // Verify all tables exist by trying to query them
        var scanResultsCount = await _context.ScanResults.CountAsync();
        var vulnerabilitiesCount = await _context.Vulnerabilities.CountAsync();
        var securityScoresCount = await _context.SecurityScores.CountAsync();
        var endpointsCount = await _context.Endpoints.CountAsync();

        // Should not throw exceptions
        scanResultsCount.Should().BeGreaterThanOrEqualTo(0);
        vulnerabilitiesCount.Should().BeGreaterThanOrEqualTo(0);
        securityScoresCount.Should().BeGreaterThanOrEqualTo(0);
        endpointsCount.Should().BeGreaterThanOrEqualTo(0);
    }

    private ScanResult CreateTestScanResult()
    {
        return new ScanResult
        {
            Id = Guid.NewGuid(),
            TargetUrl = "http://localhost:3000",
            StartTime = DateTime.UtcNow.AddMinutes(-30),
            EndTime = DateTime.UtcNow,
            Status = ScanStatus.Completed,
            TotalRequestsMade = 25,
            Vulnerabilities = new List<Vulnerability>
            {
                new Vulnerability
                {
                    Type = "SQL Injection",
                    Severity = VulnerabilitySeverity.Critical,
                    Title = "Critical SQL Injection",
                    Description = "SQL injection vulnerability in user input",
                    AffectedEndpoint = "http://localhost:3000/api/users",
                    HttpMethod = "POST",
                    PayloadUsed = "'; DROP TABLE users; --",
                    Evidence = "MySQL error in response",
                    Remediation = "Use parameterized queries",
                    CweId = "CWE-89",
                    OwaspCategory = "A03:2021 - Injection",
                    ConfidenceScore = 0.95
                },
                new Vulnerability
                {
                    Type = "Cross-Site Scripting (XSS)",
                    Severity = VulnerabilitySeverity.High,
                    Title = "Reflected XSS",
                    Description = "XSS vulnerability in search parameter",
                    AffectedEndpoint = "http://localhost:3000/api/search",
                    HttpMethod = "GET",
                    PayloadUsed = "<script>alert('xss')</script>",
                    Evidence = "Script tag reflected in response",
                    Remediation = "Encode user input",
                    CweId = "CWE-79",
                    OwaspCategory = "A03:2021 - Injection",
                    ConfidenceScore = 0.90
                }
            },
            SecurityScore = new SecurityScore
            {
                OverallScore = 75.5,
                Grade = "B",
                CategoryScores = new Dictionary<string, CategoryScore>
                {
                    ["Input Validation"] = new CategoryScore
                    {
                        Category = "Input Validation",
                        Score = 60.0,
                        TestsPassed = 3,
                        TotalTests = 5
                    },
                    ["Authentication"] = new CategoryScore
                    {
                        Category = "Authentication",
                        Score = 85.0,
                        TestsPassed = 4,
                        TotalTests = 5
                    }
                },
                Strengths = new List<string> { "Strong authentication", "Good HTTPS configuration" },
                Weaknesses = new List<string> { "Input validation issues", "Missing rate limiting" },
                TestResults = new Dictionary<string, bool>
                {
                    ["SQL Injection Test"] = false,
                    ["XSS Test"] = false,
                    ["Auth Test"] = true,
                    ["HTTPS Test"] = true
                }
            },
            TestedEndpoints = new List<string>
            {
                "http://localhost:3000",
                "http://localhost:3000/api/users",
                "http://localhost:3000/api/search"
            },
            VulnerabilityCountBySeverity = new Dictionary<string, int>
            {
                ["Critical"] = 1,
                ["High"] = 1,
                ["Medium"] = 0,
                ["Low"] = 0
            }
        };
    }

    public void Dispose()
    {
        _context.Dispose();
    }
}