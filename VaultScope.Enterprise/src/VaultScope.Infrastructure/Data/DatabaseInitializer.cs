using System;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace VaultScope.Infrastructure.Data;

public class DatabaseInitializer
{
    private readonly VaultScopeDbContext _context;
    private readonly ILogger<DatabaseInitializer> _logger;
    
    public DatabaseInitializer(VaultScopeDbContext context, ILogger<DatabaseInitializer> logger)
    {
        _context = context;
        _logger = logger;
    }
    
    public async Task InitializeAsync()
    {
        try
        {
            _logger.LogInformation("Initializing database...");
            
            // Ensure database is created
            await _context.Database.EnsureCreatedAsync();
            
            // Apply any pending migrations
            if (_context.Database.IsRelational())
            {
                var pendingMigrations = await _context.Database.GetPendingMigrationsAsync();
                if (pendingMigrations.Any())
                {
                    _logger.LogInformation("Applying {Count} pending migrations...", pendingMigrations.Count());
                    await _context.Database.MigrateAsync();
                }
            }
            
            // Seed initial data if needed
            await SeedDataAsync();
            
            _logger.LogInformation("Database initialization completed successfully");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Database initialization failed");
            throw;
        }
    }
    
    private async Task SeedDataAsync()
    {
        // Check if we need to seed data
        if (await _context.ScanConfigurations.AnyAsync())
        {
            return; // Database already has data
        }
        
        _logger.LogInformation("Seeding initial data...");
        
        // Add default scan configurations
        var defaultConfigs = new[]
        {
            new Entities.ScanConfigurationEntity
            {
                Name = "Quick Scan",
                Description = "Fast security scan with basic vulnerability checks",
                TargetUrl = "http://localhost",
                Depth = "Quick",
                MaxRequestsPerSecond = 20,
                MaxConcurrentRequests = 10,
                TestAllHttpMethods = false,
                VulnerabilityTypes = new List<string> 
                { 
                    "SqlInjection", 
                    "CrossSiteScripting", 
                    "MissingSecurityHeaders" 
                },
                GenerateReport = true,
                ReportFormats = "Html;Json"
            },
            new Entities.ScanConfigurationEntity
            {
                Name = "Comprehensive Scan",
                Description = "Thorough security assessment with all vulnerability checks",
                TargetUrl = "http://localhost",
                Depth = "Comprehensive",
                MaxRequestsPerSecond = 10,
                MaxConcurrentRequests = 5,
                TestAllHttpMethods = true,
                VulnerabilityTypes = Enum.GetNames<Core.Models.VulnerabilityType>().ToList(),
                GenerateReport = true,
                ReportFormats = "Html;Json;Pdf"
            },
            new Entities.ScanConfigurationEntity
            {
                Name = "API Security Scan",
                Description = "Specialized scan for REST API endpoints",
                TargetUrl = "http://localhost:8080/api",
                Depth = "Normal",
                MaxRequestsPerSecond = 15,
                MaxConcurrentRequests = 8,
                TestAllHttpMethods = true,
                VulnerabilityTypes = new List<string>
                {
                    "SqlInjection",
                    "CrossSiteScripting",
                    "XmlExternalEntity",
                    "CommandInjection",
                    "AuthenticationBypass",
                    "RateLimiting",
                    "MissingSecurityHeaders"
                },
                GenerateReport = true,
                ReportFormats = "Json"
            }
        };
        
        _context.ScanConfigurations.AddRange(defaultConfigs);
        await _context.SaveChangesAsync();
        
        _logger.LogInformation("Seeded {Count} default scan configurations", defaultConfigs.Length);
    }
}