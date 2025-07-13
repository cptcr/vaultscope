using Microsoft.EntityFrameworkCore;
using VaultScope.Core.Models;
using VaultScope.Infrastructure.Data.Entities;
using VaultScope.Infrastructure.Json;

namespace VaultScope.Infrastructure.Data.Repositories;

public class ScanConfigurationRepository : IScanConfigurationRepository
{
    private readonly VaultScopeDbContext _context;
    
    public ScanConfigurationRepository(VaultScopeDbContext context)
    {
        _context = context;
    }
    
    public async Task<ScanConfiguration?> GetByNameAsync(string name, CancellationToken cancellationToken = default)
    {
        var entity = await _context.ScanConfigurations
            .FirstOrDefaultAsync(c => c.Name == name && c.IsActive, cancellationToken);
        
        return entity?.ToDomainModel();
    }
    
    public async Task<List<(string Name, ScanConfiguration Configuration)>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        var entities = await _context.ScanConfigurations
            .Where(c => c.IsActive)
            .OrderBy(c => c.Name)
            .ToListAsync(cancellationToken);
        
        return entities.Select(e => (e.Name, e.ToDomainModel())).ToList();
    }
    
    public async Task<(string Name, ScanConfiguration Configuration)> SaveAsync(
        string name, 
        ScanConfiguration configuration, 
        CancellationToken cancellationToken = default)
    {
        var existingEntity = await _context.ScanConfigurations
            .FirstOrDefaultAsync(c => c.Name == name, cancellationToken);
        
        if (existingEntity != null)
        {
            // Update existing
            existingEntity.TargetUrl = configuration.TargetUrl;
            existingEntity.IncludedPaths = configuration.IncludedPaths;
            existingEntity.ExcludedPaths = configuration.ExcludedPaths;
            existingEntity.VulnerabilityTypes = configuration.VulnerabilityTypes.Select(v => v.ToString()).ToList();
            existingEntity.MaxRequestsPerSecond = configuration.MaxRequestsPerSecond;
            existingEntity.RequestTimeout = configuration.RequestTimeout;
            existingEntity.MaxConcurrentRequests = configuration.MaxConcurrentRequests;
            existingEntity.FollowRedirects = configuration.FollowRedirects;
            existingEntity.MaxRedirects = configuration.MaxRedirects;
            existingEntity.TestAllHttpMethods = configuration.TestAllHttpMethods;
            existingEntity.CustomHeaders = configuration.CustomHeaders.ToDictionary(h => h, h => h);
            existingEntity.Depth = configuration.Depth.ToString();
            existingEntity.GenerateReport = configuration.GenerateReport;
            existingEntity.ReportFormats = string.Join(";", configuration.ReportFormats.Select(f => f.ToString()));
            existingEntity.AuthType = configuration.Authentication?.Type.ToString();
            existingEntity.AuthToken = configuration.Authentication?.Token;
            existingEntity.AuthHeaders = configuration.Authentication != null 
                ? System.Text.Json.JsonSerializer.Serialize(configuration.Authentication.Headers, VaultScopeJsonContext.Default.DictionaryStringString) 
                : null;
            existingEntity.IsActive = true;
        }
        else
        {
            // Create new
            existingEntity = ScanConfigurationEntity.FromDomainModel(configuration, name);
            _context.ScanConfigurations.Add(existingEntity);
        }
        
        await _context.SaveChangesAsync(cancellationToken);
        
        return (name, existingEntity.ToDomainModel());
    }
    
    public async Task DeleteAsync(string name, CancellationToken cancellationToken = default)
    {
        var entity = await _context.ScanConfigurations
            .FirstOrDefaultAsync(c => c.Name == name, cancellationToken);
        
        if (entity != null)
        {
            // Soft delete
            entity.IsActive = false;
            await _context.SaveChangesAsync(cancellationToken);
        }
    }
    
    public async Task<bool> ExistsAsync(string name, CancellationToken cancellationToken = default)
    {
        return await _context.ScanConfigurations
            .AnyAsync(c => c.Name == name && c.IsActive, cancellationToken);
    }
}