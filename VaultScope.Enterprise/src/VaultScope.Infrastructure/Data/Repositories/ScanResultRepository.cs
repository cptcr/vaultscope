using Microsoft.EntityFrameworkCore;
using VaultScope.Core.Models;
using VaultScope.Infrastructure.Data.Entities;

namespace VaultScope.Infrastructure.Data.Repositories;

public class ScanResultRepository : IScanResultRepository
{
    private readonly VaultScopeDbContext _context;
    
    public ScanResultRepository(VaultScopeDbContext context)
    {
        _context = context;
    }
    
    public async Task<ScanResult?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default)
    {
        var entity = await _context.ScanResults
            .Include(s => s.Vulnerabilities)
            .Include(s => s.SecurityScore)
                .ThenInclude(sc => sc!.CategoryScores)
            .Include(s => s.Endpoints)
            .Include(s => s.Configuration)
            .FirstOrDefaultAsync(s => s.Id == id, cancellationToken);
        
        return entity?.ToDomainModel();
    }
    
    public async Task<List<ScanResult>> GetAllAsync(int skip = 0, int take = 50, CancellationToken cancellationToken = default)
    {
        var entities = await _context.ScanResults
            .Include(s => s.Vulnerabilities)
            .Include(s => s.SecurityScore)
            .Include(s => s.Endpoints)
            .OrderByDescending(s => s.StartTime)
            .Skip(skip)
            .Take(take)
            .ToListAsync(cancellationToken);
        
        return entities.Select(e => e.ToDomainModel()).ToList();
    }
    
    public async Task<List<ScanResult>> GetByTargetUrlAsync(string targetUrl, CancellationToken cancellationToken = default)
    {
        var entities = await _context.ScanResults
            .Include(s => s.Vulnerabilities)
            .Include(s => s.SecurityScore)
            .Include(s => s.Endpoints)
            .Where(s => s.TargetUrl == targetUrl)
            .OrderByDescending(s => s.StartTime)
            .ToListAsync(cancellationToken);
        
        return entities.Select(e => e.ToDomainModel()).ToList();
    }
    
    public async Task<List<ScanResult>> GetRecentScansAsync(int count = 10, CancellationToken cancellationToken = default)
    {
        var entities = await _context.ScanResults
            .Include(s => s.Vulnerabilities)
            .Include(s => s.SecurityScore)
            .Include(s => s.Endpoints)
            .OrderByDescending(s => s.StartTime)
            .Take(count)
            .ToListAsync(cancellationToken);
        
        return entities.Select(e => e.ToDomainModel()).ToList();
    }
    
    public async Task<ScanResult> AddAsync(ScanResult scanResult, CancellationToken cancellationToken = default)
    {
        var entity = ScanResultEntity.FromDomainModel(scanResult);
        
        // Add vulnerabilities
        foreach (var vulnerability in scanResult.Vulnerabilities)
        {
            entity.Vulnerabilities.Add(VulnerabilityEntity.FromDomainModel(vulnerability, entity.Id));
        }
        
        // Add security score
        if (scanResult.SecurityScore != null)
        {
            entity.SecurityScore = SecurityScoreEntity.FromDomainModel(scanResult.SecurityScore, entity.Id);
        }
        
        // Add endpoints
        foreach (var endpoint in scanResult.TestedEndpoints)
        {
            entity.Endpoints.Add(new EndpointEntity
            {
                Url = endpoint,
                Path = new Uri(endpoint).AbsolutePath,
                VulnerabilityCount = scanResult.Vulnerabilities.Count(v => v.AffectedEndpoint == endpoint),
                ScanResultId = entity.Id
            });
        }
        
        _context.ScanResults.Add(entity);
        await _context.SaveChangesAsync(cancellationToken);
        
        return entity.ToDomainModel();
    }
    
    public async Task UpdateAsync(ScanResult scanResult, CancellationToken cancellationToken = default)
    {
        var entity = await _context.ScanResults
            .Include(s => s.Vulnerabilities)
            .Include(s => s.SecurityScore)
            .Include(s => s.Endpoints)
            .FirstOrDefaultAsync(s => s.Id == scanResult.Id, cancellationToken);
        
        if (entity == null)
        {
            throw new InvalidOperationException($"ScanResult with ID {scanResult.Id} not found");
        }
        
        // Update basic properties
        entity.TargetUrl = scanResult.TargetUrl;
        entity.StartTime = scanResult.StartTime;
        entity.EndTime = scanResult.EndTime;
        entity.Status = scanResult.Status.ToString();
        entity.TotalRequestsMade = scanResult.TotalRequestsMade;
        entity.ErrorMessage = scanResult.ErrorMessage;
        
        // Update vulnerabilities (simple replace strategy)
        _context.Vulnerabilities.RemoveRange(entity.Vulnerabilities);
        foreach (var vulnerability in scanResult.Vulnerabilities)
        {
            entity.Vulnerabilities.Add(VulnerabilityEntity.FromDomainModel(vulnerability, entity.Id));
        }
        
        // Update security score
        if (entity.SecurityScore != null)
        {
            _context.SecurityScores.Remove(entity.SecurityScore);
        }
        if (scanResult.SecurityScore != null)
        {
            entity.SecurityScore = SecurityScoreEntity.FromDomainModel(scanResult.SecurityScore, entity.Id);
        }
        
        // Update endpoints
        _context.Endpoints.RemoveRange(entity.Endpoints);
        foreach (var endpoint in scanResult.TestedEndpoints)
        {
            entity.Endpoints.Add(new EndpointEntity
            {
                Url = endpoint,
                Path = new Uri(endpoint).AbsolutePath,
                VulnerabilityCount = scanResult.Vulnerabilities.Count(v => v.AffectedEndpoint == endpoint),
                ScanResultId = entity.Id
            });
        }
        
        await _context.SaveChangesAsync(cancellationToken);
    }
    
    public async Task DeleteAsync(Guid id, CancellationToken cancellationToken = default)
    {
        var entity = await _context.ScanResults.FindAsync(new object[] { id }, cancellationToken);
        if (entity != null)
        {
            _context.ScanResults.Remove(entity);
            await _context.SaveChangesAsync(cancellationToken);
        }
    }
    
    public async Task<int> GetTotalCountAsync(CancellationToken cancellationToken = default)
    {
        return await _context.ScanResults.CountAsync(cancellationToken);
    }
    
    public async Task<Dictionary<string, int>> GetVulnerabilityStatisticsAsync(CancellationToken cancellationToken = default)
    {
        var stats = await _context.Vulnerabilities
            .GroupBy(v => v.Severity)
            .Select(g => new { Severity = g.Key.ToString(), Count = g.Count() })
            .ToDictionaryAsync(x => x.Severity, x => x.Count, cancellationToken);
        
        // Add vulnerability type statistics
        var typeStats = await _context.Vulnerabilities
            .GroupBy(v => v.Type)
            .Select(g => new { Type = g.Key, Count = g.Count() })
            .ToDictionaryAsync(x => $"Type_{x.Type}", x => x.Count, cancellationToken);
        
        foreach (var typeStat in typeStats)
        {
            stats[typeStat.Key] = typeStat.Value;
        }
        
        // Add total count
        stats["Total"] = await _context.Vulnerabilities.CountAsync(cancellationToken);
        
        return stats;
    }
}