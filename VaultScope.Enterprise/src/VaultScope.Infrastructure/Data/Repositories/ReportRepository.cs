using Microsoft.EntityFrameworkCore;
using VaultScope.Infrastructure.Data.Entities;

namespace VaultScope.Infrastructure.Data.Repositories;

public class ReportRepository : IReportRepository
{
    private readonly VaultScopeDbContext _context;
    
    public ReportRepository(VaultScopeDbContext context)
    {
        _context = context;
    }
    
    public async Task<ReportEntity?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default)
    {
        return await _context.Reports
            .Include(r => r.ScanResult)
            .FirstOrDefaultAsync(r => r.Id == id, cancellationToken);
    }
    
    public async Task<List<ReportEntity>> GetByScanResultIdAsync(Guid scanResultId, CancellationToken cancellationToken = default)
    {
        return await _context.Reports
            .Where(r => r.ScanResultId == scanResultId)
            .OrderByDescending(r => r.GeneratedAt)
            .ToListAsync(cancellationToken);
    }
    
    public async Task<List<ReportEntity>> GetRecentReportsAsync(int count = 10, CancellationToken cancellationToken = default)
    {
        return await _context.Reports
            .Include(r => r.ScanResult)
            .OrderByDescending(r => r.GeneratedAt)
            .Take(count)
            .ToListAsync(cancellationToken);
    }
    
    public async Task<ReportEntity> AddAsync(ReportEntity report, CancellationToken cancellationToken = default)
    {
        _context.Reports.Add(report);
        await _context.SaveChangesAsync(cancellationToken);
        return report;
    }
    
    public async Task DeleteAsync(Guid id, CancellationToken cancellationToken = default)
    {
        var report = await _context.Reports.FindAsync(new object[] { id }, cancellationToken);
        if (report != null)
        {
            // Delete the file if it exists
            if (!string.IsNullOrEmpty(report.FilePath) && File.Exists(report.FilePath))
            {
                try
                {
                    File.Delete(report.FilePath);
                }
                catch
                {
                    // Log error but continue
                }
            }
            
            _context.Reports.Remove(report);
            await _context.SaveChangesAsync(cancellationToken);
        }
    }
    
    public async Task CleanupOldReportsAsync(DateTime olderThan, CancellationToken cancellationToken = default)
    {
        var oldReports = await _context.Reports
            .Where(r => r.GeneratedAt < olderThan)
            .ToListAsync(cancellationToken);
        
        foreach (var report in oldReports)
        {
            // Delete the file if it exists
            if (!string.IsNullOrEmpty(report.FilePath) && File.Exists(report.FilePath))
            {
                try
                {
                    File.Delete(report.FilePath);
                }
                catch
                {
                    // Log error but continue
                }
            }
        }
        
        _context.Reports.RemoveRange(oldReports);
        await _context.SaveChangesAsync(cancellationToken);
    }
}