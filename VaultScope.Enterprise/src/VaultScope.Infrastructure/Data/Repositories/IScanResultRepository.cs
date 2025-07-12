using VaultScope.Core.Models;

namespace VaultScope.Infrastructure.Data.Repositories;

public interface IScanResultRepository
{
    Task<ScanResult?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default);
    Task<List<ScanResult>> GetAllAsync(int skip = 0, int take = 50, CancellationToken cancellationToken = default);
    Task<List<ScanResult>> GetByTargetUrlAsync(string targetUrl, CancellationToken cancellationToken = default);
    Task<List<ScanResult>> GetRecentScansAsync(int count = 10, CancellationToken cancellationToken = default);
    Task<ScanResult> AddAsync(ScanResult scanResult, CancellationToken cancellationToken = default);
    Task UpdateAsync(ScanResult scanResult, CancellationToken cancellationToken = default);
    Task DeleteAsync(Guid id, CancellationToken cancellationToken = default);
    Task<int> GetTotalCountAsync(CancellationToken cancellationToken = default);
    Task<Dictionary<string, int>> GetVulnerabilityStatisticsAsync(CancellationToken cancellationToken = default);
}