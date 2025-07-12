using VaultScope.Infrastructure.Data.Entities;

namespace VaultScope.Infrastructure.Data.Repositories;

public interface IReportRepository
{
    Task<ReportEntity?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default);
    Task<List<ReportEntity>> GetByScanResultIdAsync(Guid scanResultId, CancellationToken cancellationToken = default);
    Task<List<ReportEntity>> GetRecentReportsAsync(int count = 10, CancellationToken cancellationToken = default);
    Task<ReportEntity> AddAsync(ReportEntity report, CancellationToken cancellationToken = default);
    Task DeleteAsync(Guid id, CancellationToken cancellationToken = default);
    Task CleanupOldReportsAsync(DateTime olderThan, CancellationToken cancellationToken = default);
}