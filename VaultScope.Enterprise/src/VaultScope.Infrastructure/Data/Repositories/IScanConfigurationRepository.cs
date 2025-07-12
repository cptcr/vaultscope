using VaultScope.Core.Models;

namespace VaultScope.Infrastructure.Data.Repositories;

public interface IScanConfigurationRepository
{
    Task<ScanConfiguration?> GetByNameAsync(string name, CancellationToken cancellationToken = default);
    Task<List<(string Name, ScanConfiguration Configuration)>> GetAllAsync(CancellationToken cancellationToken = default);
    Task<(string Name, ScanConfiguration Configuration)> SaveAsync(string name, ScanConfiguration configuration, CancellationToken cancellationToken = default);
    Task DeleteAsync(string name, CancellationToken cancellationToken = default);
    Task<bool> ExistsAsync(string name, CancellationToken cancellationToken = default);
}