using Microsoft.EntityFrameworkCore;
using VaultScope.Infrastructure.Data.Entities;

namespace VaultScope.Infrastructure.Data;

public class VaultScopeDbContext : DbContext
{
    public DbSet<ScanResultEntity> ScanResults { get; set; } = null!;
    public DbSet<VulnerabilityEntity> Vulnerabilities { get; set; } = null!;
    public DbSet<SecurityScoreEntity> SecurityScores { get; set; } = null!;
    public DbSet<EndpointEntity> Endpoints { get; set; } = null!;
    public DbSet<ScanConfigurationEntity> ScanConfigurations { get; set; } = null!;
    public DbSet<ReportEntity> Reports { get; set; } = null!;
    
    public VaultScopeDbContext(DbContextOptions<VaultScopeDbContext> options)
        : base(options)
    {
    }
    
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        
        // ScanResult configuration
        modelBuilder.Entity<ScanResultEntity>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.TargetUrl).IsRequired().HasMaxLength(500);
            entity.Property(e => e.Status).IsRequired().HasMaxLength(50);
            entity.Property(e => e.ErrorMessage).HasMaxLength(1000);
            
            entity.HasMany(e => e.Vulnerabilities)
                  .WithOne(v => v.ScanResult)
                  .HasForeignKey(v => v.ScanResultId)
                  .OnDelete(DeleteBehavior.Cascade);
            
            entity.HasOne(e => e.SecurityScore)
                  .WithOne(s => s.ScanResult)
                  .HasForeignKey<SecurityScoreEntity>(s => s.ScanResultId)
                  .OnDelete(DeleteBehavior.Cascade);
            
            entity.HasMany(e => e.Endpoints)
                  .WithOne(ep => ep.ScanResult)
                  .HasForeignKey(ep => ep.ScanResultId)
                  .OnDelete(DeleteBehavior.Cascade);
            
            entity.HasOne(e => e.Configuration)
                  .WithMany()
                  .HasForeignKey(e => e.ConfigurationId)
                  .OnDelete(DeleteBehavior.SetNull);
            
            entity.HasIndex(e => e.StartTime);
            entity.HasIndex(e => e.Status);
        });
        
        // Vulnerability configuration
        modelBuilder.Entity<VulnerabilityEntity>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Type).IsRequired().HasMaxLength(100);
            entity.Property(e => e.Title).IsRequired().HasMaxLength(500);
            entity.Property(e => e.Description).IsRequired();
            entity.Property(e => e.AffectedEndpoint).IsRequired().HasMaxLength(500);
            entity.Property(e => e.HttpMethod).IsRequired().HasMaxLength(10);
            entity.Property(e => e.CweId).HasMaxLength(20);
            entity.Property(e => e.OwaspCategory).HasMaxLength(100);
            
            entity.HasIndex(e => e.Severity);
            entity.HasIndex(e => e.Type);
            entity.HasIndex(e => e.DiscoveredAt);
        });
        
        // SecurityScore configuration
        modelBuilder.Entity<SecurityScoreEntity>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Grade).IsRequired().HasMaxLength(5);
            entity.Property(e => e.OverallScore).HasPrecision(5, 2);
            
            entity.OwnsMany(e => e.CategoryScores, cs =>
            {
                cs.Property(c => c.Category).IsRequired().HasMaxLength(100);
                cs.Property(c => c.Score).HasPrecision(5, 2);
            });
            
            entity.Property(e => e.Strengths)
                  .HasConversion(
                      v => string.Join(';', v),
                      v => v.Split(';', StringSplitOptions.RemoveEmptyEntries).ToList());
            
            entity.Property(e => e.Weaknesses)
                  .HasConversion(
                      v => string.Join(';', v),
                      v => v.Split(';', StringSplitOptions.RemoveEmptyEntries).ToList());
            
            entity.Property(e => e.Recommendations)
                  .HasConversion(
                      v => string.Join(';', v),
                      v => v.Split(';', StringSplitOptions.RemoveEmptyEntries).ToList());
        });
        
        // Endpoint configuration
        modelBuilder.Entity<EndpointEntity>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Url).IsRequired().HasMaxLength(500);
            entity.Property(e => e.Path).IsRequired().HasMaxLength(500);
            
            entity.HasIndex(e => new { e.ScanResultId, e.Url });
        });
        
        // ScanConfiguration configuration
        modelBuilder.Entity<ScanConfigurationEntity>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Name).IsRequired().HasMaxLength(200);
            entity.Property(e => e.TargetUrl).IsRequired().HasMaxLength(500);
            
            entity.Property(e => e.IncludedPaths)
                  .HasConversion(
                      v => string.Join(';', v),
                      v => v.Split(';', StringSplitOptions.RemoveEmptyEntries).ToList());
            
            entity.Property(e => e.ExcludedPaths)
                  .HasConversion(
                      v => string.Join(';', v),
                      v => v.Split(';', StringSplitOptions.RemoveEmptyEntries).ToList());
            
            entity.Property(e => e.VulnerabilityTypes)
                  .HasConversion(
                      v => string.Join(';', v),
                      v => v.Split(';', StringSplitOptions.RemoveEmptyEntries).ToList());
            
            entity.Property(e => e.CustomHeaders)
                  .HasConversion(
                      v => System.Text.Json.JsonSerializer.Serialize(v, (System.Text.Json.JsonSerializerOptions?)null),
                      v => System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(v, (System.Text.Json.JsonSerializerOptions?)null) ?? new Dictionary<string, string>());
            
            entity.HasIndex(e => e.Name);
            entity.HasIndex(e => e.CreatedAt);
        });
        
        // Report configuration
        modelBuilder.Entity<ReportEntity>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.FileName).IsRequired().HasMaxLength(500);
            entity.Property(e => e.Format).IsRequired().HasMaxLength(50);
            entity.Property(e => e.FilePath).HasMaxLength(1000);
            
            entity.HasOne(e => e.ScanResult)
                  .WithMany(s => s.Reports)
                  .HasForeignKey(e => e.ScanResultId)
                  .OnDelete(DeleteBehavior.Cascade);
            
            entity.HasIndex(e => e.GeneratedAt);
            entity.HasIndex(e => e.Format);
        });
        
        // Apply timestamp conventions
        foreach (var entityType in modelBuilder.Model.GetEntityTypes())
        {
            var createdAtProperty = entityType.FindProperty("CreatedAt");
            if (createdAtProperty != null && createdAtProperty.ClrType == typeof(DateTime))
            {
                createdAtProperty.SetDefaultValueSql("CURRENT_TIMESTAMP");
            }
            
            var updatedAtProperty = entityType.FindProperty("UpdatedAt");
            if (updatedAtProperty != null && updatedAtProperty.ClrType == typeof(DateTime))
            {
                updatedAtProperty.SetDefaultValueSql("CURRENT_TIMESTAMP");
            }
        }
    }
    
    public override int SaveChanges()
    {
        UpdateTimestamps();
        return base.SaveChanges();
    }
    
    public override async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        UpdateTimestamps();
        return await base.SaveChangesAsync(cancellationToken);
    }
    
    private void UpdateTimestamps()
    {
        var entries = ChangeTracker.Entries()
            .Where(e => e.Entity is BaseEntity && (e.State == EntityState.Added || e.State == EntityState.Modified));
        
        foreach (var entry in entries)
        {
            var entity = (BaseEntity)entry.Entity;
            
            if (entry.State == EntityState.Added)
            {
                entity.CreatedAt = DateTime.UtcNow;
            }
            
            entity.UpdatedAt = DateTime.UtcNow;
        }
    }
}