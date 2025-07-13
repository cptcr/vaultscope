using System.Text.Json.Serialization;
using VaultScope.Core.Models;
using VaultScope.Infrastructure.Reporting;

namespace VaultScope.Infrastructure.Json;

[JsonSerializable(typeof(Dictionary<string, string>))]
[JsonSerializable(typeof(Dictionary<string, object>))]
[JsonSerializable(typeof(ScanResult))]
[JsonSerializable(typeof(SecurityScore))]
[JsonSerializable(typeof(Vulnerability))]
[JsonSerializable(typeof(List<Vulnerability>))]
[JsonSerializable(typeof(ScanConfiguration))]
[JsonSerializable(typeof(object))]
[JsonSerializable(typeof(string))]
[JsonSerializable(typeof(int))]
[JsonSerializable(typeof(double))]
[JsonSerializable(typeof(bool))]
[JsonSerializable(typeof(JsonReport))]
[JsonSerializable(typeof(ReportMetadata))]
[JsonSerializable(typeof(ScanSummary))]
[JsonSerializable(typeof(RiskAssessment))]
[JsonSerializable(typeof(SecurityScoreReport))]
[JsonSerializable(typeof(CategoryScoreReport))]
[JsonSerializable(typeof(VulnerabilityReport))]
[JsonSerializable(typeof(RemediationPlan))]
[JsonSerializable(typeof(List<VulnerabilityReport>))]
[JsonSerializable(typeof(List<string>))]
public partial class VaultScopeJsonContext : JsonSerializerContext
{
}