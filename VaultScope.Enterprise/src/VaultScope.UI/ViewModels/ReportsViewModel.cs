using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Reactive;
using System.Threading.Tasks;
using ReactiveUI;
using VaultScope.Core.Constants;
using VaultScope.Core.Models;
using VaultScope.Infrastructure.Data.Repositories;

namespace VaultScope.UI.ViewModels;

public class ReportsViewModel : ViewModelBase
{
    private readonly IScanResultRepository? _scanResultRepository;
    private bool _isLoading;
    private ScanResult? _selectedReport;
    private string _statusMessage = "Ready";
    
    public bool IsLoading
    {
        get => _isLoading;
        set => this.RaiseAndSetIfChanged(ref _isLoading, value);
    }

    public string StatusMessage
    {
        get => _statusMessage;
        set => this.RaiseAndSetIfChanged(ref _statusMessage, value);
    }
    
    public ScanResult? SelectedReport
    {
        get => _selectedReport;
        set => this.RaiseAndSetIfChanged(ref _selectedReport, value);
    }
    
    public ObservableCollection<ScanResult> Reports { get; } = new();
    
    // Commands
    public ReactiveCommand<Unit, Unit> RefreshCommand { get; }
    public ReactiveCommand<ScanResult, Unit> ViewReportCommand { get; }
    public ReactiveCommand<ScanResult, Unit> ExportReportCommand { get; }
    public ReactiveCommand<ScanResult, Unit> DeleteReportCommand { get; }
    public ReactiveCommand<Unit, Unit> ExportAllCommand { get; }
    
    public ReportsViewModel(IScanResultRepository? scanResultRepository = null)
    {
        _scanResultRepository = scanResultRepository;
        
        RefreshCommand = ReactiveCommand.Create(Refresh);
        ViewReportCommand = ReactiveCommand.Create<ScanResult>(ViewReport);
        ExportReportCommand = ReactiveCommand.Create<ScanResult>(ExportReport);
        DeleteReportCommand = ReactiveCommand.Create<ScanResult>(DeleteReport);
        ExportAllCommand = ReactiveCommand.Create(ExportAll);
        
        _ = LoadReportsAsync();
    }
    
    private async void Refresh()
    {
        await LoadReportsAsync();
    }
    
    private void ViewReport(ScanResult report)
    {
        SelectedReport = report;
        // Navigate to report details
    }
    
    private void ExportReport(ScanResult report)
    {
        // Export single report
    }
    
    private async void DeleteReport(ScanResult report)
    {
        try
        {
            if (_scanResultRepository != null)
            {
                await _scanResultRepository.DeleteAsync(report.Id);
                Reports.Remove(report);
                StatusMessage = $"Report for {report.TargetUrl} deleted successfully";
            }
            else
            {
                StatusMessage = "Database not available";
            }
        }
        catch (Exception ex)
        {
            StatusMessage = $"Failed to delete report: {ex.Message}";
        }
    }
    
    private void ExportAll()
    {
        // Export all reports
    }
    
    private async Task LoadReportsAsync()
    {
        IsLoading = true;
        StatusMessage = "Loading reports...";
        
        try
        {
            Reports.Clear();
            
            if (_scanResultRepository != null)
            {
                var reports = await _scanResultRepository.GetAllAsync();
                foreach (var report in reports)
                {
                    Reports.Add(report);
                }
                StatusMessage = $"Loaded {Reports.Count} reports";
            }
            else
            {
                StatusMessage = "Database not available";
            }
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error loading reports: {ex.Message}";
        }
        finally
        {
            IsLoading = false;
        }
    }
}