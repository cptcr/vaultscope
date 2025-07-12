using System;
using System.Collections.Generic;
using Microsoft.Extensions.DependencyInjection;
using VaultScope.UI.ViewModels;

namespace VaultScope.UI.Services;

public class NavigationService : INavigationService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly Stack<ViewModelBase> _navigationStack = new();
    private ViewModelBase? _currentPage;
    
    public event EventHandler<ViewModelBase>? CurrentPageChanged;
    
    public NavigationService(IServiceProvider serviceProvider)
    {
        _serviceProvider = serviceProvider;
    }
    
    public bool CanNavigateBack => _navigationStack.Count > 0;
    
    public void NavigateTo<TViewModel>() where TViewModel : ViewModelBase
    {
        var viewModel = _serviceProvider.GetRequiredService<TViewModel>();
        Navigate(viewModel);
    }
    
    public void NavigateTo<TViewModel>(object parameter) where TViewModel : ViewModelBase
    {
        var viewModel = _serviceProvider.GetRequiredService<TViewModel>();
        
        if (viewModel is INavigationAware navigationAware)
        {
            navigationAware.OnNavigatedTo(parameter);
        }
        
        Navigate(viewModel);
    }
    
    public void NavigateBack()
    {
        if (_navigationStack.Count > 0)
        {
            var previousPage = _navigationStack.Pop();
            _currentPage = previousPage;
            CurrentPageChanged?.Invoke(this, previousPage);
        }
    }
    
    private void Navigate(ViewModelBase viewModel)
    {
        if (_currentPage != null)
        {
            _navigationStack.Push(_currentPage);
        }
        
        _currentPage = viewModel;
        CurrentPageChanged?.Invoke(this, viewModel);
    }
}

public interface INavigationAware
{
    void OnNavigatedTo(object parameter);
    void OnNavigatedFrom();
}