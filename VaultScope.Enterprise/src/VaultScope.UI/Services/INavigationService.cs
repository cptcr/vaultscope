using System;
using VaultScope.UI.ViewModels;

namespace VaultScope.UI.Services;

public interface INavigationService
{
    event EventHandler<ViewModelBase>? CurrentPageChanged;
    
    void NavigateTo<TViewModel>() where TViewModel : ViewModelBase;
    void NavigateTo<TViewModel>(object parameter) where TViewModel : ViewModelBase;
    void NavigateBack();
    bool CanNavigateBack { get; }
}