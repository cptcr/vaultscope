using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
#if DEBUG
using Avalonia.Diagnostics;
#endif

namespace VaultScope.UI.Views;

public partial class MainWindow : Window
{
    private bool _isMaximized;
    
    public MainWindow()
    {
        InitializeComponent();
        
#if DEBUG
        // Remove dev tools for now due to missing reference
        // this.AttachDevTools();
#endif
    }
    
    private void OnTitleBarPointerPressed(object? sender, PointerPressedEventArgs e)
    {
        if (e.GetCurrentPoint(this).Properties.IsLeftButtonPressed)
        {
            BeginMoveDrag(e);
        }
    }
    
    private void OnTitleBarDoubleTapped(object? sender, TappedEventArgs e)
    {
        if (_isMaximized)
        {
            WindowState = WindowState.Normal;
            _isMaximized = false;
        }
        else
        {
            WindowState = WindowState.Maximized;
            _isMaximized = true;
        }
    }
    
    private void OnMinimizeClick(object? sender, RoutedEventArgs e)
    {
        WindowState = WindowState.Minimized;
    }
    
    private void OnMaximizeClick(object? sender, RoutedEventArgs e)
    {
        if (_isMaximized)
        {
            WindowState = WindowState.Normal;
            _isMaximized = false;
        }
        else
        {
            WindowState = WindowState.Maximized;
            _isMaximized = true;
        }
    }
    
    private void OnCloseClick(object? sender, RoutedEventArgs e)
    {
        Close();
    }
    
    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);
        
        if (change.Property == WindowStateProperty)
        {
            _isMaximized = WindowState == WindowState.Maximized;
        }
    }
}