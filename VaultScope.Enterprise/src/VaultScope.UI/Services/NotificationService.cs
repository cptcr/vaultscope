using System;
using System.Collections.ObjectModel;
using System.Reactive.Linq;
using System.Threading.Tasks;
using Avalonia.Threading;
using ReactiveUI;

namespace VaultScope.UI.Services;

public class NotificationService : ReactiveObject, INotificationService
{
    private readonly ObservableCollection<NotificationViewModel> _notifications = new();
    
    public ObservableCollection<NotificationViewModel> Notifications => _notifications;
    
    public void Show(string title, string message, NotificationType type = NotificationType.Information)
    {
        Show(new NotificationModel
        {
            Title = title,
            Message = message,
            Type = type
        });
    }
    
    public void Show(NotificationModel notification)
    {
        Dispatcher.UIThread.Post(() =>
        {
            var viewModel = new NotificationViewModel(notification, RemoveNotification);
            _notifications.Add(viewModel);
            
            // Auto-remove after duration
            Observable.Timer(notification.Duration)
                .ObserveOn(RxApp.MainThreadScheduler)
                .Subscribe(_ => RemoveNotification(viewModel));
        });
    }
    
    public async Task<bool> ShowConfirmationAsync(string title, string message)
    {
        // This would show a modal dialog
        // For now, return true as a placeholder
        return await Task.FromResult(true);
    }
    
    private void RemoveNotification(NotificationViewModel notification)
    {
        Dispatcher.UIThread.Post(() =>
        {
            _notifications.Remove(notification);
            notification.Model.OnClose?.Invoke();
        });
    }
}

public class NotificationViewModel : ViewModelBase
{
    private readonly Action<NotificationViewModel> _removeAction;
    
    public NotificationModel Model { get; }
    
    public ReactiveCommand<System.Reactive.Unit, System.Reactive.Unit> CloseCommand { get; }
    public ReactiveCommand<System.Reactive.Unit, System.Reactive.Unit> ClickCommand { get; }
    
    public NotificationViewModel(NotificationModel model, Action<NotificationViewModel> removeAction)
    {
        Model = model;
        _removeAction = removeAction;
        
        CloseCommand = ReactiveCommand.Create(Close);
        ClickCommand = ReactiveCommand.Create(Click);
    }
    
    private void Close()
    {
        _removeAction(this);
    }
    
    private void Click()
    {
        Model.OnClick?.Invoke();
        Close();
    }
}