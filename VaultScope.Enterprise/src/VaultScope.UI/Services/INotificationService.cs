using System;
using System.Threading.Tasks;

namespace VaultScope.UI.Services;

public interface INotificationService
{
    void Show(string title, string message, NotificationType type = NotificationType.Information);
    void Show(NotificationModel notification);
    Task<bool> ShowConfirmationAsync(string title, string message);
}

public enum NotificationType
{
    Information,
    Success,
    Warning,
    Error
}

public class NotificationModel
{
    public string Title { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
    public NotificationType Type { get; set; } = NotificationType.Information;
    public TimeSpan Duration { get; set; } = TimeSpan.FromSeconds(5);
    public Action? OnClick { get; set; }
    public Action? OnClose { get; set; }
}