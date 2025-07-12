using System.Threading.Tasks;

namespace VaultScope.UI.Services;

public interface IThemeService
{
    Theme CurrentTheme { get; }
    Task InitializeAsync();
    Task SetThemeAsync(Theme theme);
}

public enum Theme
{
    DarkPurple,
    DarkBlue,
    Light
}