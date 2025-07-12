using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Metadata;
using Avalonia.Controls.Primitives;
using Avalonia.Input;
using Avalonia.Media;
using System.Windows.Input;

namespace VaultScope.UI.Controls;

[PseudoClasses(":selected", ":pressed")]
public class NavigationButton : TemplatedControl
{
    public static readonly StyledProperty<Geometry?> IconProperty =
        AvaloniaProperty.Register<NavigationButton, Geometry?>(nameof(Icon));
    
    public static readonly StyledProperty<string> TextProperty =
        AvaloniaProperty.Register<NavigationButton, string>(nameof(Text), string.Empty);
    
    public static readonly StyledProperty<bool> IsSelectedProperty =
        AvaloniaProperty.Register<NavigationButton, bool>(nameof(IsSelected));
    
    public static readonly StyledProperty<ICommand?> CommandProperty =
        AvaloniaProperty.Register<NavigationButton, ICommand?>(nameof(Command));
    
    public static readonly StyledProperty<object?> CommandParameterProperty =
        AvaloniaProperty.Register<NavigationButton, object?>(nameof(CommandParameter));
    
    public Geometry? Icon
    {
        get => GetValue(IconProperty);
        set => SetValue(IconProperty, value);
    }
    
    public string Text
    {
        get => GetValue(TextProperty);
        set => SetValue(TextProperty, value);
    }
    
    public bool IsSelected
    {
        get => GetValue(IsSelectedProperty);
        set => SetValue(IsSelectedProperty, value);
    }
    
    public ICommand? Command
    {
        get => GetValue(CommandProperty);
        set => SetValue(CommandProperty, value);
    }
    
    public object? CommandParameter
    {
        get => GetValue(CommandParameterProperty);
        set => SetValue(CommandParameterProperty, value);
    }
    
    static NavigationButton()
    {
        IsSelectedProperty.Changed.AddClassHandler<NavigationButton>((x, e) => x.UpdatePseudoClasses());
    }
    
    protected override void OnPointerPressed(PointerPressedEventArgs e)
    {
        base.OnPointerPressed(e);
        PseudoClasses.Set(":pressed", true);
        
        if (Command?.CanExecute(CommandParameter) == true)
        {
            Command.Execute(CommandParameter);
        }
    }
    
    protected override void OnPointerReleased(PointerReleasedEventArgs e)
    {
        base.OnPointerReleased(e);
        PseudoClasses.Set(":pressed", false);
    }
    
    private void UpdatePseudoClasses()
    {
        PseudoClasses.Set(":selected", IsSelected);
    }
}