using Avalonia;
using Avalonia.Animation;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Controls.Shapes;
using Avalonia.Controls.Templates;
using Avalonia.Data;
using Avalonia.Markup.Xaml;
using Avalonia.Media;
using Avalonia.Styling;
using System;

namespace VaultScope.UI.Controls;

public class AnimatedSpinner : TemplatedControl
{
    public static readonly StyledProperty<double> SpinDurationProperty =
        AvaloniaProperty.Register<AnimatedSpinner, double>(nameof(SpinDuration), 1.5);
    
    public static readonly StyledProperty<IBrush?> StrokeBrushProperty =
        AvaloniaProperty.Register<AnimatedSpinner, IBrush?>(nameof(StrokeBrush));
    
    public static readonly StyledProperty<double> StrokeThicknessProperty =
        AvaloniaProperty.Register<AnimatedSpinner, double>(nameof(StrokeThickness), 3);
    
    public double SpinDuration
    {
        get => GetValue(SpinDurationProperty);
        set => SetValue(SpinDurationProperty, value);
    }
    
    public IBrush? StrokeBrush
    {
        get => GetValue(StrokeBrushProperty);
        set => SetValue(StrokeBrushProperty, value);
    }
    
    public double StrokeThickness
    {
        get => GetValue(StrokeThicknessProperty);
        set => SetValue(StrokeThicknessProperty, value);
    }
    
    static AnimatedSpinner()
    {
        AffectsRender<AnimatedSpinner>(StrokeBrushProperty, StrokeThicknessProperty);
    }
    
    protected override void OnApplyTemplate(TemplateAppliedEventArgs e)
    {
        base.OnApplyTemplate(e);
        
        if (e.NameScope.Find<Border>("PART_Spinner") is { } spinner)
        {
            var animation = new Animation
            {
                Duration = TimeSpan.FromSeconds(SpinDuration),
                IterationCount = new IterationCount(ulong.MaxValue),
                Children =
                {
                    new KeyFrame
                    {
                        Cue = new Cue(0),
                        Setters = { new Setter(RotateTransform.AngleProperty, 0d) }
                    },
                    new KeyFrame
                    {
                        Cue = new Cue(1),
                        Setters = { new Setter(RotateTransform.AngleProperty, 360d) }
                    }
                }
            };
            
            animation.RunAsync(spinner, default);
        }
    }
}

public class AnimatedSpinnerTheme : ControlTheme
{
    public AnimatedSpinnerTheme() : this(typeof(AnimatedSpinner)) { }
    
    protected AnimatedSpinnerTheme(Type targetType) : base(targetType)
    {
        Add(new Setter(AnimatedSpinner.TemplateProperty, CreateTemplate()));
        Add(new Setter(AnimatedSpinner.StrokeBrushProperty, new SolidColorBrush(Colors.Blue)));
    }
    
    private static IControlTemplate CreateTemplate()
    {
        return new FuncControlTemplate<AnimatedSpinner>((spinner, scope) =>
        {
            var border = new Border
            {
                Name = "PART_Spinner",
                Width = spinner.Width,
                Height = spinner.Height,
                RenderTransform = new RotateTransform(),
                RenderTransformOrigin = new RelativePoint(0.5, 0.5, RelativeUnit.Relative),
                Child = new Avalonia.Controls.Shapes.Path
                {
                    Data = StreamGeometry.Parse("M12,2 A10,10 0 0,1 22,12"),
                    Stroke = spinner.StrokeBrush,
                    StrokeThickness = spinner.StrokeThickness,
                    StrokeLineCap = PenLineCap.Round,
                    Width = spinner.Width,
                    Height = spinner.Height,
                    Stretch = Stretch.Uniform
                }
            };
            
            scope.Register("PART_Spinner", border);
            return border;
        });
    }
}