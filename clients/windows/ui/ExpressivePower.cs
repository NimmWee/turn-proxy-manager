// SPDX-License-Identifier: GPL-3.0-only
// Native WPF silhouette approximation of Android Material Cookie12/Sunny.
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;

namespace FreeTurn.Windows;
internal sealed class ExpressivePower : Button
{
    public static readonly DependencyProperty SilhouetteProperty=DependencyProperty.Register(nameof(Silhouette),typeof(Geometry),typeof(ExpressivePower));
    public Geometry Silhouette{get=>(Geometry)GetValue(SilhouetteProperty);set=>SetValue(SilhouetteProperty,value);}
    private string phase="";
    private bool animateAllowed;
    internal ExpressivePower(){Width=148;Height=148;Style=(Style)Application.Current.FindResource("PowerButton");SetPhase("stopped",false);}
    internal void SetPhase(string state,bool animate=true)
    {
        var next=state is "connected" or "proxy_ready"?"running":state is "starting" or "switching" or "stopping" or "captcha" or "tunnel_unverified" or "proxy_unverified"?"busy":state is "error"?"error":"idle";
        if(phase==next)return;phase=next;animateAllowed=animate;
        Silhouette=next=="running"?new EllipseGeometry(new Rect(0,0,148,148)):Cookie(next=="busy"?8:next=="error"?10:12);
        Background=next=="running"?new SolidColorBrush(UiTheme.Light?Color.FromRgb(199,237,205):Color.FromRgb(37,76,47)):next=="error"?new SolidColorBrush(UiTheme.Light?Color.FromRgb(255,218,214):Color.FromRgb(147,0,10)):UiTheme.PrimaryContainer;
        Foreground=next=="running"?new SolidColorBrush(UiTheme.Light?Color.FromRgb(18,74,38):Color.FromRgb(187,239,193)):next=="error"?UiTheme.Error:UiTheme.OnPrimaryContainer;
        Content=next=="busy"?BusyMark(Foreground,animate):AndroidIcon.Create(next=="running"?"Connected":next=="error"?"Error":"Play",52,Foreground);
        ApplySpin();
    }
    public override void OnApplyTemplate(){base.OnApplyTemplate();ApplySpin();}
    private void ApplySpin()
    {
        var shape=Template?.FindName("Silhouette",this) as System.Windows.Shapes.Path;
        if(shape is not null){if(shape.RenderTransform is RotateTransform old)old.BeginAnimation(RotateTransform.AngleProperty,null);var rotation=new RotateTransform(0,74,74);shape.RenderTransform=rotation;if(phase=="busy"&&animateAllowed&&SystemParameters.ClientAreaAnimation)rotation.BeginAnimation(RotateTransform.AngleProperty,new DoubleAnimation(0,360,TimeSpan.FromSeconds(8)){RepeatBehavior=RepeatBehavior.Forever});}
    }
    private static UIElement BusyMark(Brush brush,bool animate)
    {
        var path=new System.Windows.Shapes.Path{Data=Geometry.Parse("M32,8 A24,24 0 1 1 8,32"),Stroke=brush,StrokeThickness=5,StrokeStartLineCap=PenLineCap.Round,StrokeEndLineCap=PenLineCap.Round};var canvas=new Canvas{Width=64,Height=64};canvas.Children.Add(path);var rotation=new RotateTransform(0,32,32);canvas.RenderTransform=rotation;if(animate&&SystemParameters.ClientAreaAnimation)rotation.BeginAnimation(RotateTransform.AngleProperty,new DoubleAnimation(0,360,TimeSpan.FromSeconds(1.2)){RepeatBehavior=RepeatBehavior.Forever});return new Viewbox{Width=52,Height=52,Child=canvas};
    }
    private static Geometry Cookie(int lobes)
    {
        var points=Enumerable.Range(0,lobes*2).Select(i=>{var a=-Math.PI/2+i*Math.PI/lobes;var r=i%2==0?74:59.2;return new Point(74+r*Math.Cos(a),74+r*Math.Sin(a));}).ToArray();
        static Point Mid(Point a,Point b)=>new((a.X+b.X)/2,(a.Y+b.Y)/2);
        var geometry=new StreamGeometry();using(var ctx=geometry.Open()){ctx.BeginFigure(Mid(points[^1],points[0]),true,true);for(var i=0;i<points.Length;i++)ctx.QuadraticBezierTo(points[i],Mid(points[i],points[(i+1)%points.Length]),true,false);}
        var bounds=geometry.Bounds;geometry.Transform=new MatrixTransform(148/bounds.Width,0,0,148/bounds.Height,-bounds.X*148/bounds.Width,-bounds.Y*148/bounds.Height);geometry.Freeze();return geometry;
    }
}
