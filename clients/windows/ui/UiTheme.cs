using System.Windows;
using System.Windows.Media;
namespace FreeTurn.Windows;
internal static class UiTheme
{
    internal static bool Light{get;set;}
    private static readonly Dictionary<string,string> LightColors=new(StringComparer.OrdinalIgnoreCase){["#111318"]="#F8F9FF",["#191C20"]="#EEF1F8",["#1D2024"]="#FFFFFF",["#33353A"]="#DDE2EB",["#303C50"]="#415F91",["#AAC7FF"]="#415F91",["#0A305F"]="#FFFFFF",["#F4F7FC"]="#1B1C20",["#E2E2E9"]="#1B1C20",["#EDF3FC"]="#1B1C20",["#A4B3C8"]="#444B59",["#BAC8DA"]="#444B59",["#C4C6D0"]="#44474E",["#8294AE"]="#526076",["#9DC7FF"]="#284777",["#D6E3FF"]="#183A6A",["#BEC6DC"]="#485366",["#3E4759"]="#D6E3FF",["#44474E"]="#BDC3CE",["#415F91"]="#C3D8FF",["#282A2F"]="#E1E6F0"};
    internal static SolidColorBrush Brush(string color)=>(SolidColorBrush)new BrushConverter().ConvertFromString(Light&&LightColors.TryGetValue(color,out var mapped)?mapped:color)!;
    internal static Brush Background=>Brush("#111318");
    internal static Brush Foreground=>Brush("#E2E2E9");
    internal static Brush Muted=>Brush("#A4B3C8");
    internal static FontFamily Font=>new(new Uri("pack://application:,,,/"),"./Assets/#Roboto");
    internal static Brush PrimaryContainer=>new SolidColorBrush(Light?Color.FromRgb(214,227,255):Color.FromRgb(40,71,119));
    internal static Brush OnPrimaryContainer=>new SolidColorBrush(Light?Color.FromRgb(40,71,119):Color.FromRgb(214,227,255));
    internal static Brush Button=>new SolidColorBrush(Color.FromRgb(40,71,119));
    internal static Brush Error=>Light?new SolidColorBrush(Color.FromRgb(156,38,55)):Brushes.LightSalmon;
    internal static void Configure(Application app){app.Resources["AppFont"]=Font;app.Resources["Primary"]=Brush("#AAC7FF");app.Resources["OnPrimary"]=new SolidColorBrush(Light?Colors.White:Color.FromRgb(10,48,95));foreach(var pair in new[]{("InputBackground","#1D2024"),("InputForeground","#E2E2E9"),("InputBorder","#44474E"),("InputSelection","#415F91"),("NavHover","#282A2F"),("NavPressed","#33353A"),("FocusBorder","#AAC7FF")})app.Resources[pair.Item1]=Brush(pair.Item2);}
}
