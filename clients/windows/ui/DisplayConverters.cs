using System.Globalization;
using System.Windows;
using System.Windows.Data;
namespace FreeTurn.Windows;
internal sealed class EmptyTextVisibility:IValueConverter
{
    public object Convert(object value,Type target,object parameter,CultureInfo culture)=>value is string text&&text.Length>0?Visibility.Visible:Visibility.Collapsed;
    public object ConvertBack(object value,Type target,object parameter,CultureInfo culture)=>Binding.DoNothing;
}
public sealed class OptionLabel:IValueConverter
{
    public object Convert(object value,Type target,object parameter,CultureInfo culture)=>value is string text?text switch{"vk"=>"VK Relay","direct"=>"Direct","tcp"=>"TCP","udp"=>"UDP","auto"=>"Автоматически","plain"=>"Обычный DNS","doh"=>"DNS через HTTPS","none"=>"Без обфускации","PASSWORD"=>"Пароль","SSH_KEY"=>"SSH-ключ",_=>text}:value;
    public object ConvertBack(object value,Type target,object parameter,CultureInfo culture)=>Binding.DoNothing;
}
