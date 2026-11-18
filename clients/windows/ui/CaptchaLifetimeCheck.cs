using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Threading;

namespace FreeTurn.Windows;

// Native browser lifetime check. Only about:blank; no service/VK/VPN/catalog.
internal static class CaptchaLifetimeCheck
{
 internal static async Task Run(MainWindow shell)
 {
  var folder=System.IO.Path.Combine(System.IO.Path.GetTempPath(),"ftm-captcha-lifetime-"+Guid.NewGuid().ToString("N"));
  for(var i=0;i<12;i++){
   await Cycle(shell,folder,i%3==2);
   await Dispatcher.Yield(DispatcherPriority.ApplicationIdle);
   GC.Collect();GC.WaitForPendingFinalizers();GC.Collect();
   await Dispatcher.Yield(DispatcherPriority.ApplicationIdle);
   if(Application.Current.Windows.Cast<Window>().Count(w=>w.IsVisible)!=1)throw new InvalidOperationException("CAPTCHA_EXTRA_WINDOW");
  }
 }
 [MethodImpl(MethodImplOptions.NoInlining)]
 private static async Task Cycle(MainWindow shell,string folder,bool cancelEarly)
 {
  var browser=new CaptchaWindow(shell,false,folder);var cancelled=0;browser.Cancelled+=()=>cancelled++;
  shell.AttachCaptcha(browser);await Dispatcher.Yield(DispatcherPriority.Loaded);
  var check=browser.CheckLocalBrowser();
  if(cancelEarly){browser.Close();browser.Close();try{await check;}catch(ObjectDisposedException){}catch(InvalidOperationException){}catch(System.Runtime.InteropServices.COMException e)when(e.HResult==unchecked((int)0x80004004)){}if(cancelled!=1)throw new InvalidOperationException("CAPTCHA_CANCEL_COUNT");}
  else{try{await check;}finally{browser.Completed=true;browser.Close();browser.Close();}if(cancelled!=0)throw new InvalidOperationException("CAPTCHA_COMPLETION_CANCELLED");}
 }
}
