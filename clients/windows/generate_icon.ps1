# Render the existing vector mark at native icon sizes; no external artwork.
$ErrorActionPreference='Stop'
Add-Type -AssemblyName PresentationCore,PresentationFramework,WindowsBase
$dictionary=[System.Windows.ResourceDictionary]::new()
$dictionary.Source=[Uri]::new((Join-Path $PSScriptRoot 'ui/NavigationIcons.xaml'))
$geometry=$dictionary['NavIcon.Logo'];$bounds=$geometry.Bounds
$images=@()
foreach($size in @(16,20,24,32,40,48,64,128,256)){
    $drawing=[System.Windows.Media.DrawingVisual]::new();$context=$drawing.RenderOpen()
    $context.DrawRoundedRectangle([System.Windows.Media.BrushConverter]::new().ConvertFromString('#294C80'),$null,[System.Windows.Rect]::new(0,0,$size,$size),$size*.25,$size*.25)
    $scale=$size*.66/[Math]::Max($bounds.Width,$bounds.Height)
    $x=($size-$bounds.Width*$scale)/2-$bounds.X*$scale;$y=($size-$bounds.Height*$scale)/2-$bounds.Y*$scale
    $context.PushTransform([System.Windows.Media.MatrixTransform]::new($scale,0,0,$scale,$x,$y));$context.DrawGeometry([System.Windows.Media.BrushConverter]::new().ConvertFromString('#D6E3FF'),$null,$geometry);$context.Pop();$context.Close()
    $bitmap=[System.Windows.Media.Imaging.RenderTargetBitmap]::new($size,$size,96,96,[System.Windows.Media.PixelFormats]::Pbgra32);$bitmap.Render($drawing)
    $encoder=[System.Windows.Media.Imaging.PngBitmapEncoder]::new();$encoder.Frames.Add([System.Windows.Media.Imaging.BitmapFrame]::Create($bitmap));$memory=[IO.MemoryStream]::new();$encoder.Save($memory)
    $images+=,@{Size=$size;Bytes=$memory.ToArray()};$memory.Dispose()
}
$path=Join-Path $PSScriptRoot 'ui/Assets/FreeTurn.ico';$stream=[IO.File]::Create($path);$writer=[IO.BinaryWriter]::new($stream)
try{
    $writer.Write([uint16]0);$writer.Write([uint16]1);$writer.Write([uint16]$images.Count);$offset=6+16*$images.Count
    foreach($entry in $images){$dimension=if($entry.Size -eq 256){0}else{$entry.Size};$writer.Write([byte]$dimension);$writer.Write([byte]$dimension);$writer.Write([byte]0);$writer.Write([byte]0);$writer.Write([uint16]1);$writer.Write([uint16]32);$writer.Write([uint32]$entry.Bytes.Length);$writer.Write([uint32]$offset);$offset+=$entry.Bytes.Length}
    foreach($entry in $images){$writer.Write([byte[]]$entry.Bytes)}
}finally{$writer.Dispose();$stream.Dispose()}
Write-Output 'Generated FreeTurn.ico from the existing vector logo (9 sizes)'
