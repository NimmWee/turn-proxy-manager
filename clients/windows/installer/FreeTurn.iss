#ifndef PackageDir
  #error Build with build_setup.py
#endif

[Setup]
AppId={{2738B07D-56CD-4A79-BC25-CE5D5E028AA1}
AppName=FreeTurn
AppVersion={#AppVersion}
AppVerName=FreeTurn {#AppVersion} preview
AppPublisher=FreeTurn Manager Project
DefaultDirName={autopf}\FreeTurn
UsePreviousAppDir=no
DisableDirPage=yes
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64os
ArchitecturesInstallIn64BitMode=x64os
MinVersion=10.0.17763
SetupMutex=Global\FreeTurn.Desktop.Setup.v1
CloseApplications=no
RestartApplications=no
AlwaysRestart=no
RestartIfNeededByRun=no
UninstallDisplayIcon={app}\FreeTurn.Windows.exe
SetupIconFile={#StageDir}\FreeTurn.ico
OutputDir={#OutputDirectory}
OutputBaseFilename=FreeTurn-Setup-{#AppVersion}-preview-win-x64
Compression=lzma2/fast
SolidCompression=yes
WizardStyle=modern
LicenseFile={#PackageDir}\Android-LICENSE.txt
DisableWelcomePage=no

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"

[Tasks]
Name: "desktopicon"; Description: "Создать ярлык на рабочем столе"; Flags: unchecked

[Files]
Source: "{#StageDir}\.freeturn-setup-v1"; DestDir: "{app}"; Flags: ignoreversion
#include StageDir + "\payload.iss"
Source: "{#StageDir}\FreeTurn.SetupGuard.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "Inno-Setup-LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\FreeTurn-Setup-Sources.zip"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{commonprograms}\FreeTurn"; Filename: "{app}\FreeTurn.Windows.exe"; WorkingDir: "{app}"
Name: "{commondesktop}\FreeTurn"; Filename: "{app}\FreeTurn.Windows.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Messages]
ConfirmUninstall=Удалить %1 и его сетевые службы?%n%nПрофили и ключи сохранятся.
FinishedLabelNoIcons=FreeTurn установлен. Откройте приложение через меню «Пуск». Установка не запускает VPN; сохранённые профили и настройки остались на месте.

[Code]
procedure InitializeWizard;
begin
  WizardForm.WelcomeLabel2.Caption := 'Мастер установит FreeTurn на этот компьютер. Сохранённые профили и ключи останутся на месте.' + #13#10 + #13#10 + 'Перед обновлением отключите VPN FreeTurn и закройте приложение, в том числе значок в трее. Установка не меняет другие VPN и не запускает подключение автоматически.';
end;

function GuardMessage(Code: Integer): String;
begin
  case Code of
    10: Result := 'Закройте FreeTurn, в том числе значок в трее, и повторите действие. Установщик не завершает приложение принудительно.';
    11: Result := 'Сначала отключите VPN FreeTurn и закройте приложение. Активный туннель не изменён.';
    12, 14: Result := 'Найдены чужие или неполные сетевые службы. Автоматическое действие остановлено; данные сохранены.';
    15, 16, 17: Result := 'Не удалось подтвердить безопасную папку установки FreeTurn. Файлы и профили не удалялись.';
    18, 19: Result := 'Удаление сетевого ядра не завершено. Приложение оставлено на месте, зашифрованные профили сохранены. Повторите удаление после проверки журнала.';
  else
    Result := 'Не удалось проверить состояние Windows или FreeTurn. Действие остановлено. Закройте приложение и повторите попытку.';
  end;
end;

function FixedDirectory: String;
begin
  Result := ExpandConstant('{autopf}\FreeTurn');
end;

function CheckGuard(Uninstalling: Boolean): String;
var
  Helper, Operation: String;
  Code: Integer;
begin
  Result := '';
  if Uninstalling then begin
    Helper := ExpandConstant('{app}\FreeTurn.SetupGuard.exe');
    Operation := '--check-uninstall';
  end else begin
    ExtractTemporaryFile('FreeTurn.SetupGuard.exe');
    Helper := ExpandConstant('{tmp}\FreeTurn.SetupGuard.exe');
    Operation := '--check-install';
  end;
  if not Exec(Helper, Operation, '', SW_HIDE, ewWaitUntilTerminated, Code) then
    Result := GuardMessage(13)
  else if Code <> 0 then
    Result := GuardMessage(Code);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  InstalledMS, InstalledLS: Cardinal;
  ApplicationPath: String;
begin
  NeedsRestart := False;
  Result := '';
  if CompareText(RemoveBackslashUnlessRoot(WizardDirValue), FixedDirectory) <> 0 then begin
    Result := 'Эта сборка устанавливается только в стандартную папку FreeTurn. Другие каталоги не изменены.';
    Exit;
  end;
  Result := CheckGuard(False);
  if Result <> '' then Exit;
  ApplicationPath := FixedDirectory + '\FreeTurn.Windows.exe';
  if FileExists(ApplicationPath) then begin
    if not GetVersionNumbers(ApplicationPath, InstalledMS, InstalledLS) then begin
      Result := 'Не удалось проверить версию установленного приложения.';
      Exit;
    end;
    if (InstalledMS > {#AppVersionMS}) or ((InstalledMS = {#AppVersionMS}) and (InstalledLS > {#AppVersionLS})) then
      Result := 'На компьютере уже установлена более новая версия FreeTurn. Понижение версии не выполняется.';
  end;
end;

function InitializeUninstall: Boolean;
var
  Problem: String;
begin
  Result := False;
  if CompareText(RemoveBackslashUnlessRoot(ExpandConstant('{app}')), FixedDirectory) <> 0 then begin
    MsgBox('Не удалось подтвердить папку FreeTurn. Удаление остановлено.', mbError, MB_OK);
    Exit;
  end;
  Problem := CheckGuard(True);
  if Problem <> '' then begin
    MsgBox(Problem, mbError, MB_OK);
    Exit;
  end;
  Result := True;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Code: Integer;
begin
  if CurUninstallStep = usUninstall then begin
    { Inno7.1.1 treats exceptions here as fatal, before PerformUninstall.
      This runs after its confirmation, preserving the GUI if cleanup fails. }
    if not Exec(ExpandConstant('{app}\FreeTurn.SetupGuard.exe'), '--remove-services', '', SW_HIDE, ewWaitUntilTerminated, Code) then
      RaiseException(GuardMessage(18));
    if Code <> 0 then RaiseException(GuardMessage(Code));
  end;
end;
