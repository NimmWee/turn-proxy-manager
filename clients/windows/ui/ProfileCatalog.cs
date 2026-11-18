using System.IO;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace FreeTurn.Windows;

internal sealed record SavedProfile(Guid Id, string Name, string Share,Models.SshConfig? Ssh=null,[property:JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingNull)]ManagedCredential? Managed=null,[property:JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingNull)]ManagedRoutingState? Routing=null)
{
    public override string ToString()=>Name;
}
internal sealed record ProfileSnapshot(int Version, Guid? ActiveId, List<SavedProfile> Profiles, bool AdvancedCaptcha = false, string? AndroidArchive = null, bool CloseToTray = false,bool AutoReconnect=false,SocksSettings? LocalProxy=null,bool LightTheme=false,List<string>? AndroidArchiveHistory=null,SystemRoutingSettings? SystemRouting=null,[property:JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingNull)]List<EnrollmentAttempt>? Enrollments=null,[property:JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingDefault)]bool ManagedAutoSync=false,[property:JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingDefault)]bool AutoTransport=false,[property:JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingDefault)]bool ForceManualCaptcha=false)
{
    public override string ToString()=>"ProfileSnapshot (private fields omitted)";
}

// User-owned client data, separate from the SYSTEM service's selected profile.
// Only the existing authenticated IPC may apply a selected entry to that service.
internal sealed partial class ProfileCatalog
{
    private readonly string directory;
    private string FilePath => Path.Combine(directory,"profiles.dpapi");
    private static readonly byte[] Purpose=Encoding.UTF8.GetBytes("FreeTurn Windows profile catalog v1");
    private static readonly JsonSerializerOptions Json=new(){UnmappedMemberHandling=System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow};

    internal ProfileCatalog(string? directory=null) => this.directory=directory??Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"FreeTurnManager","Profiles");

    internal ProfileSnapshot Read()
    {
        if(!File.Exists(FilePath))return new(1,null,[]);
        RejectLinks();
        if(new FileInfo(FilePath).Length>8*1024*1024)throw new IOException("PROFILE_CATALOG_INVALID");
        try{
            var raw=ProtectedData.Unprotect(File.ReadAllBytes(FilePath),Purpose,DataProtectionScope.CurrentUser);
            try{
                var value=JsonSerializer.Deserialize<ProfileSnapshot>(raw,Json)??throw new IOException();
                Validate(value);return value;
            }finally{CryptographicOperations.ZeroMemory(raw);}
        }catch{throw new IOException("PROFILE_CATALOG_INVALID");}
    }

    internal SavedProfile Add(string name,string share,bool selected=false)
    {
        var data=Read();var profile=new SavedProfile(Guid.NewGuid(),name.Trim(),share);
        data.Profiles.Add(profile);Write(data with{ActiveId=selected?profile.Id:data.ActiveId});return profile;
    }
    internal SavedProfile AddBootstrap(ManagedBootstrap bootstrap,bool selected=false)
    {
        _=ManagedBootstrap.Parse(JsonSerializer.Serialize(bootstrap));
        var data=Read();var existing=data.Profiles.FirstOrDefault(p=>p.Managed is{} m&&m.DeviceId==bootstrap.DeviceId&&m.Origin==bootstrap.Origin);
        if(existing is not null){if(existing.Managed!.PublicKey!=bootstrap.PublicKey)throw new IOException("MANAGED_BOOTSTRAP_INVALID");if(selected&&data.ActiveId!=existing.Id)Write(data with{ActiveId=existing.Id});return existing;}
        var raw=data.Profiles.FirstOrDefault(p=>p.Share==bootstrap.Share&&p.Managed is null);
        var metadata=new ManagedCredential(bootstrap.DeviceId,bootstrap.PublicKey,bootstrap.Origin,bootstrap.InternalAPIIP,bootstrap.ClaimNonce,bootstrap.ExpiresAt,ManagedCredential.NewToken());
        var profile=raw is null?new SavedProfile(Guid.NewGuid(),new ShareDocument(bootstrap.Share).Values.Name is{Length:>0} name?name:"Управляемый сервер",bootstrap.Share,Managed:metadata):raw with{Managed=metadata};
        if(raw is null)data.Profiles.Add(profile);else data.Profiles[data.Profiles.IndexOf(raw)]=profile;
        Write(data with{ActiveId=selected?profile.Id:data.ActiveId});return profile;
    }
    internal void MarkManagedRegistered(Guid id,ManagedCredential expected,string expectedShare)
    {
        var data=Read();var index=data.Profiles.FindIndex(p=>p.Id==id);if(index<0||data.Profiles[index].Managed is not{} m||m!=expected||data.Profiles[index].Share!=expectedShare)throw new IOException("MANAGED_STORAGE_CHANGED");
        data.Profiles[index]=data.Profiles[index] with{Managed=m with{Registered=true,ClaimNonce=null}};Write(data);
    }
    internal void Select(Guid id){var data=Read();if(!data.Profiles.Any(p=>p.Id==id))throw new IOException("PROFILE_NOT_FOUND");Write(data with{ActiveId=id});}
    internal void SetForceManualCaptcha(bool value){var data=Read();if(data.ForceManualCaptcha==value&&(!value||!data.AdvancedCaptcha))return;Write(data with{ForceManualCaptcha=value,AdvancedCaptcha=value?false:data.AdvancedCaptcha});}
    internal void SetAdvancedCaptcha(bool enabled)=>Write(Read() with{AdvancedCaptcha=enabled});
    internal void SetCloseToTray(bool enabled)=>Write(Read() with{CloseToTray=enabled});
    internal void SetAutoReconnect(bool enabled)=>Write(Read() with{AutoReconnect=enabled});
    internal void SetAutoTransport(bool enabled)=>Write(Read() with{AutoTransport=enabled});
    internal void SetManagedAutoSync(bool enabled)=>Write(Read() with{ManagedAutoSync=enabled});
    internal void SetLightTheme(bool enabled)=>Write(Read() with{LightTheme=enabled});
    internal void SetSsh(Guid id,Models.SshConfig settings)=>Change(id,p=>p with{Ssh=settings});
    internal void SetProxy(SocksSettings settings){if(!settings.Valid)throw new IOException("SOCKS_OPTIONS_INVALID");Write(Read() with{LocalProxy=settings});}
    internal void SetSystemRouting(SystemRoutingSettings settings){if(!settings.Valid)throw new IOException("SYSTEM_ROUTING_POLICY_INVALID");Write(Read() with{SystemRouting=settings});}
    internal int Merge(ProfileSnapshot incoming,bool restorePreferences=false)
    {
        Validate(incoming);foreach(var p in incoming.Profiles)_ = new ShareDocument(p.Share);
        var current=Read();var added=0;
        foreach(var profile in incoming.Profiles){
            if(profile.Managed is{} managed&&current.Profiles.Any(p=>p.Managed is{} existing&&existing.DeviceId==managed.DeviceId&&existing.Origin==managed.Origin))continue;
            if(profile.Managed is not null){var rawIndex=current.Profiles.FindIndex(p=>p.Managed is null&&p.Share==profile.Share&&Equals(p.Ssh,profile.Ssh));if(rawIndex>=0){current.Profiles[rawIndex]=current.Profiles[rawIndex] with{Managed=profile.Managed};added++;continue;}}
            if(current.Profiles.Any(p=>p.Share==profile.Share&&Equals(p.Ssh,profile.Ssh)))continue;
            var id=current.Profiles.Any(p=>p.Id==profile.Id)?Guid.NewGuid():profile.Id;
            current.Profiles.Add(profile with{Id=id});added++;
        }
        // Preserve complete Android sources, including SSH and settings that
        // Windows cannot execute yet. Never claim the SYSTEM profile was applied.
        var history=new List<string>(current.AndroidArchiveHistory??[]);var latest=incoming.AndroidArchive??current.AndroidArchive;
        foreach(var source in (incoming.AndroidArchiveHistory??[]).Concat(current.AndroidArchive is null?[]:new[]{current.AndroidArchive}))if(source!=latest&&!history.Contains(source,StringComparer.Ordinal))history.Add(source);
        history.RemoveAll(source=>source==latest);if(history.Count>8)throw new IOException("ANDROID_ARCHIVE_LIMIT");
        Write(current with{Enrollments=MergeEnrollments(current,incoming),AndroidArchive=latest,AndroidArchiveHistory=history.Count==0?null:history,AdvancedCaptcha=restorePreferences?incoming.AdvancedCaptcha:current.AdvancedCaptcha,CloseToTray=restorePreferences?incoming.CloseToTray:current.CloseToTray,AutoReconnect=restorePreferences?incoming.AutoReconnect:current.AutoReconnect,ManagedAutoSync=restorePreferences?incoming.ManagedAutoSync:current.ManagedAutoSync,AutoTransport=restorePreferences?incoming.AutoTransport:current.AutoTransport,ForceManualCaptcha=restorePreferences?incoming.ForceManualCaptcha:current.ForceManualCaptcha,LocalProxy=restorePreferences?incoming.LocalProxy:current.LocalProxy,LightTheme=restorePreferences?incoming.LightTheme:current.LightTheme,SystemRouting=restorePreferences?incoming.SystemRouting:current.SystemRouting});return added;
    }
    internal void Rename(Guid id,string name)=>Change(id,p=>p with{Name=name.Trim()});
    internal void Replace(Guid id,string name,string share,string? expectedShare=null)
    {
        var data=Read();var index=data.Profiles.FindIndex(p=>p.Id==id);if(index<0)throw new IOException("PROFILE_NOT_FOUND");
        if(data.Profiles[index].Managed is not null)throw new IOException("MANAGED_PROFILE_READ_ONLY");
        if(expectedShare is not null&&data.Profiles[index].Share!=expectedShare)throw new IOException("PROFILE_CHANGED_DURING_EDIT");
        data.Profiles[index]=data.Profiles[index] with{Name=name.Trim(),Share=share};
        Write(data);
    }
    internal SavedProfile Clone(Guid id)
    {
        var data=Read();var original=data.Profiles.Single(p=>p.Id==id);
        if(original.Managed is not null)throw new IOException("MANAGED_PROFILE_READ_ONLY");
        var copy=original with{Id=Guid.NewGuid(),Name=original.Name.Length>117?original.Name[..117]+" (копия)":original.Name+" (копия)"};
        data.Profiles.Add(copy);Write(data);return copy;
    }
    internal void Delete(Guid id){var data=Read();data.Profiles.RemoveAll(p=>p.Id==id);Write(data with{ActiveId=data.ActiveId==id?null:data.ActiveId});}
    private void Change(Guid id,Func<SavedProfile,SavedProfile> transform)
    {
        var data=Read();var index=data.Profiles.FindIndex(p=>p.Id==id);if(index<0)throw new IOException("PROFILE_NOT_FOUND");data.Profiles[index]=transform(data.Profiles[index]);Write(data);
    }
    private static void Validate(ProfileSnapshot value)
    {
        if(value.Version!=1||value.AndroidArchive?.Length>BackupCrypto.MaxPlaintext||value.Profiles is null||value.Profiles.Count>256||value.Profiles.Select(p=>p.Id).Distinct().Count()!=value.Profiles.Count || value.ActiveId.HasValue&&!value.Profiles.Any(p=>p.Id==value.ActiveId))throw new IOException("PROFILE_CATALOG_INVALID");
        foreach(var p in value.Profiles)
            if(p.Id==Guid.Empty||string.IsNullOrWhiteSpace(p.Name)||p.Name.Length>128||p.Name.Any(char.IsControl)||p.Share is null||p.Share.Length>96*1024||!p.Share.StartsWith("freeturn://",StringComparison.Ordinal))throw new IOException("PROFILE_CATALOG_INVALID");
        foreach(var p in value.Profiles)if(p.Ssh is not null)SshTrust.Validate(p.Ssh);
        foreach(var p in value.Profiles)if(p.Routing is not null&&(p.Managed is null||!p.Routing.Valid))throw new IOException("PROFILE_CATALOG_INVALID");
        foreach(var p in value.Profiles)if(p.Managed is not null&&!p.Managed.Valid)throw new IOException("PROFILE_CATALOG_INVALID");
        foreach(var p in value.Profiles)if(p.Managed is{} m&&(m.Applied is not null&&m.Applied.Share!=p.Share||m.Previous is not null&&m.Previous.Share!=m.PreviousShare))throw new IOException("PROFILE_CATALOG_INVALID");
        var managedIds=value.Profiles.Where(p=>p.Managed is not null).Select(p=>(p.Managed!.Origin,p.Managed.DeviceId));if(managedIds.Distinct().Count()!=managedIds.Count())throw new IOException("PROFILE_CATALOG_INVALID");
        if(value.Enrollments is{} entries&&(entries.Count>16||entries.Any(e=>e is null||!e.Valid)||entries.Select(e=>e.RequestId).Distinct().Count()!=entries.Count||entries.Select(e=>(e.Origin,e.SourceHash)).Distinct().Count()!=entries.Count))throw new IOException("PROFILE_CATALOG_INVALID");
        if(value.LocalProxy is not null&&!value.LocalProxy.Valid)throw new IOException("PROFILE_CATALOG_INVALID");
        if(value.SystemRouting is not null&&!value.SystemRouting.Valid)throw new IOException("PROFILE_CATALOG_INVALID");
        if(value.AndroidArchiveHistory is not null&&(value.AndroidArchiveHistory.Count>8||value.AndroidArchiveHistory.Any(source=>source is null||source.Length>BackupCrypto.MaxPlaintext)))throw new IOException("PROFILE_CATALOG_INVALID");
    }
    private void RejectLinks()
    {
        for(var path=new DirectoryInfo(directory);path is not null;path=path.Parent)
            if(path.Exists&&(path.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("PROFILE_CATALOG_INVALID");
        if(File.Exists(FilePath)&&(File.GetAttributes(FilePath)&FileAttributes.ReparsePoint)!=0)throw new IOException("PROFILE_CATALOG_INVALID");
    }
    private void Write(ProfileSnapshot data)
    {
        Validate(data);RejectLinks();Directory.CreateDirectory(directory);
        var sid=WindowsIdentity.GetCurrent().User??throw new IOException("PROFILE_CATALOG_INVALID");
        var acl=new DirectorySecurity();acl.SetAccessRuleProtection(true,false);acl.SetOwner(sid);
        foreach(var identity in new[]{sid,new SecurityIdentifier("S-1-5-18"),new SecurityIdentifier("S-1-5-32-544")})
            acl.AddAccessRule(new FileSystemAccessRule(identity,FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
        new DirectoryInfo(directory).SetAccessControl(acl);
        var raw=JsonSerializer.SerializeToUtf8Bytes(data,Json);byte[] cipher;
        try{if(raw.Length>BackupCrypto.MaxPlaintext)throw new IOException("PROFILE_CATALOG_TOO_LARGE");cipher=ProtectedData.Protect(raw,Purpose,DataProtectionScope.CurrentUser);}finally{CryptographicOperations.ZeroMemory(raw);}
        var temporary=Path.Combine(directory,"."+Guid.NewGuid().ToString("N")+".tmp");
        try{
            using(var stream=new FileStream(temporary,FileMode.CreateNew,FileAccess.Write,FileShare.None)){stream.Write(cipher);stream.Flush(true);}
            if(File.Exists(FilePath))File.Replace(temporary,FilePath,FilePath+".previous");else File.Move(temporary,FilePath);
        }finally{if(File.Exists(temporary))File.Delete(temporary);}
    }
}
