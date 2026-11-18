// SPDX-License-Identifier: GPL-3.0-only
// Envelope interoperates with FreeTurn Android 5.3.4 BackupCrypto.kt.
namespace FreeTurn.Windows;
internal static class BackupCrypto
{
    internal const int MaxPlaintext=6*1024*1024,MaxEnvelope=9*1024*1024;
    internal static byte[] Encrypt(byte[] plaintext,string password)
    {
        if(plaintext.Length>MaxPlaintext)throw new System.IO.IOException("BACKUP_INVALID");
        var salt=System.Security.Cryptography.RandomNumberGenerator.GetBytes(16);var iv=System.Security.Cryptography.RandomNumberGenerator.GetBytes(12);
        var key=Derive(password,salt,210000);
        try{
            var ct=new byte[plaintext.Length+16];using var aes=new System.Security.Cryptography.AesGcm(key,16);
            aes.Encrypt(iv,plaintext,ct.AsSpan(0,plaintext.Length),ct.AsSpan(plaintext.Length));
            return System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new{magic="freeturn-backup",v=1,kdf="pbkdf2-sha256",iter=210000,salt=Convert.ToBase64String(salt),iv=Convert.ToBase64String(iv),ct=Convert.ToBase64String(ct)});
        }finally{System.Security.Cryptography.CryptographicOperations.ZeroMemory(key);}
    }
    internal static byte[] Decrypt(byte[] envelope,string password)
    {
        try{
            if(envelope.Length>MaxEnvelope)throw new System.IO.IOException();
            using var document=System.Text.Json.JsonDocument.Parse(envelope,new(){MaxDepth=8});ShareDocument.Unique(document.RootElement);var root=document.RootElement;
            if(root.GetProperty("magic").GetString()!="freeturn-backup"||root.GetProperty("v").GetInt32()!=1||root.GetProperty("kdf").GetString()!="pbkdf2-sha256")throw new System.IO.IOException();
            var iterations=root.GetProperty("iter").GetInt32();if(iterations is <100000 or >2000000)throw new System.IO.IOException();
            var salt=Convert.FromBase64String(root.GetProperty("salt").GetString()!);var iv=Convert.FromBase64String(root.GetProperty("iv").GetString()!);var ct=Convert.FromBase64String(root.GetProperty("ct").GetString()!);
            if(salt.Length!=16||iv.Length!=12||ct.Length<16||ct.Length>MaxPlaintext+16)throw new System.IO.IOException();
            var key=Derive(password,salt,iterations);var plain=new byte[ct.Length-16];
            try{using var aes=new System.Security.Cryptography.AesGcm(key,16);aes.Decrypt(iv,ct.AsSpan(0,plain.Length),ct.AsSpan(plain.Length),plain);return plain;}
            catch{System.Security.Cryptography.CryptographicOperations.ZeroMemory(plain);throw;}
            finally{System.Security.Cryptography.CryptographicOperations.ZeroMemory(key);}
        }catch{throw new System.IO.IOException("BACKUP_PASSWORD_OR_DAMAGED");}
    }
    private static byte[] Derive(string password,byte[] salt,int iterations)
    {
        if(password.Length is 0 or >1024)throw new System.IO.IOException("BACKUP_PASSWORD_INVALID");
        var bytes=System.Text.Encoding.UTF8.GetBytes(password);
        try{return System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2(bytes,salt,iterations,System.Security.Cryptography.HashAlgorithmName.SHA256,32);}
        finally{System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes);}
    }
}
