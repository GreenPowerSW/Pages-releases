// GpSecurityClient.cs - High-level API for GpSecurity v2.0
//
// Provides easy-to-use managed API over native GpSecurity.dll.
// Uses DPAPI master key + AES-256-GCM + Argon2id.
//
// Author: Changwon Heo (Green Power Co., Ltd.)
// AI Assistant: Claude Code Assistant

using System.Runtime.InteropServices;

namespace GpSecurity;

/// <summary>
/// High-level security client for GpSecurity v2.0.
/// Automatically initializes DPAPI master key on construction.
/// </summary>
public sealed class GpSecurityClient : IDisposable
{
    private readonly string _configDir;

    /// <summary>
    /// Create a new GpSecurityClient.
    /// Master key is auto-created if not present.
    /// </summary>
    /// <param name="configDir">Directory for DPAPI .key file</param>
    public GpSecurityClient(string configDir)
    {
        _configDir = configDir;
        var rc = Native.gps_init_master_key(_configDir);
        if (rc != 0) throw new GpSecurityException(rc, GetLastError());
    }

    // =================================================================
    // Encryption (AES-256-GCM)
    // =================================================================

    /// <summary>Encrypt string → Base64</summary>
    public string Encrypt(string plaintext)
    {
        var rc = Native.gps_encrypt_string(_configDir, plaintext, out var ptr);
        if (rc != 0) throw new GpSecurityException(rc, GetLastError());
        try { return Marshal.PtrToStringUTF8(ptr)!; }
        finally { Native.gps_free_string(ptr); }
    }

    /// <summary>Decrypt Base64 → string</summary>
    public string Decrypt(string encryptedBase64)
    {
        var rc = Native.gps_decrypt_string(_configDir, encryptedBase64, out var ptr);
        if (rc != 0) throw new GpSecurityException(rc, GetLastError());
        try { return Marshal.PtrToStringUTF8(ptr)!; }
        finally { Native.gps_free_string(ptr); }
    }

    /// <summary>Encrypt string and save to file</summary>
    public void EncryptToFile(string plaintext, string filePath)
    {
        var rc = Native.gps_encrypt_to_file(_configDir, plaintext, filePath);
        if (rc != 0) throw new GpSecurityException(rc, GetLastError());
    }

    /// <summary>Decrypt file → string</summary>
    public string DecryptFromFile(string filePath)
    {
        var rc = Native.gps_decrypt_from_file(_configDir, filePath, out var ptr);
        if (rc != 0) throw new GpSecurityException(rc, GetLastError());
        try { return Marshal.PtrToStringUTF8(ptr)!; }
        finally { Native.gps_free_string(ptr); }
    }

    /// <summary>Encrypt binary data</summary>
    public byte[] EncryptBytes(byte[] data)
    {
        var rc = Native.gps_encrypt_bytes(_configDir, data, data.Length,
            out var resultPtr, out var resultLen);
        if (rc != 0) throw new GpSecurityException(rc, GetLastError());
        try
        {
            var result = new byte[resultLen];
            Marshal.Copy(resultPtr, result, 0, resultLen);
            return result;
        }
        finally { Native.gps_free_bytes(resultPtr, resultLen); }
    }

    /// <summary>Decrypt binary data</summary>
    public byte[] DecryptBytes(byte[] data)
    {
        var rc = Native.gps_decrypt_bytes(_configDir, data, data.Length,
            out var resultPtr, out var resultLen);
        if (rc != 0) throw new GpSecurityException(rc, GetLastError());
        try
        {
            var result = new byte[resultLen];
            Marshal.Copy(resultPtr, result, 0, resultLen);
            return result;
        }
        finally { Native.gps_free_bytes(resultPtr, resultLen); }
    }

    // =================================================================
    // Password (Argon2id)
    // =================================================================

    /// <summary>Hash password using Argon2id → PHC format string</summary>
    public string HashPassword(string password)
    {
        var rc = Native.gps_hash_password(password, out var ptr);
        if (rc != 0) throw new GpSecurityException(rc, GetLastError());
        try { return Marshal.PtrToStringUTF8(ptr)!; }
        finally { Native.gps_free_string(ptr); }
    }

    /// <summary>Verify password against Argon2id hash</summary>
    public bool VerifyPassword(string password, string hash)
    {
        var rc = Native.gps_verify_password(password, hash);
        return rc == 0; // 0 = match, -31 = mismatch
    }

    /// <summary>Verify against built-in default password</summary>
    /// <param name="password">Password to check</param>
    /// <param name="type">0 = Program, 1 = Admin</param>
    public bool VerifyDefaultPassword(string password, int type)
    {
        var rc = Native.gps_verify_default_password(password, type);
        return rc == 0;
    }

    // =================================================================
    // GitHub
    // =================================================================

    /// <summary>Get GitHub Installation Access Token (cached)</summary>
    public string GetGitHubToken(long appId, long installationId, string privateKeyPath)
    {
        var rc = Native.gps_github_get_token(
            appId, installationId, privateKeyPath, _configDir, out var ptr);
        if (rc != 0) throw new GpSecurityException(rc, GetLastError());
        try { return Marshal.PtrToStringUTF8(ptr)!; }
        finally { Native.gps_free_string(ptr); }
    }

    /// <summary>Generate GitHub App JWT</summary>
    public string GenerateGitHubJwt(long appId, string privateKeyPath)
    {
        var rc = Native.gps_github_generate_jwt(appId, privateKeyPath, _configDir, out var ptr);
        if (rc != 0) throw new GpSecurityException(rc, GetLastError());
        try { return Marshal.PtrToStringUTF8(ptr)!; }
        finally { Native.gps_free_string(ptr); }
    }

    /// <summary>Clear GitHub token cache</summary>
    public void ClearGitHubTokenCache()
    {
        Native.gps_github_clear_cache();
    }

    // =================================================================
    // Token Management
    // =================================================================

    /// <summary>Save token encrypted to file</summary>
    public void SaveToken(string filePath, string token)
    {
        var rc = Native.gps_token_save(_configDir, filePath, token);
        if (rc != 0) throw new GpSecurityException(rc, GetLastError());
    }

    /// <summary>Load encrypted token from file</summary>
    public string LoadToken(string filePath)
    {
        var rc = Native.gps_token_load(_configDir, filePath, out var ptr);
        if (rc != 0) throw new GpSecurityException(rc, GetLastError());
        try { return Marshal.PtrToStringUTF8(ptr)!; }
        finally { Native.gps_free_string(ptr); }
    }

    /// <summary>Check if token file exists</summary>
    public static bool TokenExists(string filePath)
    {
        return Native.gps_token_exists(filePath) == 1;
    }

    // =================================================================
    // Utility
    // =================================================================

    /// <summary>Get DLL version string</summary>
    public static string GetVersion()
    {
        Native.gps_version(out var ptr);
        try { return Marshal.PtrToStringUTF8(ptr) ?? "unknown"; }
        finally { Native.gps_free_string(ptr); }
    }

    /// <summary>Check if master key exists</summary>
    public static bool HasMasterKey(string configDir)
    {
        return Native.gps_has_master_key(configDir) == 1;
    }

    private static string GetLastError()
    {
        Native.gps_get_last_error(out var ptr);
        try { return Marshal.PtrToStringUTF8(ptr) ?? "Unknown error"; }
        finally { Native.gps_free_string(ptr); }
    }

    public void Dispose()
    {
        // Master key is automatically zeroized on Rust side when dropped
    }
}
