// GpSecurity.Interop.cs - Low-level P/Invoke declarations for GpSecurity v2.0
//
// .NET 8 LibraryImport (source generator, AOT compatible)
// All strings use UTF-8 marshalling
//
// Author: Changwon Heo (Green Power Co., Ltd.)
// AI Assistant: Claude Code Assistant

using System.Runtime.InteropServices;

namespace GpSecurity;

/// <summary>
/// Native P/Invoke declarations for GpSecurity.dll v2.0
/// All functions use DLL-allocated output with gps_free_* for cleanup.
/// </summary>
internal static partial class Native
{
    private const string DllName = "GpSecurity";

    // =================================================================
    // Encryption (AES-256-GCM)
    // =================================================================

    [LibraryImport(DllName, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int gps_encrypt_string(
        string configDir, string plaintext, out nint result);

    [LibraryImport(DllName, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int gps_decrypt_string(
        string configDir, string encryptedB64, out nint result);

    [LibraryImport(DllName, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int gps_encrypt_to_file(
        string configDir, string plaintext, string filePath);

    [LibraryImport(DllName, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int gps_decrypt_from_file(
        string configDir, string filePath, out nint result);

    [LibraryImport(DllName)]
    internal static partial int gps_encrypt_bytes(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string configDir,
        byte[] data, int dataLen,
        out nint resultPtr, out int resultLen);

    [LibraryImport(DllName)]
    internal static partial int gps_decrypt_bytes(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string configDir,
        byte[] data, int dataLen,
        out nint resultPtr, out int resultLen);

    // =================================================================
    // Key Management (DPAPI + HKDF)
    // =================================================================

    [LibraryImport(DllName, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int gps_init_master_key(string configDir);

    [LibraryImport(DllName, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int gps_has_master_key(string configDir);

    // =================================================================
    // Password (Argon2id)
    // =================================================================

    [LibraryImport(DllName, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int gps_hash_password(string password, out nint result);

    [LibraryImport(DllName, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int gps_verify_password(string password, string hash);

    [LibraryImport(DllName, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int gps_verify_default_password(string password, int passwordType);

    // =================================================================
    // GitHub (JWT + Installation Token)
    // =================================================================

    [LibraryImport(DllName, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int gps_github_generate_jwt(
        long appId, string privateKeyPath, string configDir, out nint result);

    [LibraryImport(DllName, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int gps_github_get_token(
        long appId, long installationId, string privateKeyPath,
        string configDir, out nint result);

    [LibraryImport(DllName)]
    internal static partial int gps_github_clear_cache();

    // =================================================================
    // Token Management
    // =================================================================

    [LibraryImport(DllName, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int gps_token_save(
        string configDir, string filePath, string token);

    [LibraryImport(DllName, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int gps_token_load(
        string configDir, string filePath, out nint result);

    [LibraryImport(DllName, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int gps_token_exists(string filePath);

    // =================================================================
    // Utility
    // =================================================================

    [LibraryImport(DllName)]
    internal static partial int gps_version(out nint result);

    [LibraryImport(DllName)]
    internal static partial int gps_get_last_error(out nint result);

    [LibraryImport(DllName)]
    internal static partial void gps_free_string(nint ptr);

    [LibraryImport(DllName)]
    internal static partial void gps_free_bytes(nint ptr, int len);
}
