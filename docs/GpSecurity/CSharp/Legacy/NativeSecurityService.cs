// NativeSecurityService.cs
// GpSecurity Native DLL P/Invoke Wrapper
//
// Author: Changwon Heo
// AI Assistant: Claude Code Assistant
// Created: 2025-12-19
// Updated: 2026-01-08 (GpSecurity rebranding)
//
// Usage:
// 1. Copy this file to your project's Services/Security/ folder
// 2. Update the namespace to match your project
// 3. Update APP_ID and INSTALLATION_ID for your project
// 4. Ensure GpSecurity.dll is in the Lib folder or application directory

using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace GpSecurity.CSharp
{
    /// <summary>
    /// GpSecurity Native DLL P/Invoke Wrapper
    /// Provides secure encryption and GitHub App authentication functions
    /// </summary>
    public static class NativeSecurityService
    {
        // ============================================
        // Project-specific settings (modify for each project)
        // ============================================

        /// <summary>GitHub App ID (same for all projects)</summary>
        private const int APP_ID = 2449919;

        /// <summary>GitHub App Installation ID (different per project)</summary>
        /// <remarks>
        /// CBViewer: 99005853
        /// CellBalancer1: (to be confirmed)
        /// GroupCellBalancing: (to be confirmed)
        /// SimulationDAQ: (to be confirmed)
        /// </remarks>
        private const long INSTALLATION_ID = 99005853;

        // ============================================
        // DLL Configuration
        // ============================================

        private const string DLL_NAME = "GpSecurity";
        private const int DEFAULT_BUFFER_SIZE = 4096;
        private const int LARGE_BUFFER_SIZE = 8192;
        private const int TOKEN_BUFFER_SIZE = 1024;

        // ============================================
        // Error Codes (must match Rust error.rs)
        // ============================================

        public const int CBS_OK = 0;
        public const int CBS_ERR_NULL_POINTER = -1;
        public const int CBS_ERR_BUFFER_TOO_SMALL = -2;
        public const int CBS_ERR_INVALID_UTF8 = -3;
        public const int CBS_ERR_INTERNAL = -9;
        public const int CBS_ERR_FILE_NOT_FOUND = -10;
        public const int CBS_ERR_FILE_READ_FAILED = -11;
        public const int CBS_ERR_FILE_WRITE_FAILED = -12;
        public const int CBS_ERR_FILE_CREATE_FAILED = -13;
        public const int CBS_ERR_ENCRYPTION_FAILED = -20;
        public const int CBS_ERR_DECRYPTION_FAILED = -21;
        public const int CBS_ERR_INVALID_KEY = -22;
        public const int CBS_ERR_INVALID_DATA = -23;
        public const int CBS_ERR_INVALID_BASE64 = -24;
        public const int CBS_ERR_JWT_FAILED = -30;
        public const int CBS_ERR_TOKEN_REQUEST_FAILED = -31;
        public const int CBS_ERR_NETWORK_ERROR = -32;
        public const int CBS_ERR_INVALID_RESPONSE = -33;
        public const int CBS_ERR_PRIVATE_KEY_INVALID = -34;

        // ============================================
        // Static Constructor - DLL Path Setup
        // ============================================

        private static bool _initialized = false;
        private static readonly object _initLock = new object();

        static NativeSecurityService()
        {
            Initialize();
        }

        private static void Initialize()
        {
            if (_initialized) return;

            lock (_initLock)
            {
                if (_initialized) return;

                try
                {
                    // Try to set DLL directory to Lib folder
                    var appDir = AppDomain.CurrentDomain.BaseDirectory;
                    var libPath = Path.Combine(appDir, "Lib");
                    if (Directory.Exists(libPath))
                    {
                        SetDllDirectory(libPath);
                    }

                    _initialized = true;
                }
                catch
                {
                    // Silently ignore initialization errors
                    _initialized = true;
                }
            }
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetDllDirectory(string lpPathName);

        // ============================================
        // Native Function Declarations
        // ============================================

        #region AES Encryption

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern int gps_encrypt_string(
            string plainText,
            StringBuilder outBuffer,
            int bufferSize);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern int gps_decrypt_string(
            string encryptedBase64,
            StringBuilder outBuffer,
            int bufferSize);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern int gps_encrypt_to_file(
            string filePath,
            string plainText);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern int gps_decrypt_from_file(
            string filePath,
            StringBuilder outBuffer,
            int bufferSize);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern int gps_decrypt_binary(
            byte[] encryptedData,
            int dataLength,
            StringBuilder outBuffer,
            int bufferSize);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern int gps_decrypt_binary_file(
            string filePath,
            StringBuilder outBuffer,
            int bufferSize);

        #endregion

        #region GitHub App Authentication

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern int gps_github_get_token(
            string configPath,
            int appId,
            long installationId,
            StringBuilder outToken,
            int bufferSize);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern int gps_github_generate_jwt(
            string privateKeyPem,
            int appId,
            StringBuilder outJwt,
            int bufferSize);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern int gps_github_clear_cache();

        #endregion

        #region Token Management

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern int gps_token_load(
            string configPath,
            StringBuilder outToken,
            int bufferSize);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern int gps_token_save(
            string configPath,
            string token);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern int gps_token_exists(string configPath);

        #endregion

        #region Utility

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern int gps_get_last_error(
            StringBuilder outBuffer,
            int bufferSize);

        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern int gps_version(
            StringBuilder outBuffer,
            int bufferSize);

        #endregion

        // ============================================
        // Public API - AES Encryption
        // ============================================

        /// <summary>
        /// Encrypts a string using AES-256-CBC
        /// </summary>
        /// <param name="plainText">Text to encrypt</param>
        /// <returns>Base64 encoded encrypted string</returns>
        /// <exception cref="CryptographicException">Encryption failed</exception>
        public static string Encrypt(string plainText)
        {
            if (string.IsNullOrEmpty(plainText))
                return string.Empty;

            var buffer = new StringBuilder(DEFAULT_BUFFER_SIZE);
            int result = gps_encrypt_string(plainText, buffer, buffer.Capacity);

            if (result < 0)
                throw new CryptographicException($"Encryption failed: {GetLastError()} (code: {result})");

            return buffer.ToString();
        }

        /// <summary>
        /// Decrypts a Base64 encoded encrypted string
        /// </summary>
        /// <param name="encryptedBase64">Base64 encoded ciphertext</param>
        /// <returns>Decrypted plain text</returns>
        /// <exception cref="CryptographicException">Decryption failed</exception>
        public static string Decrypt(string encryptedBase64)
        {
            if (string.IsNullOrEmpty(encryptedBase64))
                return string.Empty;

            var buffer = new StringBuilder(DEFAULT_BUFFER_SIZE);
            int result = gps_decrypt_string(encryptedBase64, buffer, buffer.Capacity);

            if (result < 0)
                throw new CryptographicException($"Decryption failed: {GetLastError()} (code: {result})");

            return buffer.ToString();
        }

        /// <summary>
        /// Encrypts a string and saves to file
        /// </summary>
        /// <param name="filePath">Path to output file</param>
        /// <param name="plainText">Text to encrypt</param>
        /// <returns>True if successful</returns>
        public static bool EncryptToFile(string filePath, string plainText)
        {
            if (string.IsNullOrEmpty(filePath))
                return false;

            int result = gps_encrypt_to_file(filePath, plainText ?? string.Empty);
            return result >= 0;
        }

        /// <summary>
        /// Reads and decrypts a Base64 encoded file
        /// </summary>
        /// <param name="filePath">Path to encrypted file</param>
        /// <returns>Decrypted text, or empty string on failure</returns>
        public static string DecryptFromFile(string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
                return string.Empty;

            var buffer = new StringBuilder(DEFAULT_BUFFER_SIZE);
            int result = gps_decrypt_from_file(filePath, buffer, buffer.Capacity);

            return result >= 0 ? buffer.ToString() : string.Empty;
        }

        /// <summary>
        /// Decrypts binary data (IV + ciphertext format)
        /// </summary>
        /// <param name="encryptedData">Binary data to decrypt</param>
        /// <returns>Decrypted text, or empty string on failure</returns>
        public static string DecryptBinary(byte[] encryptedData)
        {
            if (encryptedData == null || encryptedData.Length == 0)
                return string.Empty;

            var buffer = new StringBuilder(LARGE_BUFFER_SIZE);
            int result = gps_decrypt_binary(encryptedData, encryptedData.Length, buffer, buffer.Capacity);

            return result >= 0 ? buffer.ToString() : string.Empty;
        }

        /// <summary>
        /// Reads and decrypts a binary file (for github_app_key.dat)
        /// </summary>
        /// <param name="filePath">Path to binary file</param>
        /// <returns>Decrypted text, or empty string on failure</returns>
        public static string DecryptBinaryFile(string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
                return string.Empty;

            var buffer = new StringBuilder(LARGE_BUFFER_SIZE);
            int result = gps_decrypt_binary_file(filePath, buffer, buffer.Capacity);

            return result >= 0 ? buffer.ToString() : string.Empty;
        }

        // ============================================
        // Public API - GitHub App Authentication
        // ============================================

        /// <summary>
        /// Gets GitHub App Installation Token asynchronously
        /// </summary>
        /// <param name="configPath">Path to Config folder</param>
        /// <returns>Access token, or null on failure</returns>
        public static async Task<string?> GetInstallationTokenAsync(string configPath)
        {
            return await Task.Run(() =>
            {
                var buffer = new StringBuilder(TOKEN_BUFFER_SIZE);
                int result = gps_github_get_token(
                    configPath,
                    APP_ID,
                    INSTALLATION_ID,
                    buffer,
                    buffer.Capacity);

                if (result < 0)
                {
                    System.Diagnostics.Debug.WriteLine(
                        $"[NativeSecurity] Token request failed: {GetLastError()} (code: {result})");
                    return null;
                }

                return buffer.ToString();
            });
        }

        /// <summary>
        /// Gets GitHub App Installation Token asynchronously with custom IDs
        /// </summary>
        /// <param name="configPath">Path to Config folder</param>
        /// <param name="appId">GitHub App ID</param>
        /// <param name="installationId">Installation ID</param>
        /// <returns>Access token, or null on failure</returns>
        public static async Task<string?> GetInstallationTokenAsync(string configPath, int appId, long installationId)
        {
            return await Task.Run(() =>
            {
                var buffer = new StringBuilder(TOKEN_BUFFER_SIZE);
                int result = gps_github_get_token(
                    configPath,
                    appId,
                    installationId,
                    buffer,
                    buffer.Capacity);

                if (result < 0)
                {
                    System.Diagnostics.Debug.WriteLine(
                        $"[NativeSecurity] Token request failed: {GetLastError()} (code: {result})");
                    return null;
                }

                return buffer.ToString();
            });
        }

        /// <summary>
        /// Generates JWT token for GitHub App authentication
        /// </summary>
        /// <param name="privateKeyPem">PEM formatted private key</param>
        /// <param name="appId">GitHub App ID</param>
        /// <returns>JWT token, or null on failure</returns>
        public static string? GenerateJwt(string privateKeyPem, int appId)
        {
            if (string.IsNullOrEmpty(privateKeyPem))
                return null;

            var buffer = new StringBuilder(TOKEN_BUFFER_SIZE);
            int result = gps_github_generate_jwt(privateKeyPem, appId, buffer, buffer.Capacity);

            return result >= 0 ? buffer.ToString() : null;
        }

        /// <summary>
        /// Clears the token cache
        /// </summary>
        public static void ClearTokenCache()
        {
            gps_github_clear_cache();
        }

        // ============================================
        // Public API - Token Management
        // ============================================

        /// <summary>
        /// Loads GitHub PAT from encrypted file
        /// </summary>
        /// <param name="configPath">Path to Config folder</param>
        /// <returns>Decrypted token, or empty string on failure</returns>
        public static string LoadToken(string configPath)
        {
            if (string.IsNullOrEmpty(configPath))
                return string.Empty;

            var buffer = new StringBuilder(TOKEN_BUFFER_SIZE);
            int result = gps_token_load(configPath, buffer, buffer.Capacity);

            return result >= 0 ? buffer.ToString() : string.Empty;
        }

        /// <summary>
        /// Saves GitHub PAT to encrypted file
        /// </summary>
        /// <param name="configPath">Path to Config folder</param>
        /// <param name="token">Token to save</param>
        /// <returns>True if successful</returns>
        public static bool SaveToken(string configPath, string token)
        {
            if (string.IsNullOrEmpty(configPath) || string.IsNullOrEmpty(token))
                return false;

            int result = gps_token_save(configPath, token);
            return result >= 0;
        }

        /// <summary>
        /// Checks if token file exists
        /// </summary>
        /// <param name="configPath">Path to Config folder</param>
        /// <returns>True if file exists</returns>
        public static bool TokenFileExists(string configPath)
        {
            if (string.IsNullOrEmpty(configPath))
                return false;

            return gps_token_exists(configPath) == 1;
        }

        // ============================================
        // Public API - Utility
        // ============================================

        /// <summary>
        /// Gets the last error message from the DLL
        /// </summary>
        /// <returns>Error message</returns>
        public static string GetLastError()
        {
            var buffer = new StringBuilder(TOKEN_BUFFER_SIZE);
            gps_get_last_error(buffer, buffer.Capacity);
            return buffer.ToString();
        }

        /// <summary>
        /// Gets the DLL version string
        /// </summary>
        /// <returns>Version string (e.g., "1.0.0")</returns>
        public static string GetVersion()
        {
            var buffer = new StringBuilder(64);
            gps_version(buffer, buffer.Capacity);
            return buffer.ToString();
        }

        /// <summary>
        /// Checks if the native DLL is available
        /// </summary>
        /// <returns>True if DLL can be loaded</returns>
        public static bool IsAvailable()
        {
            try
            {
                var version = GetVersion();
                return !string.IsNullOrEmpty(version);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Gets error description for error code
        /// </summary>
        /// <param name="errorCode">Error code</param>
        /// <returns>Error description</returns>
        public static string GetErrorDescription(int errorCode)
        {
            return errorCode switch
            {
                CBS_OK => "Success",
                CBS_ERR_NULL_POINTER => "Null pointer provided",
                CBS_ERR_BUFFER_TOO_SMALL => "Buffer too small",
                CBS_ERR_INVALID_UTF8 => "Invalid UTF-8 string",
                CBS_ERR_INTERNAL => "Internal error",
                CBS_ERR_FILE_NOT_FOUND => "File not found",
                CBS_ERR_FILE_READ_FAILED => "Failed to read file",
                CBS_ERR_FILE_WRITE_FAILED => "Failed to write file",
                CBS_ERR_FILE_CREATE_FAILED => "Failed to create file",
                CBS_ERR_ENCRYPTION_FAILED => "Encryption failed",
                CBS_ERR_DECRYPTION_FAILED => "Decryption failed",
                CBS_ERR_INVALID_KEY => "Invalid encryption key",
                CBS_ERR_INVALID_DATA => "Invalid data format",
                CBS_ERR_INVALID_BASE64 => "Invalid Base64 encoding",
                CBS_ERR_JWT_FAILED => "JWT generation failed",
                CBS_ERR_TOKEN_REQUEST_FAILED => "Token request failed",
                CBS_ERR_NETWORK_ERROR => "Network error",
                CBS_ERR_INVALID_RESPONSE => "Invalid response from server",
                CBS_ERR_PRIVATE_KEY_INVALID => "Invalid private key",
                _ => $"Unknown error ({errorCode})"
            };
        }
    }
}
