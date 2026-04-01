// GitHubAppAuthenticatorWrapper.cs
// Drop-in replacement for existing GitHubAppAuthenticator.cs
//
// Author: Changwon Heo
// AI Assistant: Claude Code Assistant
// Created: 2025-12-19
// Updated: 2026-01-08 (GpSecurity rebranding)
//
// Usage:
// Replace your existing GitHubAppAuthenticator.cs with this file,
// or modify your code to use NativeSecurityService directly.

using System;
using System.IO;
using System.Threading.Tasks;

namespace GpSecurity.CSharp
{
    /// <summary>
    /// GitHub App Authenticator wrapper for backwards compatibility
    /// Delegates all calls to NativeSecurityService
    /// </summary>
    public static class GitHubAppAuthenticator
    {
        /// <summary>
        /// Gets GitHub App Installation Token
        /// </summary>
        /// <param name="configPath">Path to Config folder containing github_app_key.dat</param>
        /// <returns>Access token, or null on failure</returns>
        public static async Task<string?> GetInstallationTokenAsync(string configPath)
        {
            return await NativeSecurityService.GetInstallationTokenAsync(configPath);
        }

        /// <summary>
        /// Gets GitHub App Installation Token with custom App ID and Installation ID
        /// </summary>
        /// <param name="configPath">Path to Config folder</param>
        /// <param name="appId">GitHub App ID</param>
        /// <param name="installationId">Installation ID</param>
        /// <returns>Access token, or null on failure</returns>
        public static async Task<string?> GetInstallationTokenAsync(
            string configPath,
            int appId,
            long installationId)
        {
            return await NativeSecurityService.GetInstallationTokenAsync(configPath, appId, installationId);
        }

        /// <summary>
        /// Clears the cached token
        /// </summary>
        public static void ClearCache()
        {
            NativeSecurityService.ClearTokenCache();
        }

        /// <summary>
        /// Checks if private key file exists
        /// </summary>
        /// <param name="configPath">Path to Config folder</param>
        /// <returns>True if github_app_key.dat exists</returns>
        public static bool HasPrivateKey(string configPath)
        {
            if (string.IsNullOrEmpty(configPath))
                return false;

            var keyPath = Path.Combine(configPath, "github_app_key.dat");
            return File.Exists(keyPath);
        }

        /// <summary>
        /// Validates that the private key can be decrypted
        /// </summary>
        /// <param name="configPath">Path to Config folder</param>
        /// <returns>True if key is valid and can be decrypted</returns>
        public static bool ValidatePrivateKey(string configPath)
        {
            if (!HasPrivateKey(configPath))
                return false;

            try
            {
                var keyPath = Path.Combine(configPath, "github_app_key.dat");
                var decrypted = NativeSecurityService.DecryptBinaryFile(keyPath);
                return !string.IsNullOrEmpty(decrypted) &&
                       decrypted.Contains("-----BEGIN") &&
                       decrypted.Contains("PRIVATE KEY-----");
            }
            catch
            {
                return false;
            }
        }
    }
}
