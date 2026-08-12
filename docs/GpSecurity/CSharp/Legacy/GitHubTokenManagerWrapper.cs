// GitHubTokenManagerWrapper.cs
// Drop-in replacement for existing GitHubTokenManager.cs
//
// Author: Changwon Heo
// AI Assistant: Claude Code Assistant
// Created: 2025-12-19
// Updated: 2026-01-08 (GpSecurity rebranding)
//
// Usage:
// Replace your existing GitHubTokenManager.cs with this file,
// or modify your code to use NativeSecurityService directly.

using System;
using System.IO;

namespace GpSecurity.CSharp
{
    /// <summary>
    /// GitHub Token Manager wrapper for backwards compatibility
    /// Delegates all calls to NativeSecurityService
    /// </summary>
    public static class GitHubTokenManager
    {
        /// <summary>
        /// Loads GitHub Personal Access Token from encrypted file
        /// </summary>
        /// <param name="configPath">Path to Config folder</param>
        /// <returns>Decrypted token, or empty string on failure</returns>
        public static string LoadToken(string configPath)
        {
            return NativeSecurityService.LoadToken(configPath);
        }

        /// <summary>
        /// Saves GitHub Personal Access Token to encrypted file
        /// </summary>
        /// <param name="configPath">Path to Config folder</param>
        /// <param name="token">Token to save</param>
        /// <returns>True if successful</returns>
        public static bool SaveToken(string configPath, string token)
        {
            return NativeSecurityService.SaveToken(configPath, token);
        }

        /// <summary>
        /// Checks if token file exists
        /// </summary>
        /// <param name="configPath">Path to Config folder</param>
        /// <returns>True if file exists</returns>
        public static bool TokenExists(string configPath)
        {
            return NativeSecurityService.TokenFileExists(configPath);
        }

        /// <summary>
        /// Gets the full path to the token file
        /// </summary>
        /// <param name="configPath">Path to Config folder</param>
        /// <returns>Full path to github_token.dat</returns>
        public static string GetTokenFilePath(string configPath)
        {
            if (string.IsNullOrEmpty(configPath))
                return string.Empty;

            return Path.Combine(configPath, "github_token.dat");
        }

        /// <summary>
        /// Deletes the token file
        /// </summary>
        /// <param name="configPath">Path to Config folder</param>
        /// <returns>True if deleted or didn't exist</returns>
        public static bool DeleteToken(string configPath)
        {
            try
            {
                var filePath = GetTokenFilePath(configPath);
                if (File.Exists(filePath))
                {
                    File.Delete(filePath);
                }
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Validates token format (basic check)
        /// </summary>
        /// <param name="token">Token to validate</param>
        /// <returns>True if token appears valid</returns>
        public static bool IsValidTokenFormat(string token)
        {
            if (string.IsNullOrEmpty(token))
                return false;

            // GitHub tokens typically start with these prefixes
            return token.StartsWith("ghp_") ||  // Personal access token
                   token.StartsWith("ghs_") ||  // Installation token
                   token.StartsWith("gho_") ||  // OAuth token
                   token.StartsWith("ghr_");    // Refresh token
        }
    }
}
