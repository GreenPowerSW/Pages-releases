// AesEncryptionWrapper.cs
// Drop-in replacement for existing AesEncryption.cs
//
// Author: Changwon Heo
// AI Assistant: Claude Code Assistant
// Created: 2025-12-19
// Updated: 2026-01-08 (GpSecurity rebranding)
//
// Usage:
// Replace your existing AesEncryption.cs with this file,
// or modify your code to use NativeSecurityService directly.

using System;

namespace GpSecurity.CSharp
{
    /// <summary>
    /// AES Encryption wrapper for backwards compatibility
    /// Delegates all calls to NativeSecurityService
    /// </summary>
    public static class AesEncryption
    {
        /// <summary>
        /// Encrypts a string using AES-256-CBC
        /// </summary>
        /// <param name="plainText">Text to encrypt</param>
        /// <returns>Base64 encoded encrypted string</returns>
        public static string Encrypt(string plainText)
        {
            return NativeSecurityService.Encrypt(plainText);
        }

        /// <summary>
        /// Decrypts a Base64 encoded encrypted string
        /// </summary>
        /// <param name="encryptedBase64">Base64 encoded ciphertext</param>
        /// <returns>Decrypted plain text</returns>
        public static string Decrypt(string encryptedBase64)
        {
            return NativeSecurityService.Decrypt(encryptedBase64);
        }

        /// <summary>
        /// Encrypts a string and saves to file
        /// </summary>
        /// <param name="filePath">Path to output file</param>
        /// <param name="plainText">Text to encrypt</param>
        /// <returns>True if successful</returns>
        public static bool EncryptToFile(string filePath, string plainText)
        {
            return NativeSecurityService.EncryptToFile(filePath, plainText);
        }

        /// <summary>
        /// Reads and decrypts a Base64 encoded file
        /// </summary>
        /// <param name="filePath">Path to encrypted file</param>
        /// <returns>Decrypted text</returns>
        public static string DecryptFromFile(string filePath)
        {
            return NativeSecurityService.DecryptFromFile(filePath);
        }

        /// <summary>
        /// Decrypts binary data (IV + ciphertext format)
        /// </summary>
        /// <param name="encryptedData">Binary data to decrypt</param>
        /// <returns>Decrypted text</returns>
        public static string DecryptBinary(byte[] encryptedData)
        {
            return NativeSecurityService.DecryptBinary(encryptedData);
        }

        /// <summary>
        /// Reads and decrypts a binary file (for github_app_key.dat)
        /// </summary>
        /// <param name="filePath">Path to binary file</param>
        /// <returns>Decrypted text</returns>
        public static string DecryptBinaryFile(string filePath)
        {
            return NativeSecurityService.DecryptBinaryFile(filePath);
        }

        /// <summary>
        /// Tries to encrypt a string, returning false on failure
        /// </summary>
        /// <param name="plainText">Text to encrypt</param>
        /// <param name="encrypted">Encrypted result</param>
        /// <returns>True if successful</returns>
        public static bool TryEncrypt(string plainText, out string encrypted)
        {
            try
            {
                encrypted = Encrypt(plainText);
                return true;
            }
            catch
            {
                encrypted = string.Empty;
                return false;
            }
        }

        /// <summary>
        /// Tries to decrypt a string, returning false on failure
        /// </summary>
        /// <param name="encryptedBase64">Encrypted text</param>
        /// <param name="decrypted">Decrypted result</param>
        /// <returns>True if successful</returns>
        public static bool TryDecrypt(string encryptedBase64, out string decrypted)
        {
            try
            {
                decrypted = Decrypt(encryptedBase64);
                return true;
            }
            catch
            {
                decrypted = string.Empty;
                return false;
            }
        }
    }
}
