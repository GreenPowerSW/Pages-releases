// GpSecurityException.cs - Custom exception for GpSecurity errors
//
// Author: Changwon Heo (Green Power Co., Ltd.)
// AI Assistant: Claude Code Assistant

namespace GpSecurity;

/// <summary>
/// Exception thrown by GpSecurity operations.
/// Contains the native error code for programmatic handling.
/// </summary>
public class GpSecurityException : Exception
{
    /// <summary>Native error code from GpSecurity.dll</summary>
    public int ErrorCode { get; }

    public GpSecurityException(int code, string message)
        : base(message)
    {
        ErrorCode = code;
    }

    public override string ToString()
        => $"GpSecurityException (code={ErrorCode}): {Message}";
}
