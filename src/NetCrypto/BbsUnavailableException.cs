using System.Security.Cryptography;

namespace NetCrypto;

/// <summary>
/// Thrown by BBS signature and proof operations when the zkryptium-ffi native library
/// could not be loaded for the current platform.
/// </summary>
/// <remarks>
/// Running without the native library is a supported mode: every non-BBS primitive in
/// NetCrypto keeps working, <see cref="IBbsCryptoProvider.IsAvailable"/> reports
/// <c>false</c> without throwing, and only the BBS operations themselves throw this
/// exception. The original native-load error is carried as
/// <see cref="Exception.InnerException"/>.
/// </remarks>
public sealed class BbsUnavailableException : CryptographicException
{
    /// <summary>Create the exception with a message describing why BBS is unavailable.</summary>
    public BbsUnavailableException(string message)
        : base(message)
    {
    }

    /// <summary>
    /// Create the exception with a message describing why BBS is unavailable and the
    /// original native-load error as <see cref="Exception.InnerException"/>.
    /// </summary>
    public BbsUnavailableException(string message, Exception? innerException)
        : base(message, innerException)
    {
    }
}
