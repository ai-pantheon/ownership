using System.Security.Cryptography;
using System.Text;

namespace Sovereign.Crypto;

/// <summary>
/// Key derivation from user credentials.
/// Derives a Key Encryption Key (KEK) that never leaves the user's device.
///
/// Uses PBKDF2-SHA256 with high iteration count.
/// The KEK is deterministic from the same credentials — no state needed.
/// </summary>
public static class SovereignKeyDerivation
{
    /// <summary>Default iteration count. OWASP recommends 600,000+ for PBKDF2-SHA256.</summary>
    public const int DefaultIterations = 600_000;

    /// <summary>KEK length in bytes (256-bit).</summary>
    public const int KekLengthBytes = 32;

    /// <summary>Salt length in bytes (128-bit).</summary>
    public const int SaltLengthBytes = 16;

    /// <summary>
    /// Derive a KEK from user credentials and a salt.
    /// The salt should be stored alongside the user's encrypted data (it is not secret).
    /// The same credentials + salt always produce the same KEK.
    /// </summary>
    public static byte[] DeriveKek(string credentials, byte[] salt, int iterations = DefaultIterations)
    {
        ArgumentException.ThrowIfNullOrEmpty(credentials);
        ArgumentNullException.ThrowIfNull(salt);
        if (salt.Length < SaltLengthBytes)
            throw new ArgumentException($"Salt must be at least {SaltLengthBytes} bytes.", nameof(salt));

        using var pbkdf2 = new Rfc2898DeriveBytes(
            Encoding.UTF8.GetBytes(credentials),
            salt,
            iterations,
            HashAlgorithmName.SHA256);

        return pbkdf2.GetBytes(KekLengthBytes);
    }

    /// <summary>
    /// Generate a cryptographically secure random salt.
    /// Store this with the user's account — it is not secret but must be consistent.
    /// </summary>
    public static byte[] GenerateSalt()
    {
        return RandomNumberGenerator.GetBytes(SaltLengthBytes);
    }
}
