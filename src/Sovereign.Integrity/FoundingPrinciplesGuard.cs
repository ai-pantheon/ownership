using System.Security.Cryptography;
using System.Text;

namespace Sovereign.Integrity;

/// <summary>
/// Cryptographic guardian for immutable founding principles.
///
/// How it works:
/// 1. Define your principles as a string
/// 2. Compute the SHA-256 hash
/// 3. Embed the hash in your code
/// 4. On every startup and periodic check, verify the hash matches
/// 5. If it doesn't — someone tampered with the principles. Alert immediately.
///
/// This is the simplest, most powerful pattern in the entire framework.
/// One line of text changes? The hash breaks. Undetectable modification is impossible.
/// </summary>
public class FoundingPrinciplesGuard
{
    private readonly string _principles;
    private readonly string _expectedHash;

    public FoundingPrinciplesGuard(string principles, string expectedHash)
    {
        _principles = principles;
        _expectedHash = expectedHash;
    }

    /// <summary>
    /// Compute the SHA-256 hash of the principles.
    /// Use this once to generate the hash, then embed it in your code.
    /// </summary>
    public static string ComputeHash(string principles)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(principles));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    /// <summary>
    /// Verify the principles have not been tampered with.
    /// Returns true if intact, false if violated.
    /// </summary>
    public VerificationResult Verify()
    {
        var computed = ComputeHash(_principles);
        var intact = computed == _expectedHash;

        return new VerificationResult
        {
            Intact = intact,
            ExpectedHash = _expectedHash,
            ComputedHash = computed,
            Principles = _principles,
        };
    }
}

public class VerificationResult
{
    public bool Intact { get; init; }
    public string ExpectedHash { get; init; } = "";
    public string ComputedHash { get; init; } = "";
    public string Principles { get; init; } = "";
}
