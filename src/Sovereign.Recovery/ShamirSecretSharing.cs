using System.Security.Cryptography;

namespace Sovereign.Recovery;

/// <summary>
/// Shamir's Secret Sharing over GF(256).
///
/// Splits a secret into N shares where any K shares can reconstruct the original.
/// Fewer than K shares reveal zero information about the secret.
///
/// This is information-theoretically secure — not computationally secure.
/// It cannot be broken regardless of computing power. The security comes from
/// the mathematics of polynomial interpolation, not from computational difficulty.
///
/// Use case: Split a KEK recovery key into shares distributed to trusted contacts.
/// If you lose your key, K of your N contacts can help you recover — but no single
/// contact (and no single entity, including the platform) can reconstruct it alone.
/// </summary>
public static class ShamirSecretSharing
{
    /// <summary>
    /// Split a secret into N shares, requiring K to reconstruct.
    /// </summary>
    /// <param name="secret">The secret bytes to split.</param>
    /// <param name="totalShares">Total number of shares to generate (N). Max 255.</param>
    /// <param name="threshold">Minimum shares needed to reconstruct (K). Must be &lt;= N.</param>
    /// <returns>Array of N shares. Each share contains its index (1-based) and data.</returns>
    public static Share[] Split(byte[] secret, int totalShares, int threshold)
    {
        ArgumentNullException.ThrowIfNull(secret);
        if (secret.Length == 0)
            throw new ArgumentException("Secret must not be empty.", nameof(secret));
        if (totalShares < 2 || totalShares > 255)
            throw new ArgumentOutOfRangeException(nameof(totalShares), "Must be between 2 and 255.");
        if (threshold < 2 || threshold > totalShares)
            throw new ArgumentOutOfRangeException(nameof(threshold), "Must be between 2 and N.");

        var shares = new Share[totalShares];
        for (var i = 0; i < totalShares; i++)
        {
            shares[i] = new Share
            {
                Index = (byte)(i + 1),
                Data = new byte[secret.Length],
                Threshold = threshold,
            };
        }

        // For each byte of the secret, create a random polynomial of degree (threshold-1)
        // where the constant term is the secret byte, and evaluate at points 1..N
        var coefficients = new byte[threshold];

        for (var byteIndex = 0; byteIndex < secret.Length; byteIndex++)
        {
            // Constant term is the secret byte
            coefficients[0] = secret[byteIndex];

            // Random coefficients for higher-degree terms
            RandomNumberGenerator.Fill(coefficients.AsSpan(1));

            // Evaluate polynomial at x = 1, 2, ..., N
            for (var shareIndex = 0; shareIndex < totalShares; shareIndex++)
            {
                var x = (byte)(shareIndex + 1);
                shares[shareIndex].Data[byteIndex] = GF256.EvaluatePolynomial(coefficients, x);
            }
        }

        return shares;
    }

    /// <summary>
    /// Reconstruct a secret from K or more shares.
    /// </summary>
    /// <param name="shares">At least K shares (threshold number).</param>
    /// <returns>The reconstructed secret.</returns>
    /// <exception cref="ArgumentException">If insufficient shares or duplicate indices.</exception>
    public static byte[] Reconstruct(Share[] shares)
    {
        ArgumentNullException.ThrowIfNull(shares);
        if (shares.Length < 2)
            throw new ArgumentException("Need at least 2 shares to reconstruct.", nameof(shares));

        // Verify no duplicate indices
        var indices = new HashSet<byte>();
        foreach (var share in shares)
        {
            if (!indices.Add(share.Index))
                throw new ArgumentException($"Duplicate share index: {share.Index}");
        }

        // All shares must be the same length
        var secretLength = shares[0].Data.Length;
        if (shares.Any(s => s.Data.Length != secretLength))
            throw new ArgumentException("All shares must have the same data length.");

        var secret = new byte[secretLength];

        // For each byte position, use Lagrange interpolation to find the constant term
        for (var byteIndex = 0; byteIndex < secretLength; byteIndex++)
        {
            // Collect (x, y) pairs for this byte position
            var xs = shares.Select(s => s.Index).ToArray();
            var ys = shares.Select(s => s.Data[byteIndex]).ToArray();

            // Lagrange interpolation at x=0 gives us the constant term (the secret byte)
            secret[byteIndex] = GF256.LagrangeInterpolateAtZero(xs, ys);
        }

        return secret;
    }
}

/// <summary>
/// A single share from Shamir's Secret Sharing.
/// Distribute these to trusted contacts. Each share alone reveals nothing.
/// </summary>
public class Share
{
    /// <summary>Share index (1-255). Each share must have a unique index.</summary>
    public byte Index { get; init; }

    /// <summary>Share data. Same length as the original secret.</summary>
    public byte[] Data { get; init; } = Array.Empty<byte>();

    /// <summary>Minimum shares needed to reconstruct (K). Informational only.</summary>
    public int Threshold { get; init; }

    /// <summary>
    /// Serialize to a portable format: [Index(1)][Threshold(1)][Length(4)][Data(N)]
    /// </summary>
    public byte[] ToBytes()
    {
        var result = new byte[6 + Data.Length];
        result[0] = Index;
        result[1] = (byte)Threshold;
        BitConverter.TryWriteBytes(result.AsSpan(2), Data.Length);
        Buffer.BlockCopy(Data, 0, result, 6, Data.Length);
        return result;
    }

    /// <summary>
    /// Deserialize from portable format.
    /// </summary>
    public static Share FromBytes(byte[] data)
    {
        if (data.Length < 6)
            throw new ArgumentException("Data too short for a valid share.");

        var index = data[0];
        var threshold = data[1];
        var length = BitConverter.ToInt32(data, 2);

        if (data.Length < 6 + length)
            throw new ArgumentException("Data length mismatch.");

        var shareData = new byte[length];
        Buffer.BlockCopy(data, 6, shareData, 0, length);

        return new Share { Index = index, Threshold = threshold, Data = shareData };
    }
}

/// <summary>
/// Galois Field GF(256) arithmetic.
/// All operations are over the finite field GF(2^8) with the irreducible polynomial
/// x^8 + x^4 + x^3 + x + 1 (0x11B), which is the AES polynomial.
///
/// In GF(256):
/// - Addition is XOR
/// - Multiplication uses log/exp tables for efficiency
/// - Every non-zero element has a multiplicative inverse
/// - No overflow, no rounding, no approximation — exact arithmetic
/// </summary>
internal static class GF256
{
    private static readonly byte[] ExpTable = new byte[512];
    private static readonly byte[] LogTable = new byte[256];

    static GF256()
    {
        // Build log and exp tables using generator 3 over AES polynomial 0x11B
        byte x = 1;
        for (var i = 0; i < 255; i++)
        {
            ExpTable[i] = x;
            LogTable[x] = (byte)i;
            x = Multiply_Slow(x, 3);
        }

        // Extend exp table for convenience (avoids modular arithmetic)
        for (var i = 255; i < 512; i++)
        {
            ExpTable[i] = ExpTable[i - 255];
        }
    }

    /// <summary>Slow multiplication used only during table initialization.</summary>
    private static byte Multiply_Slow(byte a, byte b)
    {
        byte result = 0;
        byte hi_bit;

        for (var i = 0; i < 8; i++)
        {
            if ((b & 1) != 0)
                result ^= a;

            hi_bit = (byte)(a & 0x80);
            a <<= 1;

            if (hi_bit != 0)
                a ^= 0x1b; // x^8 + x^4 + x^3 + x + 1

            b >>= 1;
        }

        return result;
    }

    /// <summary>Multiply two elements in GF(256). O(1) via lookup tables.</summary>
    internal static byte Multiply(byte a, byte b)
    {
        if (a == 0 || b == 0)
            return 0;

        return ExpTable[LogTable[a] + LogTable[b]];
    }

    /// <summary>Multiplicative inverse in GF(256). a * Inverse(a) = 1.</summary>
    internal static byte Inverse(byte a)
    {
        if (a == 0)
            throw new DivideByZeroException("Zero has no inverse in GF(256).");

        return ExpTable[255 - LogTable[a]];
    }

    /// <summary>Division in GF(256). a / b = a * inverse(b).</summary>
    internal static byte Divide(byte a, byte b)
    {
        if (b == 0)
            throw new DivideByZeroException("Division by zero in GF(256).");
        if (a == 0)
            return 0;

        return ExpTable[(LogTable[a] + 255 - LogTable[b]) % 255];
    }

    /// <summary>
    /// Evaluate a polynomial at point x in GF(256).
    /// coefficients[0] is the constant term, coefficients[n-1] is the highest degree.
    /// Uses Horner's method.
    /// </summary>
    internal static byte EvaluatePolynomial(byte[] coefficients, byte x)
    {
        if (x == 0)
            return coefficients[0];

        // Horner's method: (...((a_n * x + a_{n-1}) * x + a_{n-2}) * x + ... + a_0)
        byte result = 0;
        for (var i = coefficients.Length - 1; i >= 0; i--)
        {
            result = (byte)(Multiply(result, x) ^ coefficients[i]);
        }

        return result;
    }

    /// <summary>
    /// Lagrange interpolation at x=0 in GF(256).
    /// Given points (xs[i], ys[i]), finds the unique polynomial passing through all points
    /// and returns its value at x=0 (which is the constant term — our secret).
    /// </summary>
    internal static byte LagrangeInterpolateAtZero(byte[] xs, byte[] ys)
    {
        byte result = 0;

        for (var i = 0; i < xs.Length; i++)
        {
            // Compute Lagrange basis polynomial L_i(0)
            byte numerator = 1;
            byte denominator = 1;

            for (var j = 0; j < xs.Length; j++)
            {
                if (i == j) continue;

                // L_i(0) = product of (0 - x_j) / (x_i - x_j) for j != i
                // In GF(256), subtraction is XOR, and 0 XOR x_j = x_j
                numerator = Multiply(numerator, xs[j]);
                denominator = Multiply(denominator, (byte)(xs[i] ^ xs[j]));
            }

            // L_i(0) * y_i
            var lagrangeTerm = Multiply(ys[i], Divide(numerator, denominator));
            result ^= lagrangeTerm; // Addition in GF(256) is XOR
        }

        return result;
    }
}
