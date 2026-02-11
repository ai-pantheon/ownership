using System.Security.Cryptography;
using Sovereign.Crypto;
using Sovereign.Recovery;
using Xunit;

namespace Sovereign.Tests;

public class ShamirTests
{
    [Fact]
    public void Split_Reconstruct_All_Shares()
    {
        var secret = "Your mind belongs to you."u8.ToArray();
        var shares = ShamirSecretSharing.Split(secret, 5, 3);
        Assert.Equal(secret, ShamirSecretSharing.Reconstruct(shares));
    }

    [Fact]
    public void Reconstruct_Exact_Threshold()
    {
        var secret = RandomNumberGenerator.GetBytes(32);
        var shares = ShamirSecretSharing.Split(secret, 5, 3);
        var subset = new[] { shares[0], shares[2], shares[4] };
        Assert.Equal(secret, ShamirSecretSharing.Reconstruct(subset));
    }

    [Fact]
    public void Any_K_Combination_Works()
    {
        var secret = "any combo"u8.ToArray();
        var shares = ShamirSecretSharing.Split(secret, 5, 3);

        for (int i = 0; i < 5; i++)
        for (int j = i + 1; j < 5; j++)
        for (int k = j + 1; k < 5; k++)
        {
            var subset = new[] { shares[i], shares[j], shares[k] };
            Assert.Equal(secret, ShamirSecretSharing.Reconstruct(subset));
        }
    }

    [Fact]
    public void Fewer_Than_Threshold_Fails()
    {
        var secret = "need three"u8.ToArray();
        var shares = ShamirSecretSharing.Split(secret, 5, 3);
        var insufficient = new[] { shares[0], shares[1] };
        Assert.NotEqual(secret, ShamirSecretSharing.Reconstruct(insufficient));
    }

    [Fact]
    public void Share_Serialization()
    {
        var secret = "serialize"u8.ToArray();
        var shares = ShamirSecretSharing.Split(secret, 3, 2);
        var restored = shares.Select(s => Share.FromBytes(s.ToBytes())).ToArray();
        Assert.Equal(secret, ShamirSecretSharing.Reconstruct(restored));
    }

    [Fact]
    public void Full_Key_Recovery_Pipeline()
    {
        var salt = SovereignKeyDerivation.GenerateSalt();
        var kek = SovereignKeyDerivation.DeriveKek("passphrase", salt);

        var envelope = SovereignEnvelopeEncryption.EncryptString("precious data", kek);
        var shares = ShamirSecretSharing.Split(kek, 5, 3);

        var recovered = ShamirSecretSharing.Reconstruct(
            new[] { shares[0], shares[2], shares[4] });
        Assert.Equal("precious data",
            SovereignEnvelopeEncryption.DecryptString(envelope, recovered));
    }
}
