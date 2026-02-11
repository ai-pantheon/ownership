using System.Security.Cryptography;
using Sovereign.Crypto;
using Xunit;

namespace Sovereign.Tests;

public class EnvelopeEncryptionTests
{
    [Fact]
    public void Encrypt_Decrypt_RoundTrip()
    {
        var kek = RandomNumberGenerator.GetBytes(32);
        var plaintext = "Your mind belongs to you."u8.ToArray();

        var envelope = SovereignEnvelopeEncryption.Encrypt(plaintext, kek);
        var decrypted = SovereignEnvelopeEncryption.Decrypt(envelope, kek);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void String_RoundTrip()
    {
        var kek = RandomNumberGenerator.GetBytes(32);
        var msg = "Architecture, not policy.";

        var envelope = SovereignEnvelopeEncryption.EncryptString(msg, kek);
        Assert.Equal(msg, SovereignEnvelopeEncryption.DecryptString(envelope, kek));
    }

    [Fact]
    public void Wrong_Kek_Throws()
    {
        var kek = RandomNumberGenerator.GetBytes(32);
        var wrong = RandomNumberGenerator.GetBytes(32);

        var envelope = SovereignEnvelopeEncryption.EncryptString("secret", kek);
        Assert.ThrowsAny<CryptographicException>(() =>
            SovereignEnvelopeEncryption.Decrypt(envelope, wrong));
    }

    [Fact]
    public void Tampered_Ciphertext_Throws()
    {
        var kek = RandomNumberGenerator.GetBytes(32);
        var envelope = SovereignEnvelopeEncryption.EncryptString("secret", kek);
        envelope.EncryptedDocument[0] ^= 0xFF;

        Assert.ThrowsAny<CryptographicException>(() =>
            SovereignEnvelopeEncryption.Decrypt(envelope, kek));
    }

    [Fact]
    public void Same_Plaintext_Different_Ciphertext()
    {
        var kek = RandomNumberGenerator.GetBytes(32);
        var e1 = SovereignEnvelopeEncryption.EncryptString("same", kek);
        var e2 = SovereignEnvelopeEncryption.EncryptString("same", kek);

        Assert.NotEqual(e1.EncryptedDocument, e2.EncryptedDocument);
    }

    [Fact]
    public void Kek_Rotation()
    {
        var oldKek = RandomNumberGenerator.GetBytes(32);
        var newKek = RandomNumberGenerator.GetBytes(32);

        var envelope = SovereignEnvelopeEncryption.EncryptString("data", oldKek);
        var rotated = SovereignEnvelopeEncryption.RotateKek(envelope, oldKek, newKek);

        Assert.ThrowsAny<CryptographicException>(() =>
            SovereignEnvelopeEncryption.Decrypt(rotated, oldKek));
        Assert.Equal("data", SovereignEnvelopeEncryption.DecryptString(rotated, newKek));
        Assert.Equal(envelope.EncryptedDocument, rotated.EncryptedDocument);
    }

    [Fact]
    public void Serialization_RoundTrip()
    {
        var kek = RandomNumberGenerator.GetBytes(32);
        var envelope = SovereignEnvelopeEncryption.EncryptString("serialize me", kek);
        var bytes = envelope.ToBytes();
        var restored = EncryptedEnvelope.FromBytes(bytes);

        Assert.Equal("serialize me",
            SovereignEnvelopeEncryption.DecryptString(restored, kek));
    }

    [Fact]
    public void Key_Derivation_Deterministic()
    {
        var salt = SovereignKeyDerivation.GenerateSalt();
        var k1 = SovereignKeyDerivation.DeriveKek("passphrase", salt);
        var k2 = SovereignKeyDerivation.DeriveKek("passphrase", salt);
        Assert.Equal(k1, k2);
    }

    [Fact]
    public void Key_Derivation_Different_Passwords()
    {
        var salt = SovereignKeyDerivation.GenerateSalt();
        var k1 = SovereignKeyDerivation.DeriveKek("one", salt);
        var k2 = SovereignKeyDerivation.DeriveKek("two", salt);
        Assert.NotEqual(k1, k2);
    }

    [Fact]
    public void Full_Pipeline()
    {
        var salt = SovereignKeyDerivation.GenerateSalt();
        var kek = SovereignKeyDerivation.DeriveKek("my-passphrase", salt);

        var diary = "Today I had a breakthrough idea.";
        var envelope = SovereignEnvelopeEncryption.EncryptString(diary, kek);
        var serialized = envelope.ToBytes();

        var kek2 = SovereignKeyDerivation.DeriveKek("my-passphrase", salt);
        var restored = EncryptedEnvelope.FromBytes(serialized);
        Assert.Equal(diary, SovereignEnvelopeEncryption.DecryptString(restored, kek2));
    }
}
