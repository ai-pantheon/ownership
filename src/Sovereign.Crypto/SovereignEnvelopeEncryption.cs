using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Sovereign.Crypto;

/// <summary>
/// AES-256-GCM envelope encryption.
///
/// How it works:
/// 1. Each document gets a unique random Data Encryption Key (DEK)
/// 2. The document is encrypted with the DEK using AES-256-GCM
/// 3. The DEK is encrypted with the user's Key Encryption Key (KEK)
/// 4. Only the encrypted DEK + encrypted document + nonces are stored
/// 5. The KEK never leaves the user's device
///
/// Why envelope encryption:
/// - Rotating the KEK doesn't require re-encrypting all documents
/// - Each document has a unique key, limiting blast radius of any single key compromise
/// - The KEK can be derived from credentials (see SovereignKeyDerivation)
/// </summary>
public static class SovereignEnvelopeEncryption
{
    /// <summary>AES-256-GCM nonce size in bytes (96-bit, per NIST recommendation).</summary>
    private const int NonceSizeBytes = 12;

    /// <summary>AES-256-GCM authentication tag size in bytes (128-bit).</summary>
    private const int TagSizeBytes = 16;

    /// <summary>DEK size in bytes (256-bit).</summary>
    private const int DekSizeBytes = 32;

    /// <summary>
    /// Encrypt a document using envelope encryption.
    /// Returns an EncryptedEnvelope containing everything needed to decrypt (except the KEK).
    /// </summary>
    /// <param name="plaintext">The document content to encrypt.</param>
    /// <param name="kek">The user's Key Encryption Key (256-bit). Never stored on server.</param>
    /// <param name="associatedData">Optional authenticated data (e.g., document ID). Not encrypted but tamper-protected.</param>
    public static EncryptedEnvelope Encrypt(byte[] plaintext, byte[] kek, byte[]? associatedData = null)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        ValidateKek(kek);

        // 1. Generate a random DEK for this document
        var dek = RandomNumberGenerator.GetBytes(DekSizeBytes);

        try
        {
            // 2. Encrypt the document with the DEK
            var documentNonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);
            var ciphertext = new byte[plaintext.Length];
            var documentTag = new byte[TagSizeBytes];

            using (var aesDocument = new AesGcm(dek, TagSizeBytes))
            {
                aesDocument.Encrypt(documentNonce, plaintext, ciphertext, documentTag, associatedData);
            }

            // 3. Encrypt the DEK with the KEK
            var dekNonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);
            var encryptedDek = new byte[DekSizeBytes];
            var dekTag = new byte[TagSizeBytes];

            using (var aesKek = new AesGcm(kek, TagSizeBytes))
            {
                aesKek.Encrypt(dekNonce, dek, encryptedDek, dekTag);
            }

            return new EncryptedEnvelope
            {
                EncryptedDocument = ciphertext,
                DocumentNonce = documentNonce,
                DocumentTag = documentTag,
                EncryptedDek = encryptedDek,
                DekNonce = dekNonce,
                DekTag = dekTag,
                AssociatedData = associatedData,
            };
        }
        finally
        {
            // Zero out the DEK from memory
            CryptographicOperations.ZeroMemory(dek);
        }
    }

    /// <summary>
    /// Encrypt a string document. Convenience wrapper over Encrypt(byte[], ...).
    /// </summary>
    public static EncryptedEnvelope EncryptString(string plaintext, byte[] kek, byte[]? associatedData = null)
    {
        return Encrypt(Encoding.UTF8.GetBytes(plaintext), kek, associatedData);
    }

    /// <summary>
    /// Decrypt an envelope using the user's KEK.
    /// </summary>
    /// <param name="envelope">The encrypted envelope from Encrypt().</param>
    /// <param name="kek">The user's Key Encryption Key (256-bit).</param>
    /// <returns>The decrypted document plaintext.</returns>
    /// <exception cref="CryptographicException">If the KEK is wrong or data has been tampered with.</exception>
    public static byte[] Decrypt(EncryptedEnvelope envelope, byte[] kek)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        ValidateKek(kek);

        // 1. Decrypt the DEK using the KEK
        var dek = new byte[DekSizeBytes];

        try
        {
            using (var aesKek = new AesGcm(kek, TagSizeBytes))
            {
                aesKek.Decrypt(envelope.DekNonce, envelope.EncryptedDek, envelope.DekTag, dek);
            }

            // 2. Decrypt the document using the DEK
            var plaintext = new byte[envelope.EncryptedDocument.Length];

            using (var aesDocument = new AesGcm(dek, TagSizeBytes))
            {
                aesDocument.Decrypt(
                    envelope.DocumentNonce,
                    envelope.EncryptedDocument,
                    envelope.DocumentTag,
                    plaintext,
                    envelope.AssociatedData);
            }

            return plaintext;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }
    }

    /// <summary>
    /// Decrypt an envelope and return as string.
    /// </summary>
    public static string DecryptString(EncryptedEnvelope envelope, byte[] kek)
    {
        return Encoding.UTF8.GetString(Decrypt(envelope, kek));
    }

    /// <summary>
    /// Re-encrypt a document's DEK with a new KEK (key rotation).
    /// The document itself is NOT re-encrypted — only the DEK wrapper changes.
    /// This is the advantage of envelope encryption.
    /// </summary>
    public static EncryptedEnvelope RotateKek(EncryptedEnvelope envelope, byte[] oldKek, byte[] newKek)
    {
        ValidateKek(oldKek);
        ValidateKek(newKek);

        // Decrypt the DEK with the old KEK
        var dek = new byte[DekSizeBytes];

        try
        {
            using (var aesOld = new AesGcm(oldKek, TagSizeBytes))
            {
                aesOld.Decrypt(envelope.DekNonce, envelope.EncryptedDek, envelope.DekTag, dek);
            }

            // Re-encrypt the DEK with the new KEK
            var newDekNonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);
            var newEncryptedDek = new byte[DekSizeBytes];
            var newDekTag = new byte[TagSizeBytes];

            using (var aesNew = new AesGcm(newKek, TagSizeBytes))
            {
                aesNew.Encrypt(newDekNonce, dek, newEncryptedDek, newDekTag);
            }

            return new EncryptedEnvelope
            {
                EncryptedDocument = envelope.EncryptedDocument,
                DocumentNonce = envelope.DocumentNonce,
                DocumentTag = envelope.DocumentTag,
                EncryptedDek = newEncryptedDek,
                DekNonce = newDekNonce,
                DekTag = newDekTag,
                AssociatedData = envelope.AssociatedData,
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }
    }

    private static void ValidateKek(byte[] kek)
    {
        ArgumentNullException.ThrowIfNull(kek);
        if (kek.Length != DekSizeBytes)
            throw new ArgumentException($"KEK must be exactly {DekSizeBytes} bytes (256-bit).", nameof(kek));
    }
}

/// <summary>
/// The output of envelope encryption. Contains everything needed to decrypt
/// the document — except the user's KEK, which never leaves their device.
///
/// All fields are safe to store on the server. Without the KEK, they are useless.
/// </summary>
public class EncryptedEnvelope
{
    /// <summary>The encrypted document content.</summary>
    public byte[] EncryptedDocument { get; init; } = Array.Empty<byte>();

    /// <summary>Nonce used to encrypt the document (unique per document).</summary>
    public byte[] DocumentNonce { get; init; } = Array.Empty<byte>();

    /// <summary>GCM authentication tag for the document (tamper detection).</summary>
    public byte[] DocumentTag { get; init; } = Array.Empty<byte>();

    /// <summary>The document's DEK, encrypted with the user's KEK.</summary>
    public byte[] EncryptedDek { get; init; } = Array.Empty<byte>();

    /// <summary>Nonce used to encrypt the DEK.</summary>
    public byte[] DekNonce { get; init; } = Array.Empty<byte>();

    /// <summary>GCM authentication tag for the DEK encryption.</summary>
    public byte[] DekTag { get; init; } = Array.Empty<byte>();

    /// <summary>Optional associated data that was authenticated but not encrypted.</summary>
    public byte[]? AssociatedData { get; init; }

    /// <summary>
    /// Serialize the envelope to a portable byte array for storage/transmission.
    /// Format: [DocNonce(12)][DocTag(16)][DekNonce(12)][DekTag(16)][EncDek(32)][EncDoc(N)]
    /// Total overhead: 88 bytes + document length.
    /// </summary>
    public byte[] ToBytes()
    {
        var result = new byte[12 + 16 + 12 + 16 + 32 + EncryptedDocument.Length];
        var offset = 0;

        Buffer.BlockCopy(DocumentNonce, 0, result, offset, 12); offset += 12;
        Buffer.BlockCopy(DocumentTag, 0, result, offset, 16); offset += 16;
        Buffer.BlockCopy(DekNonce, 0, result, offset, 12); offset += 12;
        Buffer.BlockCopy(DekTag, 0, result, offset, 16); offset += 16;
        Buffer.BlockCopy(EncryptedDek, 0, result, offset, 32); offset += 32;
        Buffer.BlockCopy(EncryptedDocument, 0, result, offset, EncryptedDocument.Length);

        return result;
    }

    /// <summary>
    /// Deserialize an envelope from the portable byte array format.
    /// </summary>
    public static EncryptedEnvelope FromBytes(byte[] data)
    {
        if (data.Length < 88)
            throw new ArgumentException("Data too short to contain a valid envelope.");

        var offset = 0;
        var docNonce = new byte[12]; Buffer.BlockCopy(data, offset, docNonce, 0, 12); offset += 12;
        var docTag = new byte[16]; Buffer.BlockCopy(data, offset, docTag, 0, 16); offset += 16;
        var dekNonce = new byte[12]; Buffer.BlockCopy(data, offset, dekNonce, 0, 12); offset += 12;
        var dekTag = new byte[16]; Buffer.BlockCopy(data, offset, dekTag, 0, 16); offset += 16;
        var encDek = new byte[32]; Buffer.BlockCopy(data, offset, encDek, 0, 32); offset += 32;
        var encDoc = new byte[data.Length - 88]; Buffer.BlockCopy(data, offset, encDoc, 0, encDoc.Length);

        return new EncryptedEnvelope
        {
            DocumentNonce = docNonce,
            DocumentTag = docTag,
            DekNonce = dekNonce,
            DekTag = dekTag,
            EncryptedDek = encDek,
            EncryptedDocument = encDoc,
        };
    }
}
