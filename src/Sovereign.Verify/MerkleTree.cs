using System.Security.Cryptography;

namespace Sovereign.Verify;

/// <summary>
/// SHA-256 Merkle tree for tamper detection.
///
/// How it works:
/// 1. Each document (encrypted) gets hashed individually (leaf node)
/// 2. Adjacent hashes are concatenated and hashed together (internal node)
/// 3. This continues until a single root hash remains
/// 4. The user stores the root hash independently (on their device, on paper, anywhere)
/// 5. If ANY document changes, the root hash changes — tamper detected
/// 6. Inclusion proofs let you verify a single document belongs to the tree
///    without revealing any other documents
///
/// The tree operates on encrypted data. No decryption needed for verification.
/// The platform cannot forge a valid tree without detection.
/// </summary>
public class MerkleTree
{
    private readonly byte[][] _leaves;
    private readonly byte[][] _nodes;
    private readonly int _leafCount;

    /// <summary>The root hash of the tree. Store this independently to detect tampering.</summary>
    public byte[] RootHash => _nodes.Length > 0 ? _nodes[0] : SHA256.HashData(Array.Empty<byte>());

    /// <summary>Number of documents in the tree.</summary>
    public int Count => _leafCount;

    /// <summary>
    /// Build a Merkle tree from document data (typically encrypted ciphertext).
    /// </summary>
    /// <param name="documents">The documents to include. Order matters.</param>
    public MerkleTree(IReadOnlyList<byte[]> documents)
    {
        ArgumentNullException.ThrowIfNull(documents);

        if (documents.Count == 0)
        {
            _leaves = Array.Empty<byte[]>();
            _nodes = Array.Empty<byte[]>();
            _leafCount = 0;
            return;
        }

        _leafCount = documents.Count;

        // Compute leaf hashes
        _leaves = new byte[_leafCount][];
        for (var i = 0; i < _leafCount; i++)
        {
            // Prefix with 0x00 to distinguish leaf nodes from internal nodes
            _leaves[i] = HashLeaf(documents[i]);
        }

        // Build tree bottom-up
        // We need the next power of 2 for a complete binary tree
        var treeSize = NextPowerOfTwo(_leafCount);
        var totalNodes = 2 * treeSize - 1;
        _nodes = new byte[totalNodes][];

        // Place leaves at the bottom of the tree
        var leafStart = treeSize - 1;
        for (var i = 0; i < treeSize; i++)
        {
            _nodes[leafStart + i] = i < _leafCount
                ? _leaves[i]
                : SHA256.HashData(Array.Empty<byte>()); // Empty node padding
        }

        // Build internal nodes bottom-up
        for (var i = leafStart - 1; i >= 0; i--)
        {
            var left = _nodes[2 * i + 1];
            var right = _nodes[2 * i + 2];
            _nodes[i] = HashInternal(left, right);
        }
    }

    /// <summary>
    /// Generate an inclusion proof for a document at the given index.
    /// The proof allows anyone with the root hash to verify this document
    /// is part of the tree — without seeing any other documents.
    /// </summary>
    /// <param name="index">Document index (0-based, in the order they were added).</param>
    /// <returns>A proof containing sibling hashes from leaf to root.</returns>
    public MerkleProof GenerateProof(int index)
    {
        if (index < 0 || index >= _leafCount)
            throw new ArgumentOutOfRangeException(nameof(index));

        var treeSize = NextPowerOfTwo(_leafCount);
        var proofSteps = new List<ProofStep>();

        // Start at the leaf position in the tree array
        var nodeIndex = treeSize - 1 + index;

        while (nodeIndex > 0)
        {
            // Find sibling
            var siblingIndex = (nodeIndex % 2 == 1) ? nodeIndex + 1 : nodeIndex - 1;
            var isLeft = nodeIndex % 2 == 0; // Is the current node the right child?

            proofSteps.Add(new ProofStep
            {
                Hash = _nodes[siblingIndex],
                IsLeft = isLeft, // Sibling is on the left when current is the right child
            });

            // Move to parent
            nodeIndex = (nodeIndex - 1) / 2;
        }

        return new MerkleProof
        {
            LeafIndex = index,
            LeafHash = _leaves[index],
            Steps = proofSteps.ToArray(),
            RootHash = RootHash,
        };
    }

    /// <summary>
    /// Verify an inclusion proof against a known root hash.
    /// This is the user-side verification — run this on your device with
    /// your independently stored root hash.
    /// </summary>
    /// <param name="document">The document to verify.</param>
    /// <param name="proof">The inclusion proof from GenerateProof().</param>
    /// <param name="expectedRootHash">Your independently stored root hash.</param>
    /// <returns>True if the document is verified to be in the tree with no tampering.</returns>
    public static bool VerifyProof(byte[] document, MerkleProof proof, byte[] expectedRootHash)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(proof);
        ArgumentNullException.ThrowIfNull(expectedRootHash);

        // Hash the document as a leaf
        var currentHash = HashLeaf(document);

        // Verify the leaf hash matches
        if (!CryptographicOperations.FixedTimeEquals(currentHash, proof.LeafHash))
            return false;

        // Walk up the tree using the proof steps
        foreach (var step in proof.Steps)
        {
            currentHash = step.IsLeft
                ? HashInternal(step.Hash, currentHash)
                : HashInternal(currentHash, step.Hash);
        }

        // Compare with the expected root hash (constant-time to prevent timing attacks)
        return CryptographicOperations.FixedTimeEquals(currentHash, expectedRootHash);
    }

    /// <summary>Hash a leaf node. Prefixed with 0x00 to prevent second preimage attacks.</summary>
    private static byte[] HashLeaf(byte[] data)
    {
        var prefixed = new byte[1 + data.Length];
        prefixed[0] = 0x00;
        Buffer.BlockCopy(data, 0, prefixed, 1, data.Length);
        return SHA256.HashData(prefixed);
    }

    /// <summary>Hash an internal node. Prefixed with 0x01 to prevent second preimage attacks.</summary>
    private static byte[] HashInternal(byte[] left, byte[] right)
    {
        var combined = new byte[1 + left.Length + right.Length];
        combined[0] = 0x01;
        Buffer.BlockCopy(left, 0, combined, 1, left.Length);
        Buffer.BlockCopy(right, 0, combined, 1 + left.Length, right.Length);
        return SHA256.HashData(combined);
    }

    private static int NextPowerOfTwo(int n)
    {
        var power = 1;
        while (power < n) power <<= 1;
        return power;
    }
}

/// <summary>
/// An inclusion proof for a single document in a Merkle tree.
/// Contains the sibling hashes needed to recompute the root.
/// </summary>
public class MerkleProof
{
    /// <summary>Index of the document in the tree.</summary>
    public int LeafIndex { get; init; }

    /// <summary>Hash of the leaf (the document).</summary>
    public byte[] LeafHash { get; init; } = Array.Empty<byte>();

    /// <summary>Sibling hashes from leaf to root.</summary>
    public ProofStep[] Steps { get; init; } = Array.Empty<ProofStep>();

    /// <summary>The root hash at the time the proof was generated.</summary>
    public byte[] RootHash { get; init; } = Array.Empty<byte>();
}

/// <summary>
/// A single step in a Merkle inclusion proof.
/// </summary>
public class ProofStep
{
    /// <summary>The sibling hash at this level of the tree.</summary>
    public byte[] Hash { get; init; } = Array.Empty<byte>();

    /// <summary>Whether this sibling is on the left (true) or right (false).</summary>
    public bool IsLeft { get; init; }
}
