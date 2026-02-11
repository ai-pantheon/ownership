using System.Security.Cryptography;
using Sovereign.Crypto;
using Sovereign.Verify;
using Xunit;

namespace Sovereign.Tests;

public class MerkleTreeTests
{
    [Fact]
    public void Single_Document()
    {
        var tree = new MerkleTree(new[] { "doc"u8.ToArray() });
        Assert.Equal(1, tree.Count);
        Assert.Equal(32, tree.RootHash.Length);
    }

    [Fact]
    public void Different_Docs_Different_Roots()
    {
        var t1 = new MerkleTree(new[] { "a"u8.ToArray() });
        var t2 = new MerkleTree(new[] { "b"u8.ToArray() });
        Assert.NotEqual(t1.RootHash, t2.RootHash);
    }

    [Fact]
    public void Same_Docs_Same_Root()
    {
        var docs = new[] { "one"u8.ToArray(), "two"u8.ToArray() };
        Assert.Equal(
            new MerkleTree(docs).RootHash,
            new MerkleTree(docs).RootHash);
    }

    [Fact]
    public void Inclusion_Proof_Verifies()
    {
        var docs = new[] { "a"u8.ToArray(), "b"u8.ToArray(), "c"u8.ToArray(), "d"u8.ToArray() };
        var tree = new MerkleTree(docs);

        for (int i = 0; i < docs.Length; i++)
        {
            var proof = tree.GenerateProof(i);
            Assert.True(MerkleTree.VerifyProof(docs[i], proof, tree.RootHash));
        }
    }

    [Fact]
    public void Fake_Document_Fails_Proof()
    {
        var docs = new[] { "real"u8.ToArray(), "another"u8.ToArray() };
        var tree = new MerkleTree(docs);
        var proof = tree.GenerateProof(0);
        Assert.False(MerkleTree.VerifyProof("fake"u8.ToArray(), proof, tree.RootHash));
    }

    [Fact]
    public void Wrong_Root_Fails()
    {
        var tree = new MerkleTree(new[] { "doc"u8.ToArray() });
        var proof = tree.GenerateProof(0);
        var fakeRoot = SHA256.HashData("fake"u8.ToArray());
        Assert.False(MerkleTree.VerifyProof("doc"u8.ToArray(), proof, fakeRoot));
    }

    [Fact]
    public void Non_Power_Of_Two()
    {
        var docs = new[] { "one"u8.ToArray(), "two"u8.ToArray(), "three"u8.ToArray() };
        var tree = new MerkleTree(docs);
        for (int i = 0; i < 3; i++)
        {
            var proof = tree.GenerateProof(i);
            Assert.True(MerkleTree.VerifyProof(docs[i], proof, tree.RootHash));
        }
    }

    [Fact]
    public void Large_Tree()
    {
        var docs = Enumerable.Range(0, 100)
            .Select(_ => RandomNumberGenerator.GetBytes(64)).ToArray();
        var tree = new MerkleTree(docs);

        foreach (var i in new[] { 0, 49, 99 })
        {
            var proof = tree.GenerateProof(i);
            Assert.True(MerkleTree.VerifyProof(docs[i], proof, tree.RootHash));
        }
    }

    [Fact]
    public void Works_With_Encrypted_Data()
    {
        var kek = RandomNumberGenerator.GetBytes(32);
        var envelopes = new[] { "secret one", "secret two", "secret three" }
            .Select(m => SovereignEnvelopeEncryption.EncryptString(m, kek).ToBytes())
            .ToArray();

        var tree = new MerkleTree(envelopes);
        var proof = tree.GenerateProof(1);
        Assert.True(MerkleTree.VerifyProof(envelopes[1], proof, tree.RootHash));
    }
}
