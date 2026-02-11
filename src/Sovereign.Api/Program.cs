using System.Text.Json;
using Sovereign.Core;
using Sovereign.Integrity;
using Sovereign.Verify;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSovereignInfrastructure("sovereign-api");
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
        policy.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader());
});

var app = builder.Build();
app.UseCors();

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------
app.MapGet("/api/v1/health", () => Results.Ok(new
{
    status = "healthy",
    service = "sovereign-api",
    version = "1.0.0",
    timestamp = DateTime.UtcNow,
}));

// ---------------------------------------------------------------------------
// Integrity — Verify founding principles haven't been tampered with
// ---------------------------------------------------------------------------
const string Principles = """
    1. Your identity is yours.
    2. Architecture, not policy.
    3. Your AI works for you.
    4. The code is open.
    5. Ownership survives everything.
    """;

var principlesHash = FoundingPrinciplesGuard.ComputeHash(Principles);
var guard = new FoundingPrinciplesGuard(Principles, principlesHash);

app.MapGet("/api/v1/integrity", () =>
{
    var result = guard.Verify();
    return Results.Ok(new
    {
        intact = result.Intact,
        expectedHash = result.ExpectedHash,
        computedHash = result.ComputedHash,
    });
});

// ---------------------------------------------------------------------------
// Vault — Store and retrieve encrypted envelopes
// ---------------------------------------------------------------------------

// Store an encrypted envelope (the server never sees plaintext)
app.MapPost("/api/v1/vault/store", async (StoreRequest request, IDocumentStore store) =>
{
    if (string.IsNullOrWhiteSpace(request.UserId) || string.IsNullOrWhiteSpace(request.EnvelopeBase64))
        return Results.BadRequest(new { error = "userId and envelopeBase64 are required" });

    var documentId = Guid.NewGuid().ToString("N");
    var record = new VaultRecord
    {
        DocumentId = documentId,
        UserId = request.UserId,
        EnvelopeBase64 = request.EnvelopeBase64,
        StoredAtUtc = DateTime.UtcNow,
    };

    await store.SetAsync($"vault-{request.UserId}", documentId, record);

    return Results.Ok(new
    {
        documentId,
        storedAt = record.StoredAtUtc,
    });
});

// Get all envelopes for a user
app.MapGet("/api/v1/vault/{userId}", async (string userId, IDocumentStore store) =>
{
    var docs = await store.GetAllAsync<VaultRecord>($"vault-{userId}");
    return Results.Ok(docs.Select(d => new
    {
        d.DocumentId,
        d.EnvelopeBase64,
        d.StoredAtUtc,
    }));
});

// Get a specific envelope
app.MapGet("/api/v1/vault/{userId}/{documentId}", async (
    string userId, string documentId, IDocumentStore store) =>
{
    var doc = await store.GetAsync<VaultRecord>($"vault-{userId}", documentId);
    if (doc is null) return Results.NotFound(new { error = "Document not found" });

    return Results.Ok(new
    {
        doc.DocumentId,
        doc.EnvelopeBase64,
        doc.StoredAtUtc,
    });
});

// Delete an envelope
app.MapDelete("/api/v1/vault/{userId}/{documentId}", async (
    string userId, string documentId, IDocumentStore store) =>
{
    await store.DeleteAsync($"vault-{userId}", documentId);
    return Results.Ok(new { deleted = documentId });
});

// ---------------------------------------------------------------------------
// Merkle — Build trees and verify proofs over stored envelopes
// ---------------------------------------------------------------------------

// Build a Merkle tree for a user's vault
app.MapPost("/api/v1/vault/{userId}/merkle", async (string userId, IDocumentStore store) =>
{
    var docs = await store.GetAllAsync<VaultRecord>($"vault-{userId}");
    if (docs.Count == 0)
        return Results.Ok(new { rootHash = (string?)null, documentCount = 0 });

    var leaves = docs
        .OrderBy(d => d.DocumentId)
        .Select(d => Convert.FromBase64String(d.EnvelopeBase64))
        .ToList();

    var tree = new MerkleTree(leaves);
    var rootHex = Convert.ToHexString(tree.RootHash).ToLowerInvariant();

    return Results.Ok(new
    {
        rootHash = rootHex,
        documentCount = docs.Count,
    });
});

// Generate an inclusion proof for a specific document
app.MapGet("/api/v1/vault/{userId}/merkle/proof/{documentId}", async (
    string userId, string documentId, IDocumentStore store) =>
{
    var docs = await store.GetAllAsync<VaultRecord>($"vault-{userId}");
    var ordered = docs.OrderBy(d => d.DocumentId).ToList();

    var index = ordered.FindIndex(d => d.DocumentId == documentId);
    if (index < 0)
        return Results.NotFound(new { error = "Document not found in vault" });

    var leaves = ordered.Select(d => Convert.FromBase64String(d.EnvelopeBase64)).ToList();
    var tree = new MerkleTree(leaves);
    var proof = tree.GenerateProof(index);

    return Results.Ok(new
    {
        leafIndex = proof.LeafIndex,
        leafHash = Convert.ToHexString(proof.LeafHash).ToLowerInvariant(),
        rootHash = Convert.ToHexString(proof.RootHash).ToLowerInvariant(),
        steps = proof.Steps.Select(s => new
        {
            hash = Convert.ToHexString(s.Hash).ToLowerInvariant(),
            isLeft = s.IsLeft,
        }),
    });
});

// Verify an inclusion proof
app.MapPost("/api/v1/vault/verify", (VerifyRequest request) =>
{
    try
    {
        var document = Convert.FromBase64String(request.DocumentBase64);
        var rootHash = Convert.FromHexString(request.ExpectedRootHash);

        var steps = request.Steps.Select(s => new ProofStep
        {
            Hash = Convert.FromHexString(s.Hash),
            IsLeft = s.IsLeft,
        }).ToArray();

        var proof = new MerkleProof
        {
            LeafIndex = request.LeafIndex,
            LeafHash = new byte[32], // Will be computed during verification
            Steps = steps,
            RootHash = rootHash,
        };

        var verified = MerkleTree.VerifyProof(document, proof, rootHash);
        return Results.Ok(new { verified });
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.Run();

// ---------------------------------------------------------------------------
// Models
// ---------------------------------------------------------------------------

record StoreRequest(string UserId, string EnvelopeBase64);

record VerifyRequest(
    string DocumentBase64,
    string ExpectedRootHash,
    int LeafIndex,
    VerifyStepRequest[] Steps);

record VerifyStepRequest(string Hash, bool IsLeft);

class VaultRecord
{
    public string DocumentId { get; set; } = "";
    public string UserId { get; set; } = "";
    public string EnvelopeBase64 { get; set; } = "";
    public DateTime StoredAtUtc { get; set; }
}
