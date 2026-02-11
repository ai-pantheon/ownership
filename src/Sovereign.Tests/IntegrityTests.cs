using Sovereign.Integrity;
using Xunit;

namespace Sovereign.Tests;

public class IntegrityTests
{
    private const string Principles = """
        1. Your identity is yours.
        2. Architecture, not policy.
        3. Your AI works for you.
        4. The code is open.
        5. Ownership survives everything.
        """;

    [Fact]
    public void Intact_Principles_Verify()
    {
        var hash = FoundingPrinciplesGuard.ComputeHash(Principles);
        var guard = new FoundingPrinciplesGuard(Principles, hash);
        Assert.True(guard.Verify().Intact);
    }

    [Fact]
    public void Tampered_Principles_Detected()
    {
        var hash = FoundingPrinciplesGuard.ComputeHash(Principles);
        var tampered = Principles.Replace("yours", "ours");
        Assert.False(new FoundingPrinciplesGuard(tampered, hash).Verify().Intact);
    }

    [Fact]
    public void Single_Space_Change_Detected()
    {
        var hash = FoundingPrinciplesGuard.ComputeHash(Principles);
        Assert.False(new FoundingPrinciplesGuard(Principles + " ", hash).Verify().Intact);
    }

    [Fact]
    public void Hash_Is_Deterministic()
    {
        Assert.Equal(
            FoundingPrinciplesGuard.ComputeHash(Principles),
            FoundingPrinciplesGuard.ComputeHash(Principles));
    }
}
