using NetCrypto;

// Per-RID smoke test (PRD FR-22): installed from the freshly packed NetCrypto
// package, runs one BBS sign/verify round-trip and prints IsAvailable.
var bbs = new DefaultBbsCryptoProvider();
Console.WriteLine($"IsAvailable = {bbs.IsAvailable}");
if (!bbs.IsAvailable)
{
    Console.Error.WriteLine("FAIL: BBS native library not available on this RID.");
    return 1;
}

var keyGen = new DefaultKeyGenerator();
var keyPair = keyGen.Generate(KeyType.Bls12381G2);
var messages = new List<byte[]> { "smoke-message-1"u8.ToArray(), "smoke-message-2"u8.ToArray() };
var signature = bbs.Sign(keyPair.PrivateKey, messages);
var ok = bbs.Verify(keyPair.PublicKey, signature, messages);
Console.WriteLine($"BBS sign/verify round-trip = {ok}");
return ok ? 0 : 1;
