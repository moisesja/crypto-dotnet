using System.Buffers.Binary;
using System.Numerics;

namespace NetCrypto;

/// <summary>
/// Keccak-256 — the <b>original</b> Keccak hash function as submitted to the SHA-3
/// competition and used throughout the Ethereum ecosystem (addresses, transaction and
/// state hashes, Solidity <c>keccak256</c>).
/// </summary>
/// <remarks>
/// <para>
/// <b>Warning:</b> this is <b>not</b> NIST FIPS 202 SHA3-256. Original Keccak applies the
/// multi-rate padding <c>pad10*1</c> directly (first padding byte <c>0x01</c>), whereas
/// SHA3-256 prepends the domain-separation bits <c>01</c> (first padding byte <c>0x06</c>).
/// The two functions therefore produce different digests for every input; for example
/// Keccak-256 of the empty string is
/// <c>c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470</c> while SHA3-256
/// of the empty string is
/// <c>a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a</c>. Use this type
/// only where original Keccak is required (e.g. <c>did:ethr</c> and other Ethereum
/// interoperability); for NIST SHA-3 use a FIPS 202 implementation instead.
/// </para>
/// <para>
/// Parameters: Keccak-f[1600] sponge with rate 1088 bits (136 bytes), capacity 512 bits,
/// 24 rounds, 32-byte digest. The permutation is vendored internally — no external
/// dependency (PRD FR-11).
/// </para>
/// <para>All members are stateless and thread-safe.</para>
/// </remarks>
public static class Keccak256
{
    /// <summary>Sponge rate in bytes: 1088 bits (capacity 512 bits).</summary>
    private const int RateBytes = 136;

    /// <summary>Digest size in bytes.</summary>
    private const int DigestSizeBytes = 32;

    /// <summary>Keccak-f[1600] round constants for the ι step (24 rounds).</summary>
    private static readonly ulong[] RoundConstants =
    [
        0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808aUL, 0x8000000080008000UL,
        0x000000000000808bUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
        0x000000000000008aUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000aUL,
        0x000000008000808bUL, 0x800000000000008bUL, 0x8000000000008089UL, 0x8000000000008003UL,
        0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800aUL, 0x800000008000000aUL,
        0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL,
    ];

    /// <summary>Rotation offsets for the ρ step, indexed by lane position <c>x + 5y</c>.</summary>
    private static readonly int[] RhoOffsets =
    [
         0,  1, 62, 28, 27,
        36, 44,  6, 55, 20,
         3, 10, 43, 25, 39,
        41, 45, 15, 21,  8,
        18,  2, 61, 56, 14,
    ];

    /// <summary>
    /// Computes the Keccak-256 digest of <paramref name="data"/> (original Keccak
    /// <c>0x01</c> padding — Ethereum's hash, <b>not</b> NIST SHA3-256).
    /// </summary>
    /// <param name="data">The input to hash. May be empty.</param>
    /// <returns>The 32-byte Keccak-256 digest.</returns>
    public static byte[] Hash(ReadOnlySpan<byte> data)
    {
        var digest = new byte[DigestSizeBytes];
        ComputeCore(data, digest);
        return digest;
    }

    /// <summary>
    /// Computes the Keccak-256 digest of <paramref name="data"/> (original Keccak
    /// <c>0x01</c> padding — Ethereum's hash, <b>not</b> NIST SHA3-256) into
    /// <paramref name="destination"/>.
    /// </summary>
    /// <param name="data">The input to hash. May be empty.</param>
    /// <param name="destination">The buffer receiving the digest. Must be at least
    /// 32 bytes long; only the first 32 bytes are written.</param>
    /// <param name="bytesWritten">On success, the number of bytes written (always 32);
    /// 0 on failure.</param>
    /// <returns><see langword="true"/> if the digest was written; <see langword="false"/>
    /// if <paramref name="destination"/> is shorter than 32 bytes.</returns>
    public static bool TryHash(ReadOnlySpan<byte> data, Span<byte> destination, out int bytesWritten)
    {
        if (destination.Length < DigestSizeBytes)
        {
            bytesWritten = 0;
            return false;
        }

        ComputeCore(data, destination[..DigestSizeBytes]);
        bytesWritten = DigestSizeBytes;
        return true;
    }

    /// <summary>Runs the full sponge (absorb, pad, squeeze) over <paramref name="data"/>.</summary>
    /// <param name="data">The input to hash.</param>
    /// <param name="digest">Exactly 32 bytes receiving the digest.</param>
    private static void ComputeCore(ReadOnlySpan<byte> data, Span<byte> digest)
    {
        Span<ulong> state = stackalloc ulong[25];
        state.Clear();

        // Absorb all full rate-sized blocks.
        while (data.Length >= RateBytes)
        {
            AbsorbBlock(state, data[..RateBytes]);
            data = data[RateBytes..];
        }

        // Final block with ORIGINAL Keccak multi-rate padding pad10*1: 0x01 at the first
        // free position, 0x80 at the last rate byte (coinciding via OR when the input
        // fills rate − 1 bytes). NOT the SHA-3 domain-separated 0x06 byte (FIPS 202 §B.2).
        Span<byte> block = stackalloc byte[RateBytes];
        block.Clear();
        data.CopyTo(block);
        block[data.Length] = 0x01;
        block[RateBytes - 1] |= 0x80;
        AbsorbBlock(state, block);

        // Squeeze: the 32-byte digest fits in a single rate block — read the first four
        // lanes little-endian; no further permutation needed.
        for (var i = 0; i < DigestSizeBytes / 8; i++)
            BinaryPrimitives.WriteUInt64LittleEndian(digest.Slice(i * 8, 8), state[i]);
    }

    /// <summary>XORs one 136-byte block into the state and applies Keccak-f[1600].</summary>
    /// <param name="state">The 25-lane sponge state.</param>
    /// <param name="block">Exactly 136 bytes to absorb.</param>
    private static void AbsorbBlock(Span<ulong> state, ReadOnlySpan<byte> block)
    {
        for (var i = 0; i < RateBytes / 8; i++)
            state[i] ^= BinaryPrimitives.ReadUInt64LittleEndian(block.Slice(i * 8, 8));

        Permute(state);
    }

    /// <summary>
    /// The Keccak-f[1600] permutation: 24 rounds of θ, ρ, π, χ, ι over the 5×5 lane state
    /// (lane (x, y) at index <c>x + 5y</c>).
    /// </summary>
    /// <param name="a">The 25-lane state, permuted in place.</param>
    private static void Permute(Span<ulong> a)
    {
        Span<ulong> c = stackalloc ulong[5];
        Span<ulong> b = stackalloc ulong[25];

        for (var round = 0; round < 24; round++)
        {
            // θ: XOR each lane with the parities of two neighbouring columns.
            for (var x = 0; x < 5; x++)
                c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];

            for (var x = 0; x < 5; x++)
            {
                var d = c[(x + 4) % 5] ^ BitOperations.RotateLeft(c[(x + 1) % 5], 1);
                for (var y = 0; y < 25; y += 5)
                    a[x + y] ^= d;
            }

            // ρ and π: rotate lane (x, y) by its offset and move it to (y, 2x + 3y).
            for (var x = 0; x < 5; x++)
            {
                for (var y = 0; y < 5; y++)
                    b[y + 5 * ((2 * x + 3 * y) % 5)] = BitOperations.RotateLeft(a[x + 5 * y], RhoOffsets[x + 5 * y]);
            }

            // χ: the only non-linear step — combine each lane with two row neighbours.
            for (var y = 0; y < 25; y += 5)
            {
                for (var x = 0; x < 5; x++)
                    a[x + y] = b[x + y] ^ (~b[(x + 1) % 5 + y] & b[(x + 2) % 5 + y]);
            }

            // ι: break symmetry with the round constant.
            a[0] ^= RoundConstants[round];
        }
    }
}
