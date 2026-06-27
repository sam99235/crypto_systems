#!/usr/bin/env python3
"""
============================================================================
MIYAGUCHI-PRENEEL HASH CONSTRUCTION - EDUCATIONAL DEMO
============================================================================

GOAL
----
Turn a *block cipher* (AES-128 here) into a *cryptographic hash function*.
A block cipher only encrypts one fixed-size block under a key. A hash function
takes an arbitrary-length message and produces a fixed-size "digest". The
Miyaguchi-Preneel (MP) construction is one standard recipe for bridging the
two. It is a "single-block-length" scheme: AES has a 128-bit block, so the
hash output is also 128 bits (16 bytes).

THE CORE IDEA (read this before the code)
-----------------------------------------
We process the message one 16-byte block at a time, keeping a running value
called the "chaining value" H. Think of H as the accumulated hash so far.

For each message block M_i we compute the next chaining value:

        H_i = E( key = H_{i-1} , plaintext = M_i )  XOR  H_{i-1}  XOR  M_i

In words, for every block:
  * KEY to the cipher        = the PREVIOUS chaining value H_{i-1}
  * PLAINTEXT to the cipher  = the current message block M_i
  * The ENCRYPTED output is then XORed with BOTH the plaintext M_i AND the
    key H_{i-1}. This double XOR is the "feed-forward" and it is what makes
    the function one-way (non-invertible) instead of just being reversible
    encryption.

So the answer to your specific questions:

  Q: "what's the key and what's the plaintext?"
  A: KEY       = previous hash / chaining value (H_{i-1})
     PLAINTEXT = the current 16-byte chunk of the message (M_i)

  Q: "how is output used as plaintext?"
  A: It is NOT. A common confusion: the cipher OUTPUT is not fed back in as
     plaintext. The cipher output is XORed into the new chaining value, and
     that new chaining value becomes the next round's KEY. The plaintext is
     always a fresh message block. (Feeding output back as plaintext would be
     a different construction.)

  Q: "how does chaining work for messages that are a multiple of the block
      size?"
  A: We always pad (see below), so even a perfectly-block-aligned message
     gets one extra full block of padding appended. This guarantees the
     padding is unambiguous and that two different messages can never produce
     the same padded byte string. Each padded block updates H in sequence;
     the final H is the digest.

FIRST ROUND
-----------
There is no "previous hash" for the very first block, so we start from a
fixed, public Initialization Vector H_0 (the IV). Using a FIXED IV is correct
and required: a hash must be deterministic, so the same input always gives the
same digest.

AES MODE
--------
We use AES in ECB mode on purpose. We are NOT using ECB to "encrypt data
securely" (ECB is famously bad for that). We are using ECB because we want AES
to behave as a single, raw, keyed permutation on exactly one 16-byte block,
with no chaining, no IV, no extra state of its own. The MP construction
provides all the chaining itself.

SECURITY NOTE
-------------
This is a teaching implementation. For real applications use a vetted hash
such as SHA-256 or SHA-3. MP-AES is studied and sound in principle, but
hand-rolled crypto in production is a bad idea.
============================================================================
"""

from Crypto.Cipher import AES   # pip install pycryptodome

# ---------------------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------------------

BLOCK_SIZE = 16  # AES block size in bytes (128 bits). Also our digest size.

# Fixed, public Initialization Vector H_0. Any fixed 16-byte constant works,
# as long as it is the SAME every time. This is the starting chaining value.
IV = b"\xeb\xe2\x273\xca\x6b\xb5\x74\x32\x17\xe2\xc1\x01\xe1\xa5\xaa"


# ---------------------------------------------------------------------------
# HELPER: XOR two equal-length byte strings
# ---------------------------------------------------------------------------

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    Return the byte-by-byte XOR of two byte strings of equal length.
    XOR is the fundamental mixing operation in the feed-forward step.
    """
    assert len(a) == len(b), "xor_bytes requires equal-length inputs"
    return bytes(x ^ y for x, y in zip(a, b))


# ---------------------------------------------------------------------------
# PADDING (PKCS#7)
# ---------------------------------------------------------------------------

def pad(message: bytes) -> bytes:
    """
    Apply PKCS#7 padding so the message length becomes a multiple of 16.

    HOW IT WORKS:
      We compute how many bytes are missing to reach the next 16-byte
      boundary, call it N (where 1 <= N <= 16). We then append N bytes, each
      with the value N.

    THE MULTIPLE-OF-BLOCK-SIZE CASE (your question):
      If the message is ALREADY a multiple of 16, N is set to a full 16
      (NOT 0). That means we append a WHOLE extra block of sixteen 0x10 bytes.
      This is deliberate. If we appended nothing, the message "ABC...<16 bytes>"
      and that same message with a trailing 0x10*16 already in it would be
      ambiguous to un-pad. Always adding padding keeps it reversible and
      collision-safe at the padding layer.

    Examples:
      len % 16 == 5  ->  append 11 bytes of value 0x0B
      len % 16 == 0  ->  append 16 bytes of value 0x10
      len % 16 == 15 ->  append  1 byte  of value 0x01
    """
    pad_len = BLOCK_SIZE - (len(message) % BLOCK_SIZE)
    # When len % 16 == 0, BLOCK_SIZE - 0 == 16, so we get a full extra block.
    return message + bytes([pad_len]) * pad_len


# ---------------------------------------------------------------------------
# THE COMPRESSION FUNCTION (one block step)
# ---------------------------------------------------------------------------

def mp_compress(h_prev: bytes, m_block: bytes, verbose: bool = False) -> bytes:
    """
    Perform ONE step of the Miyaguchi-Preneel compression function.

        H_i = E_{H_{i-1}}(M_i) XOR H_{i-1} XOR M_i

    Args:
        h_prev   : H_{i-1}, the previous chaining value. Used as the AES KEY.
        m_block  : M_i, the current 16-byte message block. Used as PLAINTEXT.

    Returns:
        H_i, the new 16-byte chaining value.
    """
    # 1) Build an AES cipher KEYED BY the previous chaining value.
    #    ECB so it acts as a pure single-block permutation (see header notes).
    cipher = AES.new(key=h_prev, mode=AES.MODE_ECB)

    # 2) Encrypt the message block. This is E_{H_{i-1}}(M_i).
    encrypted = cipher.encrypt(m_block)

    # 3) Feed-forward: XOR the cipher output with BOTH inputs to the cipher.
    #    First XOR with the plaintext block M_i ...
    step1 = xor_bytes(encrypted, m_block)
    #    ... then XOR with the key / previous chaining value H_{i-1}.
    h_new = xor_bytes(step1, h_prev)

    if verbose:
        print(f"      key (H_prev) : {h_prev.hex()}")
        print(f"      plaintext M_i: {m_block.hex()}")
        print(f"      E(M_i)       : {encrypted.hex()}")
        print(f"      H_new        : {h_new.hex()}")

    return h_new


# ---------------------------------------------------------------------------
# THE FULL HASH FUNCTION
# ---------------------------------------------------------------------------

def mp_hash(message: bytes, verbose: bool = False) -> bytes:
    """
    Compute the Miyaguchi-Preneel hash of an arbitrary-length message.

    Steps:
      1. Pad the message to a multiple of the block size.
      2. Start the chaining value at the fixed IV (H_0).
      3. For each 16-byte block, update the chaining value via mp_compress.
      4. The final chaining value is the digest.
    """
    padded = pad(message)

    if verbose:
        print(f"[*] Original message : {message!r} ({len(message)} bytes)")
        print(f"[*] After padding    : {len(padded)} bytes "
              f"({len(padded)//BLOCK_SIZE} blocks)")
        print(f"[*] IV (H_0)         : {IV.hex()}")

    h = IV  # H_0
    for i in range(0, len(padded), BLOCK_SIZE):
        m_block = padded[i:i + BLOCK_SIZE]
        if verbose:
            print(f"  -- Block {i // BLOCK_SIZE} --")
        h = mp_compress(h, m_block, verbose=verbose)

    return h  # final chaining value = digest


# ---------------------------------------------------------------------------
# VALIDATION / VERIFICATION
# ---------------------------------------------------------------------------

def mp_verify(message: bytes, expected_hex: str) -> bool:
    """
    Verify that a message hashes to an expected digest.

    Because hashing is deterministic, "validation" simply means: recompute
    the hash and compare. We compare case-insensitively on the hex string.

    NOTE on real-world comparison: for security-sensitive checks (e.g. MAC or
    password verification) you should use a constant-time comparison to avoid
    timing side-channels. For this educational demo a plain == is fine, but
    the constant-time version is shown below for completeness.
    """
    actual = mp_hash(message)
    actual_hex = actual.hex()
    expected_hex = expected_hex.strip().lower()

    # Constant-time-ish comparison: XOR all bytes, OR the differences together.
    # Result is 0 only if every byte matched.
    if len(actual_hex) != len(expected_hex):
        return False
    diff = 0
    for x, y in zip(actual.hex().encode(), expected_hex.encode()):
        diff |= x ^ y
    return diff == 0


# ---------------------------------------------------------------------------
# DEMO / CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    print("=" * 70)
    print("MIYAGUCHI-PRENEEL HASH (AES-128) DEMO")
    print("=" * 70)

    # ----- MODE 1: HASH -----
    # Usage:  python miyaguchi_preneel.py hash "your message"
    # ----- MODE 2: VALIDATE -----
    # Usage:  python miyaguchi_preneel.py verify "your message" <expected_hex>

    if len(sys.argv) >= 3 and sys.argv[1] == "hash":
        msg = sys.argv[2].encode()
        digest = mp_hash(msg, verbose=True)
        print(f"\n[RESULT] Digest: {digest.hex()}")

    elif len(sys.argv) >= 4 and sys.argv[1] == "verify":
        msg = sys.argv[2].encode()
        expected = sys.argv[3]
        ok = mp_verify(msg, expected)
        print(f"\n[RESULT] Message : {msg!r}")
        print(f"[RESULT] Expected: {expected.strip().lower()}")
        print(f"[RESULT] Actual  : {mp_hash(msg).hex()}")
        print(f"[RESULT] VALID   : {ok}")

    else:
        # No / bad args: run a self-demonstration so the file is runnable as-is.
        print("\nNo CLI args given - running built-in demonstration.\n")

        # (a) Hash a short message (smaller than one block -> 1 padded block).
        print(">>> Example A: short message (one block after padding)")
        d1 = mp_hash(b"hello mom", verbose=True)
        print(f"\nDigest A: {d1.hex()}\n")

        # (b) Hash an exact-multiple-of-16 message to show the extra pad block.
        print(">>> Example B: message exactly 16 bytes (forces an extra block)")
        exact = b"0123456789ABCDEF"  # exactly 16 bytes
        d2 = mp_hash(exact, verbose=True)
        print(f"\nDigest B: {d2.hex()}\n")

        # (c) Determinism: same input -> same digest.
        print(">>> Example C: determinism check")
        print("same input twice equal? ",
              mp_hash(b"repeat me") == mp_hash(b"repeat me"))

        # (d) Avalanche: a 1-byte change gives a totally different digest.
        print("\n>>> Example D: avalanche effect (flip one character)")
        print("  hash('test1') =", mp_hash(b"test1").hex())
        print("  hash('test2') =", mp_hash(b"test2").hex())

        # (e) Validation round-trip.
        print("\n>>> Example E: validation")
        good = mp_hash(b"hello mom").hex()
        print("  verify correct digest :", mp_verify(b"hello mom", good))
        print("  verify wrong digest   :", mp_verify(b"hello mom", "00" * 16))

    print("\n" + "=" * 70)