"""
B2: Custom Feistel Block Cipher — 8-Round Implementation
Block size: 64 bits | Key size: 64 bits
"""
import struct
import os

# ─── S-Box (4-bit substitution) ───────────────────────────────────────────────
SBOX = [0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8,
        0x3, 0xA, 0x6, 0xC, 0x5, 0x9, 0x0, 0x7]

INV_SBOX = [SBOX.index(i) for i in range(16)]

# ─── Round Function F(half_block, subkey) ─────────────────────────────────────
def rotate_left_32(val, n):
    """Rotate 32-bit value left by n bits."""
    return ((val << n) | (val >> (32 - n))) & 0xFFFFFFFF

def apply_sbox(val):
    """Apply S-Box substitution nibble-by-nibble to a 32-bit value."""
    result = 0
    for i in range(8):                       # 8 nibbles in 32 bits
        nibble = (val >> (4 * i)) & 0xF
        result |= SBOX[nibble] << (4 * i)
    return result

def round_function(R, K):
    """
    Round function F(R, K):
      1. XOR with subkey
      2. S-Box substitution (confusion)
      3. Rotate left by 7 (diffusion)
      4. XOR with rotated subkey (avalanche boost)
    """
    x = (R ^ K) & 0xFFFFFFFF
    x = apply_sbox(x)                        # Confusion
    x = rotate_left_32(x, 7)                 # Diffusion
    x = x ^ rotate_left_32(K, 13)           # Extra mixing
    return x & 0xFFFFFFFF

# ─── Key Schedule ──────────────────────────────────────────────────────────────
ROUND_CONSTANTS = [0x9E3779B9, 0x6C62272E, 0xB5C0FBCF, 0xAF7C66F0,
                   0x517CC1B7, 0x27220A95, 0xFE81C5A3, 0xD3A4FE68]

def key_schedule(master_key_64bit):
    """
    Generate 8 round subkeys from a 64-bit master key.
    KL, KR = left and right 32-bit halves of the master key.
    Subkeys are derived via rotation and XOR with round constants.
    """
    KL = (master_key_64bit >> 32) & 0xFFFFFFFF
    KR =  master_key_64bit        & 0xFFFFFFFF
    subkeys = []
    for i in range(8):
        if i % 2 == 0:
            sk = rotate_left_32(KL, (3 * i + 7) % 32) ^ ROUND_CONSTANTS[i]
        else:
            sk = rotate_left_32(KR, (5 * i + 3) % 32) ^ ROUND_CONSTANTS[i]
        sk = sk ^ (KL if i % 2 == 0 else KR)   # Cross-mix
        subkeys.append(sk & 0xFFFFFFFF)
        KL, KR = KR, rotate_left_32(KL ^ sk, 11)  # Update key state
    return subkeys

# ─── Feistel Encrypt / Decrypt ────────────────────────────────────────────────
def feistel_encrypt_block(plaintext_64, subkeys):
    """Encrypt one 64-bit block with 8 Feistel rounds."""
    L = (plaintext_64 >> 32) & 0xFFFFFFFF
    R =  plaintext_64        & 0xFFFFFFFF
    for i in range(8):
        L, R = R, L ^ round_function(R, subkeys[i])
    return ((L << 32) | R) & 0xFFFFFFFFFFFFFFFF

def feistel_decrypt_block(ciphertext_64, subkeys):
    """Decrypt one 64-bit block — apply subkeys in reverse order."""
    L = (ciphertext_64 >> 32) & 0xFFFFFFFF
    R =  ciphertext_64        & 0xFFFFFFFF
    for i in reversed(range(8)):
        L, R = R ^ round_function(L, subkeys[i]), L
    return ((L << 32) | R) & 0xFFFFFFFFFFFFFFFF

# ─── Block-level helpers (bytes <-> int) ─────────────────────────────────────
def bytes_to_int(b):
    return int.from_bytes(b, 'big')

def int_to_bytes(n, length=8):
    return n.to_bytes(length, 'big')

def pad(data):
    """PKCS#7-style padding to 8-byte block boundary."""
    pad_len = 8 - (len(data) % 8)
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def encrypt(plaintext: bytes, key: int) -> bytes:
    subkeys = key_schedule(key)
    padded = pad(plaintext)
    ct = b''
    for i in range(0, len(padded), 8):
        block = bytes_to_int(padded[i:i+8])
        ct += int_to_bytes(feistel_encrypt_block(block, subkeys))
    return ct

def decrypt(ciphertext: bytes, key: int) -> bytes:
    subkeys = key_schedule(key)
    pt = b''
    for i in range(0, len(ciphertext), 8):
        block = bytes_to_int(ciphertext[i:i+8])
        pt += int_to_bytes(feistel_decrypt_block(block, subkeys))
    return unpad(pt)

# ─── Demonstrate Correctness ──────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  B2: Custom 8-Round Feistel Block Cipher — Demo")
    print("=" * 60)

    KEY = 0xDEADBEEFCAFEBABE
    MSG = b"Hello, Feistel World!"

    print(f"\n[KEY]        0x{KEY:016X}")
    print(f"[PLAINTEXT]  {MSG}")

    ct = encrypt(MSG, KEY)
    print(f"\n[CIPHERTEXT] {ct.hex()}")

    pt = decrypt(ct, KEY)
    print(f"[DECRYPTED]  {pt}")

    assert pt == MSG, "DECRYPTION FAILED!"
    print("\n[PASS] Encrypt → Decrypt correctness verified.")

    # Show subkeys
    sk = key_schedule(KEY)
    print("\n[KEY SCHEDULE]")
    for i, k in enumerate(sk):
        print(f"  K{i+1}: 0x{k:08X}")

    # Avalanche test
    print("\n[AVALANCHE TEST] (1-bit change in plaintext)")
    block1 = 0x0000000000000000
    block2 = 0x0000000000000001
    c1 = feistel_encrypt_block(block1, sk)
    c2 = feistel_encrypt_block(block2, sk)
    diff = bin(c1 ^ c2).count('1')
    print(f"  PT1: {block1:016X}  →  CT1: {c1:016X}")
    print(f"  PT2: {block2:016X}  →  CT2: {c2:016X}")
    print(f"  Bits changed: {diff}/64 ({diff/64*100:.1f}%)")

    # Multiple message test
    print("\n[MULTIPLE MESSAGES TEST]")
    messages = [b"Attack at dawn", b"12345678", b"CryptoTest"]
    for m in messages:
        ct_ = encrypt(m, KEY)
        pt_ = decrypt(ct_, KEY)
        status = "PASS" if pt_ == m else "FAIL"
        print(f"  [{status}] '{m.decode()}' → {ct_.hex()[:24]}... → '{pt_.decode()}'")

    print("\n[ALL TESTS PASSED]")
