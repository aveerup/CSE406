import os
import time

from aes_helpers import Sbox, InvSbox, Rcon, Mixer, InvMixer, gf_mult


BLOCK_SIZE = 16
AES_128_ROUNDS = 10


def normalize_key(key):
    """Return a 16-byte AES-128 key by zero-padding or truncating."""
    if isinstance(key, str):
        key = key.encode("utf-8")
    key = bytes(key)

    if len(key) < BLOCK_SIZE:
        return key + bytes(BLOCK_SIZE - len(key))
    return key[:BLOCK_SIZE]


def bytes_to_state(block):
    """Convert 16 bytes into AES's 4x4 column-major state matrix."""
    if len(block) != BLOCK_SIZE:
        raise ValueError("AES block must be exactly 16 bytes")

    return [[block[row + 4 * col] for col in range(4)] for row in range(4)]


def state_to_bytes(state):
    """Convert a 4x4 column-major AES state matrix back into 16 bytes."""
    return bytes(state[row][col] for col in range(4) for row in range(4))


def xor_bytes(left, right):
    return bytes(a ^ b for a, b in zip(left, right))


def sub_bytes(state):
    for row in range(4):
        for col in range(4):
            state[row][col] = Sbox[state[row][col]]
    return state


def inv_sub_bytes(state):
    for row in range(4):
        for col in range(4):
            state[row][col] = InvSbox[state[row][col]]
    return state


def shift_rows(state):
    for row in range(1, 4):
        state[row] = state[row][row:] + state[row][:row]
    return state


def inv_shift_rows(state):
    for row in range(1, 4):
        state[row] = state[row][-row:] + state[row][:-row]
    return state


def _mix_columns_with_matrix(state, matrix):
    for col in range(4):
        old_col = [state[row][col] for row in range(4)]
        for row in range(4):
            state[row][col] = (
                gf_mult(matrix[row][0], old_col[0])
                ^ gf_mult(matrix[row][1], old_col[1])
                ^ gf_mult(matrix[row][2], old_col[2])
                ^ gf_mult(matrix[row][3], old_col[3])
            )
    return state


def mix_columns(state):
    return _mix_columns_with_matrix(state, Mixer)


def inv_mix_columns(state):
    return _mix_columns_with_matrix(state, InvMixer)


def add_round_key(state, round_key):
    for row in range(4):
        for col in range(4):
            state[row][col] ^= round_key[row][col]
    return state


def _rot_word(word):
    return word[1:] + word[:1]


def _sub_word(word):
    return [Sbox[byte] for byte in word]


def key_expansion(key):
    """Generate 11 round keys for AES-128."""
    key = normalize_key(key)

    words = [list(key[i:i + 4]) for i in range(0, BLOCK_SIZE, 4)]

    for i in range(4, 4 * (AES_128_ROUNDS + 1)):
        temp = words[i - 1].copy()

        if i % 4 == 0:
            temp = _sub_word(_rot_word(temp))
            temp[0] ^= Rcon[i // 4]

        new=[]
        for j in range(4):
            new.append(words[i-4][j]^temp[j])

        words.append(new)

    round_keys = []
    for round_number in range(AES_128_ROUNDS + 1):
        round_words = words[4 * round_number:4 * round_number + 4]
        round_key = [[round_words[col][row] for col in range(4)] for row in range(4)]
        round_keys.append(round_key)

    return round_keys


def encrypt_block(block, round_keys):
    state = bytes_to_state(block)

    add_round_key(state, round_keys[0])

    for round_number in range(1, AES_128_ROUNDS):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[round_number])

    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[AES_128_ROUNDS])

    return state_to_bytes(state)


def decrypt_block(block, round_keys):
    state = bytes_to_state(block)

    add_round_key(state, round_keys[AES_128_ROUNDS])

    for round_number in range(AES_128_ROUNDS - 1, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, round_keys[round_number])
        inv_mix_columns(state)

    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, round_keys[0])

    return state_to_bytes(state)


def pkcs7_pad(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    data = bytes(data)

    padding_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([padding_len]) * padding_len


def pkcs7_unpad(data):
    if not data:
        raise ValueError("Padded data cannot be empty")

    padding_len = data[-1]
    if padding_len < 1 or padding_len > BLOCK_SIZE:
        raise ValueError("Invalid PKCS#7 padding length")

    if data[-padding_len:] != bytes([padding_len]) * padding_len:
        raise ValueError("Invalid PKCS#7 padding bytes")

    return data[:-padding_len]


def encrypt_ecb(plaintext, key):
    padded = pkcs7_pad(plaintext)
    round_keys = key_expansion(key)

    ciphertext = bytearray()
    for i in range(0, len(padded), BLOCK_SIZE):
        ciphertext.extend(encrypt_block(padded[i:i + BLOCK_SIZE], round_keys))

    return bytes(ciphertext)


def decrypt_ecb(ciphertext, key):
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("ECB ciphertext length must be a multiple of 16")

    round_keys = key_expansion(key)

    plaintext = bytearray()
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        plaintext.extend(decrypt_block(ciphertext[i:i + BLOCK_SIZE], round_keys))

    return pkcs7_unpad(bytes(plaintext))


def encrypt_cbc(plaintext, key, iv=None):
    if iv is None:
        iv = os.urandom(BLOCK_SIZE)
    if len(iv) != BLOCK_SIZE:
        raise ValueError("CBC IV must be exactly 16 bytes")

    padded = pkcs7_pad(plaintext)
    round_keys = key_expansion(key)

    previous = iv
    ciphertext = bytearray(iv)

    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i:i + BLOCK_SIZE]
        encrypted_block = encrypt_block(xor_bytes(block, previous), round_keys)
        ciphertext.extend(encrypted_block)
        previous = encrypted_block

    return bytes(ciphertext)


def decrypt_cbc(iv_and_ciphertext, key):
    if len(iv_and_ciphertext) < 2 * BLOCK_SIZE:
        raise ValueError("CBC input must contain a 16-byte IV and at least one ciphertext block")
    if len(iv_and_ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("CBC ciphertext length must be a multiple of 16")

    iv = iv_and_ciphertext[:BLOCK_SIZE]
    ciphertext = iv_and_ciphertext[BLOCK_SIZE:]
    round_keys = key_expansion(key)

    previous = iv
    plaintext = bytearray()

    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        decrypted_block = decrypt_block(block, round_keys)
        plaintext.extend(xor_bytes(decrypted_block, previous))
        previous = block

    return pkcs7_unpad(bytes(plaintext))


def bytes_to_hex(data):
    return bytes(data).hex()


def bytes_to_ascii(data):
    return bytes(data).decode("utf-8", errors="replace")


def run_mode_demo(mode_name, plaintext, key):
    key_bytes = normalize_key(key)
    plaintext_bytes = plaintext.encode("utf-8")

    key_start = time.perf_counter()
    key_expansion(key_bytes)
    key_time = time.perf_counter() - key_start

    encrypt_start = time.perf_counter()
    if mode_name == "ECB":
        ciphertext = encrypt_ecb(plaintext_bytes, key_bytes)
    elif mode_name == "CBC":
        ciphertext = encrypt_cbc(plaintext_bytes, key_bytes)
    else:
        raise ValueError("Unsupported AES mode")
    encryption_time = time.perf_counter() - encrypt_start

    decrypt_start = time.perf_counter()
    if mode_name == "ECB":
        recovered = decrypt_ecb(ciphertext, key_bytes)
    else:
        recovered = decrypt_cbc(ciphertext, key_bytes)
    decryption_time = time.perf_counter() - decrypt_start

    print(f"Mode: {mode_name}")
    print(f"Key ASCII: {bytes_to_ascii(key_bytes)}")
    print(f"Key HEX: {bytes_to_hex(key_bytes)}")
    print(f"Plaintext ASCII: {plaintext}")
    print(f"Plaintext HEX: {bytes_to_hex(plaintext_bytes)}")

    if mode_name == "CBC":
        print(f"IV HEX: {bytes_to_hex(ciphertext[:BLOCK_SIZE])}")
        print(f"Ciphertext HEX: {bytes_to_hex(ciphertext)}")
    else:
        print(f"Ciphertext HEX: {bytes_to_hex(ciphertext)}")

    print(f"Recovered ASCII: {bytes_to_ascii(recovered)}")
    print(f"Recovered HEX: {bytes_to_hex(recovered)}")
    print(f"Key schedule time: {key_time:.8f} seconds")
    print(f"Encryption time: {encryption_time:.8f} seconds")
    print(f"Decryption time: {decryption_time:.8f} seconds")
    print()


def self_test():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    expected_ciphertext = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

    round_keys = key_expansion(key)
    ciphertext = encrypt_block(plaintext, round_keys)
    recovered = decrypt_block(ciphertext, round_keys)

    assert ciphertext == expected_ciphertext
    assert recovered == plaintext


def main():
    self_test()

    plaintext = input("Enter plaintext: ")
    key = input("Enter key: ")

    run_mode_demo("ECB", plaintext, key)
    run_mode_demo("CBC", plaintext, key)


if __name__ == "__main__":
    main()
