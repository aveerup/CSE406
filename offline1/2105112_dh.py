import hashlib
import random
import time


DEFAULT_TRIALS = 5


def is_probable_prime(n, rounds=20):
    """Miller-Rabin primality test."""
    if n < 2:
        return False

    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for prime in small_primes:
        if n == prime:
            return True
        if n % prime == 0:
            return False

    d = n - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2

    for _ in range(rounds):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


def generate_safe_prime(k):
    """Generate a k-bit safe prime P where P = 2q + 1 and q is prime."""
    if k < 3:
        raise ValueError("Key size must be at least 3 bits")

    while True:
        q = random.getrandbits(k - 1)
        q |= 1
        q |= 1 << (k - 2)

        if not is_probable_prime(q):
            continue

        p = 2 * q + 1
        if p.bit_length() == k and is_probable_prime(p):
            return p, q


def find_generator(p, q):
    """Find a generator for a safe-prime modulus P = 2q + 1."""
    prime_factors_of_p_minus_1 = (2, q)

    while True:
        g = random.randrange(2, p - 1)
        is_generator = True

        for factor in prime_factors_of_p_minus_1:
            if pow(g, (p - 1) // factor, p) == 1:
                is_generator = False
                break

        if is_generator:
            return g


def generate_public_parameters(k, seed=None):
    if seed is not None:
        random.seed(seed)

    p, q = generate_safe_prime(k)
    g = find_generator(p, q)
    return p, g


def generate_private_key(k):
    """Generate a private key with at least k bits."""
    secret = random.getrandbits(k)
    secret |= 1 << (k - 1)
    return secret


def generate_public_key(g, private_key, p):
    return pow(g, private_key, p)


def compute_shared_secret(other_public_key, private_key, p):
    return pow(other_public_key, private_key, p)


def int_to_bytes(value):
    length = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(length, byteorder="big")


def derive_aes_key(shared_secret, key_size=128):
    """Derive an AES key by SHA-256 hashing the DH secret and truncating."""
    if key_size not in (128, 192, 256):
        raise ValueError("AES key size must be 128, 192, or 256 bits")

    digest = hashlib.sha256(int_to_bytes(shared_secret)).digest()
    return digest[:key_size // 8]


def run_single_exchange(k, p=None, g=None):
    if p is None or g is None:
        p, g = generate_public_parameters(k)

    alice_private = generate_private_key(k)
    bob_private = generate_private_key(k)

    alice_public_start = time.perf_counter()
    alice_public = generate_public_key(g, alice_private, p)
    alice_public_time = time.perf_counter() - alice_public_start

    bob_public_start = time.perf_counter()
    bob_public = generate_public_key(g, bob_private, p)
    bob_public_time = time.perf_counter() - bob_public_start

    shared_start = time.perf_counter()
    alice_shared = compute_shared_secret(bob_public, alice_private, p)
    bob_shared = compute_shared_secret(alice_public, bob_private, p)
    shared_time = time.perf_counter() - shared_start

    if alice_shared != bob_shared:
        raise RuntimeError("Diffie-Hellman shared secrets do not match")

    return {
        "p": p,
        "g": g,
        "alice_private": alice_private,
        "bob_private": bob_private,
        "alice_public": alice_public,
        "bob_public": bob_public,
        "shared_secret": alice_shared,
        "alice_public_time": alice_public_time,
        "bob_public_time": bob_public_time,
        "shared_time": shared_time,
    }


def benchmark_key_sizes(key_sizes=(128, 192, 256), trials=DEFAULT_TRIALS):
    results = []

    for k in key_sizes:
        p, g = generate_public_parameters(k, seed=k)

        alice_total = 0.0
        bob_total = 0.0
        shared_total = 0.0

        for _ in range(trials):
            result = run_single_exchange(k, p, g)
            alice_total += result["alice_public_time"]
            bob_total += result["bob_public_time"]
            shared_total += result["shared_time"]

        results.append({
            "k": k,
            "alice_public_avg": alice_total / trials,
            "bob_public_avg": bob_total / trials,
            "shared_avg": shared_total / trials,
        })

    return results


def print_benchmark_table(results):
    print("Computation time for Diffie-Hellman")
    print(f"{'k':<8}{'A = g^Ka mod P':<20}{'B = g^Kb mod P':<20}{'shared key s':<20}")

    for result in results:
        print(
            f"{result['k']:<8}"
            f"{result['alice_public_avg']:<20.8f}"
            f"{result['bob_public_avg']:<20.8f}"
            f"{result['shared_avg']:<20.8f}"
        )


def demo(k=128):
    print(f"Generating {k}-bit Diffie-Hellman public parameters...")
    result = run_single_exchange(k)

    print(f"P: {result['p']}")
    print(f"g: {result['g']}")
    print(f"Alice private Ka: {result['alice_private']}")
    print(f"Alice public A: {result['alice_public']}")
    print(f"Bob private Kb: {result['bob_private']}")
    print(f"Bob public B: {result['bob_public']}")
    print(f"Shared secret s: {result['shared_secret']}")
    print(f"Derived AES-128 key HEX: {derive_aes_key(result['shared_secret']).hex()}")
    print("Shared secret verification: OK")
    print()

    results = benchmark_key_sizes()
    print_benchmark_table(results)


if __name__ == "__main__":
    demo()
