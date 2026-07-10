import importlib.util
import json
import socket
import struct


HOST = "127.0.0.1"
PORT = 5000
KEY_SIZE = 128


def load_dh_module():
    spec = importlib.util.spec_from_file_location("student_dh", "2105112_dh.py")
    dh = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dh)
    return dh


def load_aes_module():
    spec = importlib.util.spec_from_file_location("student_aes", "2105112_aes.py")
    aes = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(aes)
    return aes


def send_json(sock, payload):
    data = json.dumps(payload).encode("utf-8")
    sock.sendall(struct.pack("!I", len(data)) + data)


def recv_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Socket closed before full message was received")
        data.extend(chunk)
    return bytes(data)


def recv_json(sock):
    size = struct.unpack("!I", recv_exact(sock, 4))[0]
    return json.loads(recv_exact(sock, size).decode("utf-8"))


def main():
    dh = load_dh_module()
    aes = load_aes_module()
    plaintext = input("Enter plaintext for Alice to send: ").encode("utf-8")

    print(f"Generating {KEY_SIZE}-bit Diffie-Hellman values...")
    p, g = dh.generate_public_parameters(KEY_SIZE)
    alice_private = dh.generate_private_key(KEY_SIZE)
    alice_public = dh.generate_public_key(g, alice_private, p)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect((HOST, PORT))

        send_json(client, {
            "type": "dh_params",
            "k": KEY_SIZE,
            "P": str(p),
            "g": str(g),
            "A": str(alice_public),
        })

        bob_message = recv_json(client)
        bob_public = int(bob_message["B"])

        shared_secret = dh.compute_shared_secret(bob_public, alice_private, p)
        aes_key = dh.derive_aes_key(shared_secret, 128)
        ciphertext = aes.encrypt_cbc(plaintext, aes_key)

        send_json(client, {
            "type": "ciphertext",
            "mode": "CBC",
            "ciphertext": ciphertext.hex(),
        })

        print("Alice computed shared secret.")
        print(f"Bob ready: {bob_message.get('ready')}")
        print(f"Derived AES key HEX: {aes_key.hex()}")
        print(f"Plaintext ASCII: {plaintext.decode('utf-8', errors='replace')}")
        print(f"Plaintext HEX: {plaintext.hex()}")
        print(f"Ciphertext HEX: {ciphertext.hex()}")


if __name__ == "__main__":
    main()
