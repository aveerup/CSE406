import importlib.util
import json
import socket
import struct


HOST = "127.0.0.1"
PORT = 5000


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

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(1)
        print(f"Bob is listening on {HOST}:{PORT}...")

        connection, address = server.accept()
        with connection:
            print(f"Connected with Alice at {address}")

            dh_message = recv_json(connection)
            p = int(dh_message["P"])
            g = int(dh_message["g"])
            alice_public = int(dh_message["A"])
            k = int(dh_message["k"])

            bob_private = dh.generate_private_key(k)
            bob_public = dh.generate_public_key(g, bob_private, p)
            shared_secret = dh.compute_shared_secret(alice_public, bob_private, p)
            aes_key = dh.derive_aes_key(shared_secret, 128)

            send_json(connection, {
                "type": "dh_public",
                "B": str(bob_public),
                "ready": True,
            })

            encrypted_message = recv_json(connection)
            ciphertext = bytes.fromhex(encrypted_message["ciphertext"])
            plaintext = aes.decrypt_cbc(ciphertext, aes_key)

            print("Bob computed shared secret.")
            print(f"Derived AES key HEX: {aes_key.hex()}")
            print(f"Received ciphertext HEX: {ciphertext.hex()}")
            print(f"Recovered plaintext ASCII: {plaintext.decode('utf-8', errors='replace')}")
            print(f"Recovered plaintext HEX: {plaintext.hex()}")


if __name__ == "__main__":
    main()
