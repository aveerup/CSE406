import importlib.util


def load_aes_module():
    spec = importlib.util.spec_from_file_location("student_aes", "2105112_aes.py")
    aes = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(aes)
    return aes


def load_dh_module():
    spec = importlib.util.spec_from_file_location("student_dh", "2105112_dh.py")
    dh = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dh)
    return dh


def run_aes_demo():
    aes = load_aes_module()

    plaintext = input("Enter plaintext: ")
    key = input("Enter key: ")

    aes.run_mode_demo("ECB", plaintext, key)
    aes.run_mode_demo("CBC", plaintext, key)


def run_dh_demo():
    dh = load_dh_module()
    dh.demo(128)


def main():
    while True:
        print("1. AES ECB/CBC demo")
        print("2. Diffie-Hellman demo and timing table")
        print("3. Exit")

        choice = input("Choose option: ").strip()
        print()

        if choice == "1":
            run_aes_demo()
        elif choice == "2":
            run_dh_demo()
        elif choice == "3":
            break
        else:
            print("Invalid choice")


if __name__ == "__main__":
    main()
