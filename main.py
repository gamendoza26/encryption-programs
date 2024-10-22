from key_generation import generate_key
from message_processing import encrypt_message, decrypt_message

def main():
    # Test the key generation
    generated_key = generate_key("gam70@duke.edu")
    ##print(f"Generated cryptographic key: {generated_key}\n")

    # Test the message processing
    encrypted_bits = encrypt_message("Hello World!")
    ##print(f"Generated encrypted message in bits: {encrypted_bits}\n")
    decrypted_message = decrypt_message(encrypted_bits)
    ##print(f"Generated decrypted message: {decrypted_message}\n")

    # Test the encryption


if __name__ == "__main__":
    main()
