from key_generation import generate_key
from message_processing import encrypt_message, decrypt_message
from encryption import encrypt
from permutation import permute

def reverse_permutation(IP):
    reverse_IP = [0] * len(IP)  # Create a list of the same length as IP, initialized to 0
    for i, pos in enumerate(IP):
        reverse_IP[pos - 1] = i + 1  # The (pos - 1)th position in reverse IP gets i+1
    return reverse_IP

def main():
    # Test the key generation
    generated_key = generate_key("gam70@duke.edu")
    print(f"Generated cryptographic key: {generated_key}\n")

    # Test the message processing
    encrypted_bits = encrypt_message("Hello World!")
    print(f"Generated encrypted message in bits: {encrypted_bits}\n")
    #### decrypted_message = decrypt_message(encrypted_bits)
    #### print(f"Generated decrypted message: {decrypted_message}\n")

    # Test the encryption
    encrypted = encrypt(generated_key, encrypted_bits)
    print(f"Generated final encryption: {encrypted}\n")

    # Test the permutation
    permuted = permute("This is the permutation message")
    ##print(f"Generated permutation: {permuted}\n")

if __name__ == "__main__":
    main()
