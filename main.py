from key_generation import generate_key
from message_processing import encrypt_message, decrypt_message
from encryption import encrypt
import random

# Dictionary to store users and their associated IPs and reverse IPs
users = {}

# Boolean for deciding wheather to continue running the program
run = True

def reverse_permutation(IP):
    reverse_IP = [0] * len(IP)  # Create a list of the same length as IP, initialized to 0
    for i, pos in enumerate(IP):
        reverse_IP[pos - 1] = i + 1  # The (pos - 1)th position in reverse IP gets i+1
    return reverse_IP

def create_IP():
    # Creates a list/array of numbers from 1 to 64
    IP = list(range(1, 65))  # Create a list of numbers from 1 to 64
    random.shuffle(IP)  # Shuffle the list in place to get a random order
    return IP

def create_user_data():
    """
    Creates user data: 4 IPs and their corresponding reverse IPs.
    Returns a list of 8 arrays, 4 IPs followed by their reverse IPs.
    """
    IPs = [create_IP() for _ in range(4)]  # Generate 4 IPs
    reverse_IPs = [reverse_permutation(IP) for IP in IPs]  # Generate corresponding reverse IPs
    return IPs + reverse_IPs

def to_chars(final_bits):
    # Convert final_bits to ASCII characters
    characters = []
    for i in range(0, len(final_bits), 8):  # Process 8 bits at a time
        byte = final_bits[i:i+8]  # Get the next 8-bit chunk
        characters.append(chr(int(byte, 2)))  # Convert to ASCII and append the character
    return ''.join(characters)

def main():
    global run # Allows run to be modified in the main function

    # Ask the user to input their email address
    email = input("Enter your email address: ").strip()

    # Check if the user already exists in the dictionary
    if email in users:
        print(f"User {email} already exists in the system.")
    else:
        # Create new IPs and reverse IPs for the user
        user_data = create_user_data()
        users[email] = user_data
        print(f"Created new user data for {email}")

    # Generate the cryptographic key for the user and encrypt it
    generated_key = generate_key(email, users.get(email)[0:4])
    print(f"Generated cryptographic key in bits: {generated_key}\n")
    print(f"Generated cryptographic key in ASCII chars: {to_chars(''.join(generated_key))}\n")

    # Ask the user to input a message to encrypt
    message = input("Enter the message you want to encrypt: ").strip()

    # Process and encrypt the message
    encrypted_bits = encrypt_message(message, users.get(email)[0:4])
    print(f"Generated encrypted message in bits: {encrypted_bits}\n")

    # Encrypt the message using the user's key
    final_encryption = encrypt(generated_key, encrypted_bits)
    print(f"Generated final encryption: {final_encryption}\n")

    # Ask if the user wants to decrypt the message
    decrypt_choice = input("Do you want to decrypt the message? (yes/no): ").strip().lower()
    if decrypt_choice == "yes":
        decrypted_message = decrypt_message(encrypted_bits, users.get(email)[0:4])
        print(f"Decrypted message: {decrypted_message}")
    else:
        print("Message decryption skipped.")
    
    # Ask if the user wants to run the program again
    run_choice = input("Do you want to run the program again? (yes/no): ").strip().lower()
    if run_choice == "no":
        run = False
        print(f"The program has now finished running. Thank you for using!")
    else:
        print(f"Great! We are running the program again!")

if __name__ == "__main__":
    while(run):
        main()