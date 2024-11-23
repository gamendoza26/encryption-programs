# Encryption Program

This Python program allows users to securely generate cryptographic keys, encrypt messages, and decrypt them. It utilizes unique initial permutations (IPs) and reverse permutations to customize the encryption process for each user.

## Features

- **User Management**: Maintains a dictionary of users, where each user is identified by their unique email address. Each user is assigned:
  - 4 unique initial permutations (IPs).
  - 4 reverse permutations corresponding to the IPs.

- **Key Generation**: Generates a cryptographic key based on the user's email address.

- **Message Encryption**:
  - Processes the input message into encrypted bits.
  - Encrypts the message using the user's cryptographic key.

- **Message Decryption**: Decrypts the encrypted bits back into the original message upon user request.

- **Interactive Console**:
  - Allows users to interactively provide email addresses and messages.
  - Handles user-specific data securely.

## How It Works

1. **User Creation**:
   - If the user is new, the program generates 4 unique IPs and their corresponding reverse IPs.
   - If the user already exists, it notifies the user and skips new data creation.

2. **Cryptographic Key**:
   - The program generates a key based on the user's email address using the `generate_key` function.

3. **Message Processing**:
   - Encrypts the message into bits using `encrypt_message`.
   - Produces a final encrypted message using the user's cryptographic key and the `encrypt` function.

4. **Decryption**:
   - If the user opts to decrypt the message, the `decrypt_message` function is used to restore the original message.

5. **Program Loop**:
   - Users are asked if they wish to run the program again or exit.

## Installation and Usage

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd <repository-directory>
