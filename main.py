from key_generation import generate_key

def main():
    # Test the key generation
    generated_key = generate_key("user1234")
    print(f"Generated cryptographic key: {generated_key}")


if __name__ == "__main__":
    main()
