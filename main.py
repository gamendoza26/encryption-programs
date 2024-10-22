from key_generation import generate_key
from message_processing import process_message

def main():
    # Test the key generation
    generated_key = generate_key("user1234")
    ## print(f"Generated cryptographic key: {generated_key}")

    # Test the message processing
    processed_message = process_message("hello there!")
    print(processed_message)

if __name__ == "__main__":
    main()
