def build_IP_array(bit_string):    
    IP_array = []
    
    # Split the bit string into 8 groups (each of 32 bits)
    IP_array.append(bit_string[0:32] + bit_string[64:96])
    IP_array.append(bit_string[32:64] + bit_string[96:128])
    IP_array.append(bit_string[128:160] + bit_string[192:224])
    IP_array.append(bit_string[160:192] + bit_string[224:256])

    return IP_array

def run_through_IP_algorithm(IP_array):
    final_array = []

    IP1 = [5, 22, 12, 45, 8, 31, 55, 60, 11, 34, 6, 2, 50, 29, 42, 13, 19, 58, 1, 62, 35, 20, 40, 16, 33, 47, 9, 26, 38, 14, 7, 61, 53, 18, 28, 56, 24, 44, 3, 25, 37, 52, 10, 21, 30, 43, 49, 59, 17, 15, 46, 41, 27, 36, 32, 48, 63, 57, 4, 23, 39, 64, 54, 51]
    IP2 = [34, 1, 29, 47, 6, 9, 43, 56, 22, 15, 50, 48, 61, 40, 19, 36, 57, 63, 8, 3, 20, 35, 11, 12, 17, 46, 30, 24, 4, 5, 59, 60, 13, 25, 2, 33, 55, 38, 26, 18, 49, 7, 32, 31, 64, 52, 27, 45, 14, 23, 41, 10, 28, 44, 53, 42, 62, 37, 21, 58, 16, 54, 51, 39]
    IP3 = [3, 29, 53, 41, 16, 54, 25, 10, 50, 1, 60, 38, 27, 5, 48, 17, 46, 12, 44, 63, 34, 28, 7, 35, 2, 30, 43, 18, 8, 26, 61, 36, 62, 4, 14, 6, 39, 11, 15, 24, 21, 19, 47, 37, 33, 64, 52, 55, 42, 58, 9, 56, 22, 32, 49, 40, 20, 13, 59, 23, 45, 51, 31, 57]
    IP4 = [23, 40, 35, 3, 54, 50, 30, 61, 32, 11, 6, 41, 14, 26, 38, 9, 1, 62, 48, 57, 4, 63, 22, 34, 20, 7, 13, 36, 19, 56, 25, 24, 44, 18, 10, 52, 12, 58, 33, 8, 16, 43, 60, 49, 45, 17, 53, 29, 59, 21, 27, 47, 37, 64, 15, 2, 5, 28, 31, 55, 42, 51, 39, 46]
    IPs = [IP1, IP2, IP3, IP4]  # Group all IP arrays for easy iteration

    for i, ip in enumerate(IP_array):
        final_bits = ""
        for pos in IPs[i]:  # Go through the respective IP array
            bit_position = pos - 1  # Adjust for 0-indexing
            final_bits += ip[bit_position]  # Get the bit from the IP_array
        final_array.append(final_bits[0:32])  # Append the the first segment of rearranged bits to final_array
        final_array.append(final_bits[32:64])  # Append the the second segment of rearranged bits to final_array
    
    return final_array

def encrypt_message(message):
    binary_message = ''.join(format(ord(char), '08b') for char in message) # convert plain text to binary string

    # checks to make sure binary string is in bounds
    if len(binary_message) > 256:
        return "ERROR: Message exceeds 256 bits"

    # creates padding for remaining of 256 bits
    binary_message = binary_message.ljust(256,'0') 

    # Split string into 64 bit increments
    array_bits = build_IP_array(binary_message)

    array_bits = run_through_IP_algorithm(array_bits)

    return array_bits

## DECRYPTION BELOW

def reverse_IP_algorithm(final_array):
    original_array = []
    
    # Same IP arrays as used in encryption
    IP1 = [5, 22, 12, 45, 8, 31, 55, 60, 11, 34, 6, 2, 50, 29, 42, 13, 19, 58, 1, 62, 35, 20, 40, 16, 33, 47, 9, 26, 38, 14, 7, 61, 53, 18, 28, 56, 24, 44, 3, 25, 37, 52, 10, 21, 30, 43, 49, 59, 17, 15, 46, 41, 27, 36, 32, 48, 63, 57, 4, 23, 39, 64, 54, 51]
    IP2 = [34, 1, 29, 47, 6, 9, 43, 56, 22, 15, 50, 48, 61, 40, 19, 36, 57, 63, 8, 3, 20, 35, 11, 12, 17, 46, 30, 24, 4, 5, 59, 60, 13, 25, 2, 33, 55, 38, 26, 18, 49, 7, 32, 31, 64, 52, 27, 45, 14, 23, 41, 10, 28, 44, 53, 42, 62, 37, 21, 58, 16, 54, 51, 39]
    IP3 = [3, 29, 53, 41, 16, 54, 25, 10, 50, 1, 60, 38, 27, 5, 48, 17, 46, 12, 44, 63, 34, 28, 7, 35, 2, 30, 43, 18, 8, 26, 61, 36, 62, 4, 14, 6, 39, 11, 15, 24, 21, 19, 47, 37, 33, 64, 52, 55, 42, 58, 9, 56, 22, 32, 49, 40, 20, 13, 59, 23, 45, 51, 31, 57]
    IP4 = [23, 40, 35, 3, 54, 50, 30, 61, 32, 11, 6, 41, 14, 26, 38, 9, 1, 62, 48, 57, 4, 63, 22, 34, 20, 7, 13, 36, 19, 56, 25, 24, 44, 18, 10, 52, 12, 58, 33, 8, 16, 43, 60, 49, 45, 17, 53, 29, 59, 21, 27, 47, 37, 64, 15, 2, 5, 28, 31, 55, 42, 51, 39, 46]
    IPs = [IP1, IP2, IP3, IP4]  # Group all IP arrays for easy iteration


    IPs = [IP1, IP2, IP3, IP4]

    for i, encrypted_bits in enumerate(final_array):
        reversed_bits = [''] * 64  # Create a 64-bit empty string
        
        for idx, pos in enumerate(IPs[i]):
            reversed_bits[pos - 1] = encrypted_bits[idx]  # Reverse map the bits
        
        # Convert list back to string and append to original array
        original_array.append(''.join(reversed_bits))
    
    return original_array


def decrypt_message(bit_array):
    IP_array = [
        bit_array[0] + bit_array[1],
        bit_array[2] + bit_array[3],
        bit_array[4] + bit_array[5],
        bit_array[6] + bit_array[7]
    ]
    # Reverse the IP step
    reversed_IP_array = reverse_IP_algorithm(IP_array)

    # Rearrange the 32 bit segments in the correct order
    final_bits = reversed_IP_array[0][0:32] + reversed_IP_array[1][0:32] + reversed_IP_array[0][32:64] + reversed_IP_array[1][32:64] + reversed_IP_array[2][0:32] + reversed_IP_array[3][0:32] + reversed_IP_array[2][32:64] + reversed_IP_array[3][32:64]

    # Convert final_bits to ASCII characters
    characters = []
    for i in range(0, len(final_bits), 8):  # Process 8 bits at a time
        byte = final_bits[i:i+8]  # Get the next 8-bit chunk
        characters.append(chr(int(byte, 2)))  # Convert to ASCII and append the character

    # Join the characters to form the final string
    return ''.join(characters)