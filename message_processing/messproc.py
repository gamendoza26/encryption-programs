# ENCRYPTION BELOW

def build_IP_array(bit_string):    
    IP_array = []
    
    # Split the bit string into 8 groups (each of 32 bits)
    IP_array.append(bit_string[0:32] + bit_string[64:96])
    IP_array.append(bit_string[32:64] + bit_string[96:128])
    IP_array.append(bit_string[128:160] + bit_string[192:224])
    IP_array.append(bit_string[160:192] + bit_string[224:256])

    return IP_array

def run_through_IP_algorithm(IP_array, IPs):
    final_array = []

    for i, ip in enumerate(IP_array):
        final_bits = ""
        for pos in IPs[i]:  # Go through the respective IP array
            bit_position = pos - 1  # Adjust for 0-indexing
            final_bits += ip[bit_position]  # Get the bit from the IP_array
        final_array.append(final_bits[0:32])  # Append the the first segment of rearranged bits to final_array
        final_array.append(final_bits[32:64])  # Append the the second segment of rearranged bits to final_array
    
    return final_array

def encrypt_message(message, IPs):
    binary_message = ''.join(format(ord(char), '08b') for char in message) # convert plain text to binary string

    # checks to make sure binary string is in bounds
    if len(binary_message) > 256:
        return "ERROR: Message exceeds 256 bits"

    # creates padding for remaining of 256 bits
    binary_message = binary_message.ljust(256,'0') 

    # Split string into 64 bit increments
    array_bits = build_IP_array(binary_message)

    array_bits = run_through_IP_algorithm(array_bits, IPs)

    return array_bits

## DECRYPTION BELOW

def reverse_IP_algorithm(final_array, IPs):
    original_array = []

    for i, encrypted_bits in enumerate(final_array):
        reversed_bits = [''] * 64  # Create a 64-bit empty string
        
        for idx, pos in enumerate(IPs[i]):
            reversed_bits[pos - 1] = encrypted_bits[idx]  # Reverse map the bits
        
        # Convert list back to string and append to original array
        original_array.append(''.join(reversed_bits))
    
    return original_array


def decrypt_message(bit_array, IPs):
    IP_array = [
        bit_array[0] + bit_array[1],
        bit_array[2] + bit_array[3],
        bit_array[4] + bit_array[5],
        bit_array[6] + bit_array[7]
    ]
    # Reverse the IP step
    reversed_IP_array = reverse_IP_algorithm(IP_array, IPs)

    # Rearrange the 32 bit segments in the correct order
    final_bits = reversed_IP_array[0][0:32] + reversed_IP_array[1][0:32] + reversed_IP_array[0][32:64] + reversed_IP_array[1][32:64] + reversed_IP_array[2][0:32] + reversed_IP_array[3][0:32] + reversed_IP_array[2][32:64] + reversed_IP_array[3][32:64]

    # Convert final_bits to ASCII characters
    characters = []
    for i in range(0, len(final_bits), 8):  # Process 8 bits at a time
        byte = final_bits[i:i+8]  # Get the next 8-bit chunk
        characters.append(chr(int(byte, 2)))  # Convert to ASCII and append the character

    # Join the characters to form the final string
    return ''.join(characters)