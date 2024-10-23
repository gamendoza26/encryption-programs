import hashlib

def hash_generation(key):
    key_bytes = key.encode('utf-8') #Convert the input key into bytes

    sha256_hash = hashlib.sha256() #Creates a SHA-256 hash object
    sha256_hash.update(key_bytes) #Updates SHA-256 hash with input string

    hash_hex = sha256_hash.hexdigest() #Gives a hexadecimal representation of the digest
    
    return hash_hex

def build_IP_array(hash_hex):
    bit_string = bin(int(hash_hex, 16))[2:].zfill(256)  # Convert hex to a 256-bit binary string
    
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


def generate_key(key, IPs):
    hash_hex = hash_generation(key) # Generates 256 bit hash string

    IP_array = build_IP_array(hash_hex) # Creates 4 mixed sections of bits (from hash string)

    # Uses personal IPs to rearrange the bits in a specific form, broken into 32 bit sections (8 total)
    final_array = run_through_IP_algorithm(IP_array, IPs) 
    return final_array