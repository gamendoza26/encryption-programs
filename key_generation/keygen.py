import hashlib

def hash_generation(key):
    key_bytes = key.encode('utf-8') #Convert the input key into bytes

    sha256_hash = hashlib.sha256() #Creates a SHA-256 hash object
    sha256_hash.update(key_bytes) #Updates SHA-256 hash with input string

    hash_hex = sha256_hash.hexdigest() #Gives a hexadecimal representation of the digest
    
    return hash_hex

def build_IP_array(hash_hex):
    IP_array = []

    #Creates new IPs in an array separated in the correct format (split into 8 groups)
    IP_array.append(hash_hex[0:8] + hash_hex[16:24])
    IP_array.append(hash_hex[8:16] + hash_hex[24:32])
    IP_array.append(hash_hex[32:40] + hash_hex[48:56])
    IP_array.append(hash_hex[40:48] + hash_hex[56:64])

    return IP_array

def run_through_IP_algorithm(IP_array):

    return final_array

def generate_key(key):
    hash_hex = hash_generation(key)

    IP_array = build_IP_array(hash_hex)

    final_array = run_through_IP_algorithm(IP_array)

    return final_array