# n = 8 means we are working with bytes (8 bits) 
n = 8

#Encryption
def encryption(plain_text, key):
    
    # Setup initial arrays for KSA and PRGA (0 to 255 for byte values)
    S = [i for i in range(0, 2**n)]
    
    # Convert key and plain_text to decimal numbers instantly for easier processing in KSA and PRGA
    key_list = [ord(c) for c in key]
    pt = [ord(c) for c in plain_text]

    # Key Generation Algorithm (KSA) [Initialize the state vector S based on the key]
    def KSA():
        j = 0
        N = len(S)
        for i in range(0, N):
            # Using modulo (%) to wrap around the key and state vector indices
            j = (j + S[i] + key_list[i % len(key_list)]) % N
            S[i], S[j] = S[j], S[i]      
    KSA()

    # Keystream Generation (PRGA) [Generate a keystream of bytes that will be XORed with the plaintext]
    key_stream = []
    def PRGA():
        N = len(S)
        i = j = 0
        # This loop generates a keystream byte for each byte of plaintext
        for k in range(0, len(pt)):
            i = (i + 1) % N
            j = (j + S[i]) % N
            S[i], S[j] = S[j], S[i]
            t = (S[i] + S[j]) % N
            key_stream.append(S[t])
    PRGA()

    # XOR Encryption Mechanism (XOR each byte of plaintext with corresponding byte of keystream)
    cipher_text = []
    def XOR():
        # This loop pairs up each plaintext byte with a keystream byte and applies XOR
        for i in range(len(pt)):
            c = key_stream[i] ^ pt[i]
            cipher_text.append(c)
    XOR()

    # Convert the encrypted numbers to readable Hexadecimal text
    encrypted_hex = ""
    # This loop converts each byte of the cipher text to a two-digit hexadecimal string
    for i in cipher_text:
        encrypted_hex += f"{i:02X}" 
        
    print("\nCipher text (Hex format) : ", encrypted_hex)
    return encrypted_hex

#Decryption
def decryption(cipher_hex, key):
    
    # Setup initial arrays again for decryption
    S = [i for i in range(0, 2**n)]
    key_list = [ord(c) for c in key]
    
    # Convert hex cipher text back to decimal numbers
    pt = []
    for i in range(0, len(cipher_hex), 2):
        pt.append(int(cipher_hex[i:i+2], 16))

    # KSA for decryption (same as encryption)
    def KSA():
        j = 0
        N = len(S)
        for i in range(0, N):
            j = (j + S[i] + key_list[i % len(key_list)]) % N
            S[i], S[j] = S[j], S[i]
    KSA()

    # PRGA for decryption (same as encryption)
    key_stream = []
    def PRGA():
        N = len(S)
        i = j = 0
        for k in range(0, len(pt)):
            i = (i + 1) % N
            j = (j + S[i]) % N
            S[i], S[j] = S[j], S[i]
            t = (S[i] + S[j]) % N
            key_stream.append(S[t])
    PRGA()

    # XOR Decryption Mechanism (XOR each byte of cipher text with corresponding byte of keystream to retrieve original plaintext)
    original_text = []
    def do_XOR():
        for i in range(len(pt)):
            p = key_stream[i] ^ pt[i]
            original_text.append(p)
    do_XOR()

    # Convert the decrypted numbers back to normal text letters
    decrypted_string = ""
    for i in original_text:
        decrypted_string += chr(i)
        
    print("Decrypted text : ", decrypted_string)
    return decrypted_string


# ==========================================
# Main Function
# ==========================================

# Accept normal user input
user_plaintext = input("Enter the plaintext: ")
user_key = input("Enter the key(string only): ")

# Run the fixed functions
final_cipher = encryption(user_plaintext, user_key)
print ("Key used for encryption and decryption : ", user_key)
final_plain = decryption(final_cipher, user_key)
