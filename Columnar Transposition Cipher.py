import math

# Encryption
def encryptMessage(msg, key):
    cipher = ""
    msg_len = float(len(msg))
    msg_lst = list(msg)

    col = len(key)
    row = int(math.ceil(msg_len / col))

    fill_null = int((row * col) - msg_len)
    msg_lst.extend('_' * fill_null)

    matrix = [msg_lst[i: i + col] for i in range(0, len(msg_lst), col)]

    # Pair each character with its original index, then sort by the character
    key_order = sorted([(char, i) for i, char in enumerate(key)])

    for char, original_index in key_order:
        cipher += ''.join([r[original_index] for r in matrix])

    return cipher


# Decryption
def decryptMessage(cipher, key):
    msg = ""
    msg_len = float(len(cipher))

    col = len(key)
    row = int(math.ceil(msg_len / col))

    # Pair each character with its original index, then sort by the character
    key_order = sorted([(char, i) for i, char in enumerate(key)])

    dec_cipher = [[None] * col for _ in range(row)]

    # Fill the matrix column-wise based on the sorted key order
    msg_indx = 0
    for char, original_index in key_order:
        for j in range(row):
            dec_cipher[j][original_index] = cipher[msg_indx]
            msg_indx += 1

    # Join the characters in the matrix to form the original message
    try:
        msg = ''.join(sum(dec_cipher, []))
    except TypeError:
        raise TypeError("This program cannot handle repeating words.")

    null_count = msg.count('_')
    if null_count > 0:
        return msg[: -null_count]

    return msg


# User input
plaintext = input("Please enter the plaintext: ")
key = input("Please enter the key(string only): ")

# Encryption and Decryption Output
cipher = encryptMessage(plaintext, key)
print("\nEncrypted Message: {}".format(cipher))
print("Key: {}".format(key))
print("Plain Message: {}".format(decryptMessage(cipher, key)))