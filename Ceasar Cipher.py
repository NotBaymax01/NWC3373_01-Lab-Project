
# Encryption
def encrypt(text,s):
    result = ""

    for i in range(len(text)):
        char = text[i]

        # Encrypt uppercase characters
        if (char.isupper()):
            result += chr((ord(char) + s - 65) % 26 + 65) #65 is the ASCII value of 'A', while 26 is the number of letters in the English alphabet

        # Encrypt lowercase characters
        elif (char.islower()):
            result += chr((ord(char) + s - 97) % 26 + 97) #97 is the ASCII value of 'a', while 26 is the number of letters in the English alphabet

        # Leave spaces, numbers, and symbols alone
        else:
            result += char

    return result

# Decryption
def decrypt(cipher,s):
    result = ""

    for i in range(len(cipher)):
        char = cipher[i]

        # Decrypt uppercase characters
        if (char.isupper()):
            result += chr((ord(char) - s - 65) % 26 + 65)

        # Decrypt lowercase characters
        elif (char.islower()):
            result += chr((ord(char) - s - 97) % 26 + 97)

        # Leave spaces, numbers, and symbols alone
        else:
            result += char

    return result

# user input
plaintext = input("Please enter the plaintext: ")
s = int(input("Please enter the shift value (numbers 1-25 only): "))

# print the results
print("\nEncrypted Text: " + encrypt(plaintext,s))
print("Shift : " + str(s))
print("Decrypted Text  : " + decrypt(encrypt(plaintext,s),s))