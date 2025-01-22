from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
import sys
import struct

#----------------task 1 code---------------------

#helper function that determines the header size of a given BMP file
def get_header_size(filename:str) -> int:
    with open(filename, "rb") as file:
            #jump 14 bytes since file header is always 14 bytes
            file.seek(14)
            #read next 4 bytes from dib header to get dib header size
            dib_header_size_bytes = file.read(4)
            #convert the 4 bytes to integer
            dib_header_size = int.from_bytes(dib_header_size_bytes, "little")
            #combine file header size and dib header size for total header size
            total_header_size = 14 + dib_header_size
            return total_header_size

#extract the header of the BMP file
def read_BMP_header(filename: str) -> bytes:
        header_size = get_header_size(filename)
        with open(filename, "rb") as file:
            return file.read(header_size)

#extract the data from the BMP file
def read_image_data(filename: str) -> bytes: #CBC_decrypt: #bool = False, block_size: int = 16
        header_size = get_header_size(filename)
        with open(filename, "rb") as file:
            file.seek(header_size)
            #if(CBC_decrypt == True):
                #file.seek(block_size)
            return file.read()
         
#padding function for PKCS7
def PKCS7_pad(data: bytes, block_size: int) -> None:
    #get the amount of padding needed
    file_size = len(data)
    pad_size = block_size - (file_size % block_size)
    padding = bytes([pad_size] * pad_size)
    #add padding to data
    return data + padding

#remove padding from data
def PKCS7_unpad(data: bytes) -> bytes:
    #Get the value of the last byte
    #padding_length = int(data[len(data)-1])
    padding_length = data[-1]
    if (padding_length <= 16):
        data = data[:len(data)-padding_length]
    #Remove the padding
    return data

# #generate a random AES key
# def generate_aes_key(key_length: int) -> bytes:
#     if key_length not in [16, 24, 32]:
#         raise ValueError("Key length must be 16, 24, or 32 bytes for AES.")
#     return get_random_bytes(key_length)

#encrpyt the data using ECB
def ECB_encrypt(data: bytes, key: bytes) -> bytes:
    block_size = len(key)
    padded_data = PKCS7_pad(data, block_size)
    #Create the AES cipher in ECB mode
    cipher = AES.new(key, AES.MODE_ECB)
    #encrypt the data in blocks and write individually to file
    cipher_text = b""
    for i in range(0, len(padded_data), block_size):
        block = padded_data[i:i+block_size]
        cipher_block = cipher.encrypt(block)
        cipher_text += cipher_block
    return cipher_text

#decrpyt the data using ECB
def ECB_decrypt(data: bytes, key: bytes) -> bytes:
    block_size = len(key)
    #Create the AES cipher in ECB mode
    cipher = AES.new(key, AES.MODE_ECB)
    #decrypt the data in blocks and write individually to file
    decrypted_data = b""
    for i in range(0, len(data), block_size):
        cipher_block = data[i:i+block_size]
        plain_block = cipher.decrypt(cipher_block)
        decrypted_data += plain_block
    #Remove padding from the decrypted data
    plaintext_data = PKCS7_unpad(decrypted_data)
    return plaintext_data

#encrypt the data using CBC
def CBC_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    block_size = len(key)
    padded_data = PKCS7_pad(data, block_size)
    #Create the AES cipher in ECB mode
    cipher = AES.new(key, AES.MODE_ECB)
    #encrypt the data
    cipher_text = b""
    cipher_block = iv
    for i in range(0, len(padded_data), block_size):
        block = padded_data[i:i+block_size]
        #XOR each byte of the block with each byte of the previous cipher block (IV for the first block)
        XOR_block = bytes([block[j] ^ cipher_block[j] for j in range(block_size)])
        #encrypt the XORed block
        cipher_block = cipher.encrypt(XOR_block)
        cipher_text += cipher_block
    return cipher_text

#decrpyt the data using ECB
def CBC_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    block_size = len(key)
    #Create the AES cipher in ECB mode
    cipher = AES.new(key, AES.MODE_ECB)
    #decrypt the data
    decrypted_data = b""
    prev_cipher_block = iv
    for i in range(0, len(data), block_size):
        cipher_block = data[i:i+block_size]
        #decrypt the block
        XORed_block = cipher.decrypt(cipher_block)
        #XOR each byte of the block with each byte of the previous cipher block (IV for the first block)
        plain_block =  bytes([XORed_block[j] ^ prev_cipher_block[j] for j in range(block_size)])
        prev_cipher_block = cipher_block
        #XOR each byte of the block with each byte of the previous cipher block
        decrypted_data += plain_block   
    #Remove padding from the decrypted data
    plaintext_data = PKCS7_unpad(decrypted_data)
    return plaintext_data
     
#encrypt the image using AES in ECB or CBC mode
def encrypt_image(image_filename: str, mode: str, key: bytes, iv: bytes = 0) -> bytes:
    #seperate the header and data
    header = read_BMP_header(image_filename)
    data = read_image_data(image_filename)
    if(mode == "ECB"):
        cipher_text = ECB_encrypt(data, key)
        #create new file name
        output_filename = image_filename.replace(".bmp", "_ECB_encrypted.bmp")
        #write header and encrypted data to new file
        with open(output_filename, "wb") as file:
            file.write(header)
            file.write(cipher_text)
    elif(mode == "CBC"):
        cipher_text = CBC_encrypt(data, key, iv)
        #create new file name
        output_filename = image_filename.replace(".bmp", "_CBC_encrypted.bmp")
        #write header and encrypted data to new file
        with open(output_filename, "wb") as file:
            file.write(header)
            file.write(cipher_text)
    else:
        raise ValueError("Invalid mode")
    
#decrypt the image using AES in ECB or CBC mode
def decrypt_image(image_filename: str, mode: str, key: bytes, iv: bytes = 0) -> None:
    #seperate the header and data
    header = read_BMP_header(image_filename)
    data = read_image_data(image_filename)
    if(mode == "ECB"):
        plaintext = ECB_decrypt(data, key)
        #create new file name
        output_filename = image_filename.replace("_ECB_encrypted.bmp", "_ECB_decrypted.bmp")
        #write header, IV, and decrypted data to new file
        with open(output_filename, "wb") as file:
            file.write(header)
            file.write(plaintext)
    elif(mode == "CBC"):
        plaintext = CBC_decrypt(data, key, iv)
        #create new file name
        output_filename = image_filename.replace("_CBC_encrypted.bmp", "_CBC_decrypted.bmp")
        #write header, IV, and decrypted data to new file
        with open(output_filename, "wb") as file:
            file.write(header)
            file.write(plaintext)
    else:
        raise ValueError("Invalid mode") 

#----------------task 2 code---------------------

#encrypt text using AES in CBC mode
def submit(userdata: str, key: bytes, iv: bytes) -> bytes:  
    text = "userid=456; userdata=" + userdata + ";session-id=31337"
    #URL encode the text replacing '=' and ';' with their respective ASCII values
    encoded_text= text.replace(";", "%3B").replace("=", "%3D")
    #pad the text to a multiple of 16 bytes
    padded_text = PKCS7_pad(encoded_text.encode(), len(encoded_text.encode()))
    #encrypt the padded text using AES in CBC mode
    ciphertext = CBC_encrypt(padded_text, key, iv)
    return ciphertext

#decrypt text using AES in CBC mode
def verify(cipher_text: bytes, key: bytes, iv: bytes) -> bool:
    #Create the AES cipher in ECB mode
    cipher = AES.new(key, AES.MODE_CBC, iv)
    #decrypt the cipher text
    data = cipher.decrypt(cipher_text)
    #remove padding from the decrypted
    data = PKCS7_unpad(data)
    plaintext = data.decode()
    #extract the userdata from the plaintext
    if (";admin=true;" in plaintext):
        return True
    else:
        return False

#bit flipping attack to modify the ciphertext to inject the target string
def bit_flipping(ciphertext: str, key: bytes, target: str) -> bytes:
    block_size = len(key)
    #split the ciphertext into blocks
    blocks = []
    for i in range(0, len(ciphertext), block_size):
        blocks.append(ciphertext[i:i + block_size])
    #convert the target string to bytes
    target_bytes = target.encode()
    #find the block that contains the target string
    target_block_idx= 0
    for i in range(len(blocks)):
        if target_bytes in blocks[i]:
            target_block_idx = i
            break
    #Modify the preceding ciphertext block to inject the target
    modified_block = bytearray(blocks[target_block_idx - 1]) #bytearray makes it mutable
    
    for i in range(len(target_bytes)):
        target_char = target_bytes[i]
        #Replace with the correct byte
        original_char = ord(';') if i < len(";admin=true;") else 0
        #XOR with the difference  
        modified_block[i] ^= target_char ^ original_char 

    # Replace the modified block in the ciphertext
    blocks[target_block_idx - 1] = bytes(modified_block) 

    #Reassemble the modified ciphertext
    modified_ciphertext = b"".join(blocks)
    return modified_ciphertext


#----------------main code--------------------- 
# if __name__ == "__main__":
from cipher import *

#----------------task 1 execution---------------------
# key = get_random_bytes(16)
# iv = get_random_bytes(16)
# #cp-logo
# encrypt_image("cp-logo.bmp", "ECB", key)
# decrypt_image("cp-logo_ECB_encrypted.bmp", "ECB", key)
# encrypt_image("cp-logo.bmp", "CBC", key, iv)
# decrypt_image("cp-logo_CBC_encrypted.bmp", "CBC", key, iv)
# #mustang
# encrypt_image("mustang.bmp", "ECB", key)
# decrypt_image("mustang_ECB_encrypted.bmp", "ECB", key)
# encrypt_image("mustang.bmp", "CBC", key, iv)
# decrypt_image("mustang_CBC_encrypted.bmp", "CBC", key, iv)

# #----------------task 2 execution---------------------
# cipher_text = submit("You’re the man now, dog", key, iv)
# modified_cipher_text = bit_flipping(cipher_text, key, ";admin=true;")
# print(verify(cipher_text, key, iv))