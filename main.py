from cipher import *

#----------------task 1 execution---------------------
key = get_random_bytes(16)
iv = get_random_bytes(16)
#cp-logo
encrypt_image("cp-logo.bmp", "ECB", key)
decrypt_image("cp-logo_ECB_encrypted.bmp", "ECB", key)
encrypt_image("cp-logo.bmp", "CBC", key, iv)
decrypt_image("cp-logo_CBC_encrypted.bmp", "CBC", key, iv)
#mustang
encrypt_image("mustang.bmp", "ECB", key)
decrypt_image("mustang_ECB_encrypted.bmp", "ECB", key)
encrypt_image("mustang.bmp", "CBC", key, iv)
decrypt_image("mustang_CBC_encrypted.bmp", "CBC", key, iv)

#----------------task 2 execution---------------------
cipher_text = submit("You’re the man now, dog", key, iv)
modified_cipher_text = bit_flipping(cipher_text, key, ";admin=true;")
print(verify(cipher_text, key, iv))