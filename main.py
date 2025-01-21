from cipher import *

key = generate_aes_key(16)
iv = get_random_bytes(16)
encrypt_image("cp-logo.bmp", "ECB", key)
decrypt_image("cp-logo_ECB_encrypted.bmp", "ECB", key)
encrypt_image("cp-logo.bmp", "CBC", key, iv)
decrypt_image("cp-logo_CBC_encrypted.bmp", "CBC", key, iv)
# cipher_text = submit("You’re the man now, dog", key, iv)
# print(verify(cipher_text, key, iv))