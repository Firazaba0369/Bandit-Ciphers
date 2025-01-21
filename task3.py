import matplotlib.pyplot as plt

block_size = [16, 64, 256, 1024, 8192, 16384]
aes128 = [649849, 951141, 957307, 1007677, 1099639, 955781] # information received from command
aes192 = [572196, 805719, 951987, 809436, 847456, 788287.41]
aes256 = [536159, 692645, 694165, 706547, 708267, 706517]


plt.plot(block_size, aes128, label='AES-128') # plot format
plt.plot(block_size, aes192, label='AES-192')
plt.plot(block_size, aes256, label='AES-256')
plt.xlabel('Block Size (bytes)')
plt.ylabel('Throughput (bytes/sec)')
plt.title('AES Performance: Block Size vs Throughput')
plt.legend()
plt.show()


rsa_size = [512, 1024, 2048, 3072, 4096, 7680, 15360]
rsa_sign = [21685, 7059.6, 1082, 340, 142, 15, 2] # information received from command
rsa_verify = [321193, 121743, 36561, 15231, 8590, 2525, 671]

plt.plot(rsa_size, rsa_sign, label='Signing') # plot format
plt.plot(rsa_size, rsa_verify, label='Verifying')
plt.xlabel('Key Size (bits)')
plt.ylabel('Throughput (operations/sec)')
plt.title('RSA Performance: Key Size vs Throughput')
plt.legend()
plt.show()
