#aubrey gatewood 1-17-24

from cryptBreak import cryptBreak
from BitVector import *
RandomInteger = 9999 #arbitrary int for creating a bitvector
for i in range(1600, 1700): #for demonstration purposes
# for i in range(0,65536): #original testing range
    key_bv = BitVector(intVal = i, size=16)
    decryptedMessage = cryptBreak('encrypted.txt', key_bv)
    if 'Ferrari' in decryptedMessage:
        print('Encryption Broken!')
        print(i, " is the key")
        print('decrypted message is: ', decryptedMessage)
        break
    else:
        print('Not decrypted yet')