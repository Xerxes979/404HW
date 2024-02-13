#Aubrey Gatewood 1/17/24
import sys
from BitVector import *

def cryptBreak(ciphertextFile, key_bv):
    #ciphertextFile is a string that contains the filename of the ciphertext
    #key_bv is 16-bit BitVector for decryption key
    #decrypts for a single key
    PassPhrase = "Hopes and dreams of a million years"                          #(C)

    #pulling code from DecryptForFun from lecture notes
    BLOCKSIZE = 16 #changed to 16 from 64                                       #(D)
    numbytes = BLOCKSIZE // 8 

    # Reduce the passphrase to a bit array of size BLOCKSIZE:
    bv_iv = BitVector(bitlist = [0]*BLOCKSIZE)                                  #(F)
    for i in range(0,len(PassPhrase) // numbytes):                              #(G)
        textstr = PassPhrase[i*numbytes:(i+1)*numbytes]                         #(H)
        bv_iv ^= BitVector( textstring = textstr )                              #(I)

    # Create a bitvector from the ciphertext hex string:
    FILE = open(ciphertextFile)                                               #(J)
    encrypted_bv = BitVector( hexstring = FILE.read() )                       #(K)

    # key = key_bv #from function input

    # Reduce the key to a bit array of size BLOCKSIZE:
    # key_bv = BitVector(intVal = key)                                 #(P)
    # for i in range(0,len(key) // numbytes):                                     #(Q)
    #     keyblock = key[i*numbytes:(i+1)*numbytes]                               #(R)
    #     key_bv ^= BitVector( textstring = keyblock )                            #(S)

    # Create a bitvector for storing the decrypted plaintext bit array:
    msg_decrypted_bv = BitVector( size = 0 )                                    #(T)

    # Carry out differential XORing of bit blocks and decryption:
    previous_decrypted_block = bv_iv                                            #(U)
    for i in range(0, len(encrypted_bv) // BLOCKSIZE):                          #(V)
        bv = encrypted_bv[i*BLOCKSIZE:(i+1)*BLOCKSIZE]                          #(W)
        temp = bv.deep_copy()                                                   #(X)
        bv ^=  previous_decrypted_block                                         #(Y)
        previous_decrypted_block = temp                                         #(Z)
        bv ^=  key_bv                                                           #(a)
        msg_decrypted_bv += bv                                                  #(b)

    # Extract plaintext from the decrypted bitvector:    
    outputtext = msg_decrypted_bv.get_text_from_bitvector()                     #(c)
    # print(key_bv)
    # print(outputtext)
    # Write plaintext to the output file:
    # FILEOUT = open("recover.txt", 'w')                                            #(d)
    # FILEOUT.write(outputtext)                                                   #(e)
    # FILEOUT.close()                                                             #(f)
    return outputtext
