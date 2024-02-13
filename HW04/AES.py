# Aubrey Gatewood 2/12/2024

import sys
from BitVector import *
import numpy as np

class AES():
    # class constructor - when making an AES object, the class's constructor 
    # is executed and instance vars are initialized
    def __init__(self, keyfile:str) -> None:
        self.keyfile = keyfile
    
        self.AES_modulus = BitVector(bitstring='100011011')
        self.num_rounds = 14
        self.subBytesTable = self.gen_subbytes_table()

    def gen_subbytes_table(self):
        subBytesTable = []
        c = BitVector(bitstring='01100011')
        for i in range(0, 256):
            a = BitVector(intVal = i, size=8).gf_MI(self.AES_modulus, 8) if i != 0 else BitVector(intVal=0)
            a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
            a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
            subBytesTable.append(int(a))
        return subBytesTable
    
    def gee(self, keyword, round_constant, byte_sub_table):
        '''
        This is the g() function you see in Figure 4 of Lecture 8.
        '''
        rotated_word = keyword.deep_copy()
        rotated_word << 8
        newword = BitVector(size = 0)
        for i in range(4):
            newword += BitVector(intVal = byte_sub_table[rotated_word[8*i:8*i+8].intValue()], size = 8)
        newword[:8] ^= round_constant
        round_constant = round_constant.gf_multiply_modular(BitVector(intVal = 0x02), self.AES_modulus, 8)
        return newword, round_constant

    def gen_key_schedule_256(self, key_bv):
        byte_sub_table = self.gen_subbytes_table()
        #  We need 60 keywords (each keyword consists of 32 bits) in the key schedule for
        #  256 bit AES. The 256-bit AES uses the first four keywords to xor the input
        #  block with.  Subsequently, each of the 14 rounds uses 4 keywords from the key
        #  schedule. We will store all 60 keywords in the following list:
        key_words = [None for i in range(60)]
        round_constant = BitVector(intVal = 0x01, size=8)
        for i in range(8):
            key_words[i] = key_bv[i*32 : i*32 + 32]
        for i in range(8,60):
            if i%8 == 0:
                kwd, round_constant = self.gee(key_words[i-1], round_constant, byte_sub_table)
                key_words[i] = key_words[i-8] ^ kwd
            elif (i - (i//8)*8) < 4:
                key_words[i] = key_words[i-8] ^ key_words[i-1]
            elif (i - (i//8)*8) == 4:
                key_words[i] = BitVector(size = 0)
                for j in range(4):
                    key_words[i] += BitVector(intVal = 
                                    byte_sub_table[key_words[i-1][8*j:8*j+8].intValue()], size = 8)
                key_words[i] ^= key_words[i-8] 
            elif ((i - (i//8)*8) > 4) and ((i - (i//8)*8) < 8):
                key_words[i] = key_words[i-8] ^ key_words[i-1]
            else:
                sys.exit("error in key scheduling algo for i = %d" % i)
        return key_words

    def print_st_ar(self, statearray):
        for i in range(4):
            sys.stdout.write("\n\n")
            for j in range(4):
                sys.stdout.write( str(BitVector.get_hex_string_from_bitvector(statearray[i][j])) )
                sys.stdout.write("\t")
        sys.stdout.write("\n\n")
    # encrypt - method performs AES encryption on the plaintext and writes 
    # ciphertext to disk
        # inputs: plaintext (str) - filename containing plaintext
        #         ciphertext (str) - filename containing ciphertext
    # return void
    def encrypt(self, plaintext:str, ciphertext:str) -> None:
        self.plainfile = plaintext
        self.cipherfile = ciphertext

        # getting key schedule
        # print("file name is: ", self.keyfile)
        with open(self.keyfile, 'r') as f:
            textkey = f.read()
        keyVec = BitVector(textstring = textkey)
        # print("keyvec is: ", keyVec)
        key_words = self.gen_key_schedule_256(keyVec)
        round_keys = [None for i in range(self.num_rounds+1)]
        for i in range(0, self.num_rounds+1):
            round_keys[i] = (key_words[i*4] + key_words[i*4+1] + key_words[i*4+2] + key_words[i*4+3])
        
        # getting blocks of plaintext as hex
        bitPlaintext = BitVector(filename = plaintext)
        print(bitPlaintext.get_bitvector_in_hex())

        # make state array
        statearray = [[0 for x in range(4)] for x in range(4)]
        temparray = [[0 for x in range(4)] for x in range(4)]
        

        colsarray = [[0x2,0x3,0x1,0x1],
                     [0x1,0x2,0x3,0x1],
                     [0x1,0x1,0x2,0x3],
                     [0x3,0x1,0x1,0x2]]
        tempstring = ''
        while (bitPlaintext.more_to_read):
            bitvec = bitPlaintext.read_bits_from_file(128)
            if bitvec.size < 128:
                bitvec.pad_from_right(128 - (bitvec.size % 128))
            chunk = bitvec ^ round_keys[0]
            for i in range (4):
                for j in range (4):
                    statearray[j][i] = chunk[32*i + 8*j:32*i + 8*(j+1)]
        
            for currentround in range(14):
                # print(bitvec.get_hex_string_from_bitvector())
                # print(chunk.get_bitvector_in_hex())
                # 2. The first block of plaintext after XOR with the first 4 words of the key schedule#######################################################################
                # 22041908164e1d175f1a1a0e1d110c45
                for i in range (4):
                    for j in range (4):
                        # statearray[i][j] = self.subBytesTable[statearray[i][j]]
                        bitvec_index = statearray[i][j].intValue()  # Convert the bitvector to an integer index
                        statearray[i][j] = self.subBytesTable[bitvec_index]  # Use the integer index to access subBytesTable
                
                # 3. The first block of plaintext after performing the Sub Bytes Step in round 1:######################################################################## 
                # 93f2d430472fa4f0cfa2a2aba482fe6e
                
                
                statearray[1] = np.roll(statearray[1], -1)
                statearray[2] = np.roll(statearray[2], -2)
                statearray[3] = np.roll(statearray[3], -3)

                for i in range (4):
                    for j in range (4):
                        # print(hex(statearray[j][i]))
                        temparray[i][j] = statearray[j][i] # transposing
                statearray = temparray
                # for i in range (4):
                #     for j in range (4):
                #         print(hex(statearray[i][j]))                    

                # 4. The first block of plaintext after performing the Row Shift Step in round 1:###################################################################################
                # 932fa26e47a2fe30cf82d4f0a4f2a4ab


                # convert back to a bitvector because I messed it up and converted to np
                newBitVec = BitVector(size=0)
                for row in statearray:
                    for element in row:
                        element_bv = BitVector(intVal=element, size=8)
                        newBitVec += element_bv
                for i in range(4):
                    for j in range(4):
                        statearray[j][i] = newBitVec[32*i + 8*j:32*i + 8*(j+1)]
                # self.print_st_ar(statearray)
                # print(newBitVec.get_bitvector_in_hex())

                # print(type(newBitVec), newBitVec)
                # print(type(colsarray), colsarray)
                if (currentround != 13):

                    # mix columns 
                    for i in range(4):
                        for j in range(4):
                            column = newBitVec[i*32:(i+1)*32]
                            # Perform the MixColumns operation for each byte in the column
                            temparray[j][i] = column[0:8].gf_multiply_modular(BitVector(intVal=colsarray[j][0], size=8), self.AES_modulus, 8) ^ \
                                            column[8:16].gf_multiply_modular(BitVector(intVal=colsarray[j][1], size=8), self.AES_modulus, 8) ^ \
                                            column[16:24].gf_multiply_modular(BitVector(intVal=colsarray[j][2], size=8), self.AES_modulus, 8) ^ \
                                            column[24:32].gf_multiply_modular(BitVector(intVal=colsarray[j][3], size=8), self.AES_modulus, 8)
                            # ... and so on for the other rows
                    
                statearray = [[temparray[j][i] for j in range(4)] for i in range(4)]


                state_bv = BitVector(size=0)
                for row in statearray:
                    for bitvec in row:
                        # print(bitvec.get_hex_string_from_bitvector(), end=' ')
                        state_bv += bitvec
                    # print()  # Creates a new line after each row for better readability
                
                # 5. The first block of plaintext after performing the Mix Columns Step in round 1:###############################################################################
                # 805e51ffbd3152f53c47f5e75107e3ec
                round_key = round_keys[currentround + 1]

                state_bv ^= round_key
                # statearray = state_bv
                for i in range (4):
                    for j in range (4):
                        statearray[j][i] = state_bv[32*i + 8*j:32*i + 8*(j+1)]
            print("round ", currentround, "output: ", state_bv.get_hex_string_from_bitvector())
            tempstring += state_bv.get_hex_string_from_bitvector()

                # break
            print(tempstring)
            # break
        
        with open(ciphertext, 'w') as f:
            f.write(tempstring)





    #decrypt - method performs AES decryption on the ciphertext and writes plaintext to disk
    # inputs: ciphertext (str) - filename containing ciphertext
    #         decrypted (str) - filename containing recovered plaintext
    # return void
    def decrypt(self, ciphertext:str, decrypted:str) -> None:
        self.cipherfile = ciphertext
        self.decryptfile = decrypted
        # open the file like we opened DES decrypt file
        
        # get key schedule, get round keys
            
        # have to reverse the round keys
        # continue as in encryption
        # in while loop, its the same until the inverse shift rows (right instead of left)
        # inverse sub bytes, same call except use inversesubbytestable
        # add round key same way
        # do inverse mix columns, almost the same except we change the matrix (see in document)









if __name__ == "__main__":
    cipher = AES(keyfile = sys.argv[3])

    if sys.argv[1] == "-e":
        cipher.encrypt(plaintext = sys.argv[2], ciphertext=sys.argv[4])
    elif sys.argv[1] == "-d":
        cipher.decrypt(ciphertext=sys.argv[2], decrypted=sys.argv[4])
    else:
        sys.exit("Incorrect Command-Line Syntax")
