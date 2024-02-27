# Aubrey Gatewood 2/26/2024
import sys
import random
from math import gcd as bltingcd
# from math import pow
from BitVector import *


class RSA(): 
    def __init__(self, e) -> None:
        self.e = e
        self.n = None
        self.d = None
        self.p = None
        self.q = None
        

    def generate(self, p_text:str, q_text:str) -> None:
        '''
        write p and q to p.txt and q.txt, 
        should be integers represented in ascii
        '''
        generator = PrimeGenerator(bits = 128)
        check = 1
        while(check):
            self.p = generator.findPrime()
            self.q = generator.findPrime()
            # print(self.p)
            # print(self.q)
            check = 0
            # if p == q go again
            if (self.p == self.q):
                check = 1
                print("equality")
                continue
            # go again if leftmost 2 bits of p and q aren't set
            leftmost_p = (self.p >> 126) & 0b11
            leftmost_q = (self.q >> 126) & 0b11
            # print("leftmost p: ", leftmost_p)
            # print("leftmost q: ", leftmost_q)
            if (leftmost_p == 0 or leftmost_q == 0):
                check = 1
                print("leftmost bits")
                continue
            # go again if either p-1 or q-1 isn't coprime to e (e=65537)
            # print("p is: ", self.p, "\n and q is: ", self.q)
            p_test = self.test_coprime((self.p-1), self.e)
            q_test = self.test_coprime((self.q-1), self.e)
            if (p_test == 0 or q_test == 0):
                # print("one of them was 0")
                check = 1
        with open(p_text, 'w') as f:
            f.write(str(self.p))
        with open(q_text, 'w') as f:
            f.write(str(self.q))
            
    def test_coprime(self, num1:int, num2:int):
        if (bltingcd(num1, num2) == 1):
            # print("returning 1")
            return 1 # coprime
        else:
            return 0 # not coprime


        

    def encrypt(self, plaintext:str, ciphertext:str) -> None:
        # always pad from right, don't pad from left because it doesn't work
        with open(sys.argv[4], 'r') as f:
            self.q = f.read()
        with open (sys.argv[3], 'r') as f:
            self.p = f.read()
        n = int(self.q) * int(self.p) # this is the mod
        plainbv = BitVector(filename = plaintext)
        with open(ciphertext, 'w') as f:
            while (plainbv.more_to_read):
                plainchunk = plainbv.read_bits_from_file(128)
                plainchunk.pad_from_left(128) # this is prepending right? 
                if (plainchunk.size < 256):
                    plainchunk.pad_from_right(256 - plainchunk.size) # for when its less than 256 bits
                plainchunk = pow(plainchunk.intValue(), self.e, n)
                outchunk = BitVector(intVal = plainchunk, size = 256)
                f.write(outchunk.get_bitvector_in_hex())
            

    def decrypt(self, ciphertext:str, recovered_plaintext:str) -> None:
        pass

class PrimeGenerator( object ):                                              #(A1)

    def __init__( self, **kwargs ):                                          #(A2)
        bits = debug = None                                                  #(A3)
        if 'bits' in kwargs  :     bits = kwargs.pop('bits')                 #(A4)
        if 'debug' in kwargs :     debug = kwargs.pop('debug')               #(A5)
        self.bits            =     bits                                      #(A6)
        self.debug           =     debug                                     #(A7)
        self._largest        =     (1 << bits) - 1                           #(A8)

    def set_initial_candidate(self):                                         #(B1)
        candidate = random.getrandbits( self.bits )                          #(B2)
        if candidate & 1 == 0: candidate += 1                                #(B3)
        candidate |= (1 << self.bits-1)                                      #(B4)
        candidate |= (2 << self.bits-3)                                      #(B5)
        self.candidate = candidate                                           #(B6)

    def set_probes(self):                                                    #(C1)
        self.probes = [2,3,5,7,11,13,17]                                     #(C2)

    # This is the same primality testing function as shown earlier
    # in Section 11.5.6 of Lecture 11:
    def test_candidate_for_prime(self):                                      #(D1)
        'returns the probability if candidate is prime with high probability'
        p = self.candidate                                                   #(D2)
        if p == 1: return 0                                                  #(D3)
        if p in self.probes:                                                 #(D4)
            self.probability_of_prime = 1                                    #(D5)
            return 1                                                         #(D6)
        if any([p % a == 0 for a in self.probes]): return 0                  #(D7)
        k, q = 0, self.candidate-1                                           #(D8)
        while not q&1:                                                       #(D9)
            q >>= 1                                                          #(D10)
            k += 1                                                           #(D11)
        if self.debug: print("q = %d  k = %d" % (q,k))                       #(D12)
        for a in self.probes:                                                #(D13)
            a_raised_to_q = pow(a, q, p)                                     #(D14)
            if a_raised_to_q == 1 or a_raised_to_q == p-1: continue          #(D15)
            a_raised_to_jq = a_raised_to_q                                   #(D16)
            primeflag = 0                                                    #(D17)
            for j in range(k-1):                                             #(D18)
                a_raised_to_jq = pow(a_raised_to_jq, 2, p)                   #(D19)
                if a_raised_to_jq == p-1:                                    #(D20)
                    primeflag = 1                                            #(D21)
                    break                                                    #(D22)
            if not primeflag: return 0                                       #(D23)
        self.probability_of_prime = 1 - 1.0/(4 ** len(self.probes))          #(D24)
        return self.probability_of_prime                                     #(D25)

    def findPrime(self):                                                     #(E1)
        self.set_initial_candidate()                                         #(E2)
        if self.debug:  print("    candidate is: %d" % self.candidate)       #(E3)
        self.set_probes()                                                    #(E4)
        if self.debug:  print("    The probes are: %s" % str(self.probes))   #(E5)
        max_reached = 0                                                      #(E6)
        while 1:                                                             #(E7)
            if self.test_candidate_for_prime():                              #(E8)
                if self.debug:                                               #(E9)
                    print("Prime number: %d with probability %f\n" %       
                          (self.candidate, self.probability_of_prime) )      #(E10)
                break                                                        #(E11)
            else:                                                            #(E12)
                if max_reached:                                              #(E13)
                    self.candidate -= 2                                      #(E14)
                elif self.candidate >= self._largest - 2:                    #(E15)
                    max_reached = 1                                          #(E16)
                    self.candidate -= 2                                      #(E17)
                else:                                                        #(E18)
                    self.candidate += 2                                      #(E19)
                if self.debug:                                               #(E20)
                    print("    candidate is: %d" % self.candidate)           #(E21)
        return self.candidate  
    
if __name__ == "__main__":
    cipher = RSA(e=65537)
    # try: 
    if sys.argv[1] == "-e":
        cipher.encrypt(plaintext=sys.argv[2], ciphertext=sys.argv[5])
    elif sys.argv[1] == "-d":
        cipher.decrypt(ciphertext=sys.argv[2], recovered_plaintext=sys.argv[5])
    elif sys.argv[1] == "-g":
        cipher.generate(p_text=sys.argv[2], q_text=sys.argv[3])
    # except Exception as e:
    #     print(f"Error given was: {e}")
    #     print("Call should be one of these forms: \npython RSA.py -g p.txt q.txt \npython RSA.py -e message.txt p.txt q.txt encrypted.txt \npython RSA.py -d encrypted.txt p.txt q.txt decrypted.txt")