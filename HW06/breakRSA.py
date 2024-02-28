# Aubrey Gatewood 2/27/2024
import sys
from BitVector import *
import random
from math import gcd as bltingcd

class breakRSA():
    def __init__(self) -> None:
        self.e = 3
        

    def encrypt(self, message, enc1, enc2, enc3, n_1_2_3):
        # generate 3 sets of public and private keys with e = 3
        myRSA = RSA(3)
        with open(n_1_2_3, 'w') as f:
            myRSA.generate("p_test.txt", "q_test.txt")
            with open("p_test.txt", 'r') as f2:
                p = f2.read()
            with open ("q_test.txt", 'r') as f2:
                q = f2.read()
            myRSA.encrypt(message, enc1, p, q)
            n = int(p) * int(q)
            # f.write("n1: ")
            f.write(str(n))
            f.write("\n")

            myRSA.generate("p_test.txt", "q_test.txt")
            with open("p_test.txt", 'r') as f2:
                p = f2.read()
            with open ("q_test.txt", 'r') as f2:
                q = f2.read()
            myRSA.encrypt(message, enc2, p, q)
            n = int(p) * int(q)
            # f.write("n2: ")
            f.write(str(n))
            f.write("\n")

            myRSA.generate("p_test.txt", "q_test.txt")
            with open("p_test.txt", 'r') as f2:
                p = f2.read()
            with open ("q_test.txt", 'r') as f2:
                q = f2.read()
            myRSA.encrypt(message, enc3, p, q)
            n = int(p) * int(q)
            # f.write("n3: ")
            f.write(str(n))
            f.write("\n")
                
        

    def crack(self, enc1, enc2, enc3, n_1_2_3,  cracked):
        # given 3 ciphertexts and their public keys, recover original plaintext and write to a file
        Ni = []
        N = 1
        with open(n_1_2_3, 'r') as FILEIN:
            for line in FILEIN: 
                line = line.strip("\n")
                Ni.append(int(line))
                N *= int(line)
        # print("product of mods is: ", N)
        N1N2N3 = []
        Ni_inv = []
        for i,n in enumerate(Ni):
            N1N2N3.append(N // n) # this is N1, N2, N3 after division
            Ni_inv.append(int(BitVector(intVal = N1N2N3[i]).multiplicative_inverse(BitVector(intVal = n))))
        # need to read text files into bitvectors and read 256 bits at a time
        # read file contents, pass as hexstring to bitvectors, then use block size iterators to loop 
        # because we aren't using read_bits anymore 
        with open(enc1, 'r') as FILEIN:
            text1 = BitVector(hexstring = FILEIN.read())
        with open(enc2, 'r') as FILEIN:
            text2 = BitVector(hexstring = FILEIN.read())
        with open(enc3, 'r') as FILEIN:
            text3 = BitVector(hexstring = FILEIN.read())
        startblock = 0
        endblock = 256
        currBlock = 0
        lastBlock = text1.size // 256
        with open(cracked, 'w') as FILEOUT: 
            while (currBlock < lastBlock): # enc1-3 should all be same length exactly
                chunk1 = text1[startblock:endblock]
                chunk2 = text2[startblock:endblock]
                chunk3 = text3[startblock:endblock]
                chunk1 = chunk1.int_val() * N1N2N3[0] * Ni_inv[0]
                chunk2 = chunk2.int_val() * N1N2N3[1] * Ni_inv[1]
                chunk3 = chunk3.int_val() * N1N2N3[2] * Ni_inv[2]
                M3 = (chunk1 + chunk2 + chunk3) % N
                M3 = self.solve_pRoot(3, M3)
                final = BitVector(intVal = M3,size =128)
                # print(final.get_bitvector_in_ascii())
                FILEOUT.write(final.get_bitvector_in_ascii())
                startblock += 256
                endblock += 256
                currBlock += 1


    def MI(self, num, mod):
        '''
        This function uses ordinary integer arithmetic implementation of the
        Extended Euclid's Algorithm to find the MI of the first-arg integer
        vis-a-vis the second-arg integer.
        '''
        NUM = num; MOD = mod
        x, x_old = 0, 1
        y, y_old = 1, 0
        while mod:
            q = num // mod
            num, mod = mod, num % mod
            x, x_old = x_old - q * x, x
            y, y_old = y_old - q * y, y
        if num != 1:
            print("\nNO MI. However, the GCD of %d and %d is %u\n" % (NUM, MOD, num))
        else:
            MI = (x_old + MOD) % MOD
            print("\nMI of %d modulo %d is: %d\n" % (NUM, MOD, MI))
            return MI

    def solve_pRoot(self, p, x): 
        '''
        Implement binary search to find the pth root of x. The logic is as follows:
        1). Initialize upper bound to 1
        2). while u^p <= x, increment u by itself
        3). Intialize lower bound to u//2
        4). While the lower bound is smaller than the upper bound:
            a). Compute the midpoint as (lower + upper) / 2
            b). Exponentiate the midpoint by p
            c). if lower bound < midpoint and midpoint < x, then set the new lower bound to midpoint
            d). else if upperbown > midpoint and midpoint > x, then set the new upper bown to midpoint
            e). else return the midpoint
        5). If while loop breaks before returning, return midpoint + 1

        Author: Joseph Wang
            wang3450 at purdue edu

        '''

        u = 1
        while u ** p <= x: u *= 2

        l = u // 2
        while l < u:
            mid = (l + u) // 2
            mid_pth = mid ** p
            if l < mid and mid_pth < x:
                l = mid
            elif u > mid and mid_pth > x:
                u = mid
            else:
                return mid
        return mid + 1

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


        

    def encrypt(self, plaintext:str, ciphertext:str, p, q) -> None:
        # always pad from right, don't pad from left because it doesn't work
        self.q = q
        self.p = p
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
        with open(sys.argv[4], 'r') as f:
            self.q=f.read()
        with open(sys.argv[3], 'r') as f:
            self.p=f.read()
        n = int(self.p) * int(self.q)
        d = pow(self.e, -1, ((int(self.p)-1)*(int(self.q)-1))) # d = e^-1 * (p-1)*(q-1)
        with open(ciphertext, 'r') as f:
            tempstring = f.read()
        bv = BitVector(hexstring = tempstring)
        with open("temp.txt", 'wb') as f:
            bv.write_to_file(f)
        cipherbv = BitVector(filename='temp.txt')
        with open(recovered_plaintext, 'w') as f:
            while (cipherbv.more_to_read):
                cipherchunk = cipherbv.read_bits_from_file(256)
                # no padding
                cipherchunk = pow(cipherchunk.intValue(), d, n) # M = C^d % n
                outchunk = BitVector(intVal = cipherchunk, size = 128)
                f.write(outchunk.get_bitvector_in_ascii())

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
    breaker = breakRSA()
    if sys.argv[1] == "-e":
        breaker.encrypt(message=sys.argv[2], enc1=sys.argv[3], enc2=sys.argv[4], enc3=sys.argv[5], n_1_2_3=sys.argv[6])
    elif sys.argv[1] == "-c":
        breaker.crack(enc1=sys.argv[2], enc2=sys.argv[3], enc3=sys.argv[4], n_1_2_3=sys.argv[5], cracked=sys.argv[6])
    else:
        print("wrong argument format")
