#!/usr/bin/env python

'''
Homework: #7, SHA-512
Name: Dhruv Gowd
ECN Login: dgowd
Due Date: 3/7/19
'''
import hashlib
import sys
from BitVector import *

def sha512(bv, file_out):
    #The eight 64 bit msg_schedule for initializing the hash buffer
    h0 = BitVector(hexstring='6a09e667f3bcc908')
    h1 = BitVector(hexstring='bb67ae8584caa73b')
    h2 = BitVector(hexstring='3c6ef372fe94f82b')
    h3 = BitVector(hexstring='a54ff53a5f1d36f1')
    h4 = BitVector(hexstring='510e527fade682d1')
    h5 = BitVector(hexstring='9b05688c2b3e6c1f')
    h6 = BitVector(hexstring='1f83d9abfb41bd6b')
    h7 = BitVector(hexstring='5be0cd19137e2179')

    #Values of K for round constants
    k = ["428a2f98d728ae22", "7137449123ef65cd", "b5c0fbcfec4d3b2f", "e9b5dba58189dbbc",
        "3956c25bf348b538", "59f111f1b605d019", "923f82a4af194f9b", "ab1c5ed5da6d8118",
        "d807aa98a3030242", "12835b0145706fbe", "243185be4ee4b28c", "550c7dc3d5ffb4e2",
        "72be5d74f27b896f", "80deb1fe3b1696b1", "9bdc06a725c71235", "c19bf174cf692694",
        "e49b69c19ef14ad2", "efbe4786384f25e3", "0fc19dc68b8cd5b5", "240ca1cc77ac9c65",
        "2de92c6f592b0275", "4a7484aa6ea6e483", "5cb0a9dcbd41fbd4", "76f988da831153b5",
        "983e5152ee66dfab", "a831c66d2db43210", "b00327c898fb213f", "bf597fc7beef0ee4",
        "c6e00bf33da88fc2", "d5a79147930aa725", "06ca6351e003826f", "142929670a0e6e70",
        "27b70a8546d22ffc", "2e1b21385c26c926", "4d2c6dfc5ac42aed", "53380d139d95b3df",
        "650a73548baf63de", "766a0abb3c77b2a8", "81c2c92e47edaee6", "92722c851482353b",
        "a2bfe8a14cf10364", "a81a664bbc423001", "c24b8b70d0f89791", "c76c51a30654be30",
        "d192e819d6ef5218", "d69906245565a910", "f40e35855771202a", "106aa07032bbd1b8",
        "19a4c116b8d2d0c8", "1e376c085141ab53", "2748774cdf8eeb99", "34b0bcb5e19b48a8",
        "391c0cb3c5c95a63", "4ed8aa4ae3418acb", "5b9cca4f7763e373", "682e6ff3d6b2b8a3",
        "748f82ee5defb2fc", "78a5636f43172f60", "84c87814a1f0ab72", "8cc702081a6439ec",
        "90befffa23631e28", "a4506cebde82bde9", "bef9a3f7b2c67915", "c67178f2e372532b",
        "ca273eceea26619c", "d186b8c721c0c207", "eada7dd6cde0eb1e", "f57d4f7fee6ed178",
        "06f067aa72176fba", "0a637dc5a2c898a6", "113f9804bef90dae", "1b710b35131c471b",
        "28db77f523047d84", "32caab7b40c72493", "3c9ebe0a15c9bebc", "431d67c49c100d4c",
        "4cc5d4becb3e42b6", "597f299cfc657e2a", "5fcb6fab3ad6faec", "6c44198c4a475817"]

    #Converting the table above to an array of BitVectors
    k_bv = [BitVector(hexstring = k_constant) for k_constant in k]

    #Step 1 pad the message with zeros and length of message
    bv = BitVector(textstring = plaintext)
    bv1 = bv + BitVector(bitstring="1") #Constant one to add to the plaintext in case of empty message
    zerolist = [0] * ((896 - bv1.length()) % 1024)
    #Final message is 1 added to original message + zeros + the size of message
    message_to_hash_bv = bv1 + BitVector(bitlist = zerolist) + BitVector(intVal =  bv.length(), size = 128)

    #Allocate space for the message schedule
    msg_schedule = [None] * 80

    length_message = message_to_hash_bv.length()
    for x in range(0,length_message, 1024):
        block = message_to_hash_bv[x:x+1024]

        #Step 2, generate the hash buffer and message schedule
        #These are message schedule words 0 through 15
        msg_schedule[0:16] = [block[i:i+64] for i in range(0,1024,64)]

        #Generate msg_schedule 16 through 80 from previous word values
        for j in range (16, 80):
            w_minus_2 = msg_schedule[j-2]
            w_minus_15 = msg_schedule[j-15]

            sig0 = (w_minus_15.deep_copy()>>1) ^ (w_minus_15.deep_copy()>>8) ^ (w_minus_15.deep_copy().shift_right(7))
            sig1 = (w_minus_2.deep_copy()>>19) ^ (w_minus_2.deep_copy()>>61) ^ (w_minus_2.deep_copy().shift_right(6))
            new_msg_val = (int(msg_schedule[j-16]) + int(sig1) + int(msg_schedule[j-7]) + int(sig0)) % (2**64)
            msg_schedule[j] = BitVector(intVal= (new_msg_val), size=64)

        #temporary storage of hash buffer
        a,b,c,d,e,f,g,h = h0,h1,h2,h3,h4,h5,h6,h7
        #Round Based processing
        for k in range(80):
            ch = (e & f) ^ (~e & g)
            maj = (a & b) ^ (a & c) ^ (b & c)
            sum_a = (a.deep_copy() >> 28) ^ (a.deep_copy() >> 34) ^ (a.deep_copy() >> 39)
            sum_e = (e.deep_copy() >> 14) ^ (e.deep_copy() >> 18) ^ (e.deep_copy() >> 41)
            new_t1 = (int(h) + int(ch) + int(sum_e) + int(msg_schedule[k]) + int(k_bv[k])) % (2**64)
            t1 = BitVector(intVal = new_t1, size=64)
            new_t2 = (int(sum_a) + int(maj)) % (2**64)
            t2 = BitVector(intVal = new_t2, size=64)
            h = g
            g = f
            f = e
            d_plus_t1 = (int(d) + int(t1)) % (2**64)
            e = BitVector(intVal = d_plus_t1 , size=64)
            d = c
            c = b
            b = a
            t1_plus_t2 = (int(t1) + int(t2)) % (2**64)
            a = BitVector(intVal = t1_plus_t2 , size=64)

        #Updating the conent of the hash buffer
        new_h0 = (int(h0) + int(a)) % (2**64)
        h0 = BitVector( intVal = new_h0 , size=64 )

        new_h1 = (int(h1) + int(b)) % (2**64)
        h1 = BitVector( intVal = new_h1 , size=64 )

        new_h2 = (int(h2) + int(c)) % (2**64)
        h2 = BitVector( intVal = new_h2 , size=64 )

        new_h3 = (int(h3) + int(d)) % (2**64)
        h3 = BitVector( intVal = new_h3, size=64 )

        new_h4 = (int(h4) + int(e)) % (2**64)
        h4 = BitVector( intVal = new_h4, size=64 )

        new_h5 = (int(h5) + int(f)) % (2**64)
        h5 = BitVector( intVal = new_h5, size=64 )

        new_h6 = (int(h6) + int(g)) % (2**64)
        h6 = BitVector( intVal = new_h6, size=64 )

        new_h7 = (int(h7) + int(h)) % (2**64)
        h7 = BitVector( intVal = new_h7, size=64 )

    #Concatonating the final hashed message
    hashed_message_bv = h0 + h1 + h2 + h3 + h4 + h5 + h6 + h7
    with open(file_out, 'w') as f:
        f.write(hashed_message_bv.getHexStringFromBitVector())


if __name__ == "__main__":
    #get the entire message
    with open(sys.argv[1]) as f:
        plaintext = f.read()

    sha512(plaintext, sys.argv[2])
