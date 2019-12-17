import sys
import numpy as np
from BitVector import *
from PrimeGenerator import *
from solve_pRoot import *

public_key = 3

def gcd(a,b):
	while b:
		a,b = b,b%a
	return a

def encrypt(file_in, mod_n, file_out):
	input_bv = BitVector(filename = file_in)
	out = open(file_out, 'w')
	out_hex = open(file_out + 'hex', 'w')

	while input_bv.more_to_read:
		plaintext_bv = input_bv.read_bits_from_file(256)

		if plaintext_bv.length() < 128:
			#Append last block to make it 128 bits
			plaintext_bv.pad_from_right(128 - plaintext_bv.length())

		#Pad from left 128 bits to make 256 plaintext block
		plaintext_bv.pad_from_left(128)

		#raise to power of e (public_key)
		plaintext_num = int(plaintext_bv)
		cipher = pow(plaintext_num, public_key, mod_n)

		#write cipher block to file
		cipher_bv = BitVector(intVal = cipher, size = 256)
		cipher_ascii = cipher_bv.get_bitvector_in_ascii()
		out.write(cipher_ascii)
		out_hex.write(cipher_bv.get_bitvector_in_hex())

	out_hex.close()
	out.close()

def genRandom():
	primeGen = PrimeGenerator(bits=128, debug=0)

	isSatisfied = True
	while True:
		left_bit = BitVector(bitstring = '11')#For checking left two bits
		p = primeGen.findPrime()
		q = primeGen.findPrime()

		p_bv = BitVector(intVal = p)
		q_bv = BitVector(intVal = q)
		#Check left two most bets if set
		if q_bv[0:2] != left_bit or p_bv[0:2] != left_bit:
			isSatisfied = False

		if p == q:
			isSatisfied = False

		#Check for coprimality with publc key
		p_gcd_e = gcd(p - 1, public_key)
		q_gcd_e = gcd(q - 1, public_key)

		if p_gcd_e is 1 and q_gcd_e is 1:
			isSatisfied = False

		if isSatisfied is True:
			break
		else:
			isSatisfied = True
		#Return n for mod n arithmetic
        return p*q

def breakRSA(n1, n2, n3, file_out):
	out = open(file_out, 'w')
	#Convert each n to bitvector to find MI
	n1_bv = BitVector(intVal = n1)
	n2_bv = BitVector(intVal = n2)
	n3_bv = BitVector(intVal = n3)

	#Modulus for the chinese remainder theorem
	N = n1 * n2 * n3

	#Calculate necesssary constants and their bitvectors
	N1 = N / n1
	N2 = N / n2
	N3 = N / n3
	N1_bv = BitVector(intVal = N1)
	N2_bv = BitVector(intVal = N2)
	N3_bv = BitVector(intVal = N3)

	#Calculate the multiple inverse of each value above
	D1 = int(N1_bv.multiplicative_inverse(n1_bv))
	D2 = int(N2_bv.multiplicative_inverse(n2_bv))
	D3 = int(N3_bv.multiplicative_inverse(n3_bv))

	input_bv1 = BitVector(filename = 'encrypted_with_key_1.txt')
	input_bv2 = BitVector(filename = 'encrypted_with_key_2.txt')
	input_bv3 = BitVector(filename = 'encrypted_with_key_3.txt')
	while input_bv1.more_to_read and input_bv2.more_to_read and input_bv3.more_to_read:
		#Read 256 blocks from three different encrypted blocks
		C1 = input_bv1.read_bits_from_file(256).int_val()
		C2 = input_bv2.read_bits_from_file(256).int_val()
		C3 = input_bv3.read_bits_from_file(256).int_val()

		#Chinese remainder thm to get M^3
		x = ((C1 * N1 * D1) + (C2 * N2 * D2) + (C3 * N3 * D3)) % N

		#Take cube root
		M = solve_pRoot(3, x)

		#Convert to ascii and store
		plaintext_bv = BitVector(intVal = M, size = 256)
		out.write(plaintext_bv.get_bitvector_in_ascii())

if __name__ == "__main__":
	#Generate three random numbers
	n1 = genRandom()
	n2 = genRandom()
	n3 = genRandom()
	with open('ALLD.txt', 'w') as f:
		f.write(str(n1) + '\n')
		f.write(str(n2) + '\n')
		f.write(str(n3) + '\n')

	#Encrypt same message three different times with three different values of n
	encrypt(sys.argv[1], n1, 'encrypted_with_key_1.txt')
	encrypt(sys.argv[1], n2, 'encrypted_with_key_2.txt')
	encrypt(sys.argv[1], n3, 'encrypted_with_key_3.txt')

	breakRSA( n1, n2, n3, sys.argv[2])
