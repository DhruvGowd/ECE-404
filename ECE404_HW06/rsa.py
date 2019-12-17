import sys
from BitVector import *
from PrimeGenerator import *

def gcd(a,b):
	while b:
		a,b = b,b%a
	return a

public_key = 65537
public_key_bv = BitVector(intVal = public_key)

def encrypt(file_in, mod_n, file_out):
	input_bv = BitVector(filename = file_in)
	out = open(file_out, 'w')
	out_hex = open('encrypted_hex.txt', 'w')

	while input_bv.more_to_read:
		plaintext_bv = input_bv.read_bits_from_file(128)

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
		print cipher_bv.length()

	out_hex.close()
	out.close()

def decrypt(file_in, p, q, d, file_out):
	out = open(file_out, 'w')
	n = q * p
	#Make bitvector for p, q, and d
	q_bv = BitVector(intVal = q)
	p_bv = BitVector(intVal = p)
	d_bv = BitVector(intVal = d, size = 256)

	#Find MI of q in mod p
	MI_p_in_q = p_bv.multiplicative_inverse(q_bv)
	MI_q_in_p = q_bv.multiplicative_inverse(p_bv)

	#Calculate X_p and X_q
	X_p = q * int(MI_q_in_p)
	X_q  = p * int(MI_p_in_q)

	input_bv = BitVector(filename = file_in)
	check = BitVector(filename = 'encrypted_hex.txt')
	while input_bv.more_to_read:
		cipher_bv = input_bv.read_bits_from_file(256)
		cipher_hex = check.read_bits_from_file(256)
		#Calculate V_p and V_q
	 	V_p = pow(int(cipher_bv.get_bitvector_in_hex(), 16), d, p)
		V_q = pow(int(cipher_bv.get_bitvector_in_hex(), 16), d, q)

		V_p_hex = pow(int(cipher_hex.get_bitvector_in_ascii(), 16), d, p)
		V_q_hex = pow(int(cipher_hex.get_bitvector_in_ascii(), 16), d, q)
		print cipher_hex.length()

	 	#Apply CRT, remove padding by setting BitVec size
		decrypted_int = (V_p * X_p + V_q * X_q) % n
		decrypted_bv = BitVector(intVal = decrypted_int, size = 128)

		decr = (V_p_hex * X_p + V_q_hex * X_q) % n
		test = BitVector(intVal = decr, size = 256)
		#test = test[128:]
		#print test.get_bitvector_in_ascii()

		out.write(decrypted_bv.get_bitvector_in_ascii())
	out.close()

if sys.argv[1] == '-e':
	primeGen = PrimeGenerator(bits=128, debug=0)
	#Generate two prime numbers p and q
	isSatisfied = True
	while True:
		#This is to compare the left two most bits
		left_bit = BitVector(bitstring = '11')
		#Generate two primes to test
		p = primeGen.findPrime()
		q = primeGen.findPrime()

		p_bv = BitVector(intVal = p)
		q_bv = BitVector(intVal = q)

		#Check if left two most bits are set
		if q_bv[0:2] != left_bit or p_bv[0:2] != left_bit:
			isSatisfied = False

		if p == q:
			isSatisfied = False

		#Check for co primality of totient p and q with public key
		p_gcd_e = gcd(p - 1, public_key)
		q_gcd_e = gcd(q - 1, public_key)

		if p_gcd_e is 1 and q_gcd_e is 1:
			isSatisfied = False

		if isSatisfied is True:
			break
		else:
			isSatisfied = True

	n = p * q #Field for mod n arithmetic
	n_totient = (p-1)*(q-1)
	n_totient_bv = BitVector(intVal = n_totient)
	#Calculate private key
	private_key_bv = public_key_bv.multiplicative_inverse(n_totient_bv)
	private_key    = int(private_key_bv)

	#Store p, q, and private jey for decrypting
	with open('p.txt', 'w') as f:
		f.write(str(p))

	with open('q.txt', 'w') as f:
		f.write(str(q))

	with open('d.txt', 'w') as f:
		f.write(str(private_key))

	encrypt(sys.argv[2], n, sys.argv[3])

elif sys.argv[1] == '-d':
	#Read in the p, q, and d needed for decryption
	with open('p.txt', 'r') as f:
		p = int(f.read())

	with open('q.txt', 'r') as f:
		q = int(f.read())

	with open('d.txt', 'r') as f:
		d = int(f.read())

	decrypt(sys.argv[2], p, q, d, sys.argv[3])

else:
	print 'Must select -e or -d flag'
