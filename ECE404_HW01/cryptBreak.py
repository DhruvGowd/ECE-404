#USING PYTHON VERSION 3.7
import sys
from BitVector import *

BLOCKSIZE = 16
numbytes = BLOCKSIZE // 8

def decrypt(test_key, encryptedMessage):
    #if len(sys.argv) is not 3:
    #    sys.exit('''Needs two command-line arguments, one for '''
    #             '''the encrypted file and the other for the '''
    #             '''decrypted output file''')

    PassPhrase = "Hopes and dreams of a million years"

    BLOCKSIZE = 16
    numbytes = BLOCKSIZE // 8

    # Reduce the passphrase to a bit array of size BLOCKSIZE:
    bv_iv = BitVector(bitlist = [0]*BLOCKSIZE)
    for i in range(0,len(PassPhrase) // numbytes):
        textstr = PassPhrase[i*numbytes:(i+1)*numbytes]
        bv_iv ^= BitVector( textstring = textstr )

    # Create a bitvector from the ciphertext hex string:
    #FILEIN = open(sys.argv[1])
    #encrypted_bv = BitVector( hexstring = FILEIN.read() )
    encrypted_bv = BitVector( hexstring = encryptedMessage)
    # Get key from user:
    #key = None
    key_bv = test_key
    #if sys.version_info[0] == 3:
    #    key = input("\nEnter key: ")
    #else:
    #    key = raw_input("\nEnter key: ")
    #key = key.strip()

    # Reduce the key to a bit array of size BLOCKSIZE:
    # key_bv = BitVector(bitlist = [0]*BLOCKSIZE)
    # for i in range(0,len(key) // numbytes):
    #    keyblock = key[i*numbytes:(i+1)*numbytes]
    #    key_bv ^= BitVector( textstring = keyblock )

    # Create a bitvector for storing the decrypted plaintext bit array:
    msg_decrypted_bv = BitVector( size = 0 )

    # Carry out differential XORing of bit blocks and decryption:
    previous_decrypted_block = bv_iv
    for i in range(0, len(encrypted_bv) // BLOCKSIZE):
        bv = encrypted_bv[i*BLOCKSIZE:(i+1)*BLOCKSIZE]
        temp = bv.deep_copy()
        bv ^=  previous_decrypted_block
        previous_decrypted_block = temp
        bv ^=  key_bv
        msg_decrypted_bv += bv

    # Extract plaintext from the decrypted bitvector:
    outputtext = msg_decrypted_bv.get_text_from_bitvector()

    # Write plaintext to the output file:
    #FILEOUT = open(sys.argv[2], 'w')
    #FILEOUT.write(outputtext)
    #FILEOUT.close()
    return outputtext


if __name__ == "__main__":

    encrypted_str = "2b2f37793960707478617a377b2e7f3d362a3138782b67387c37612961316f677f7e63287d3767296b3b223a2a3f632d633d6c2e773d703f392023763974396e3c3821262d70376733747a637d7134622b71307e2d602d78232e33372f61317e2b6027726e7366762f742e6767626f79632f632a2a382a28253b3e28392a7e561d0d37142c0f241a6d2167146f10720e62542b612b632b70312637367e347f2736013316330e5072"
    for key in range(65535):
        keyBin = bin(key)[2:]
        keyBin = keyBin.zfill(16)
        key_test = BitVector(intVal = key, size = BLOCKSIZE)
        test_msg = decrypt(key_test, encrypted_str)
        if "Cormac McCarthy" in test_msg:
            print(test_msg)
            FOUND_KEY = key_test
            print("Key " + str(FOUND_KEY))
            KEY_ASCII = key_test.get_bitvector_in_ascii()
            print("Charactar Key " + KEY_ASCII)
            break
        #print(keyBin)
