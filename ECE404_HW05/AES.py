import sys
from BitVector import *
#----------------------------------key generation-----------------------------#
AES_modulus = BitVector(bitstring='100011011')

def gee(keyword, round_constant, byte_sub_table):
    rotated_word = keyword.deep_copy()
    rotated_word << 8
    newword = BitVector(size = 0)
    for i in range(4):
        newword += BitVector(intVal = byte_sub_table[rotated_word[8*i:8*i+8].intValue()], size = 8)
    newword[:8] ^= round_constant
    round_constant = round_constant.gf_multiply_modular(BitVector(intVal = 0x02), AES_modulus, 8)
    return newword, round_constant

def gen_subbytes_table():
    subBytesTable = []
    c = BitVector(bitstring='01100011')
    for i in range(0, 256):
        a = BitVector(intVal = i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
    return subBytesTable

def gen_key_schedule_256(key_bv):
    byte_sub_table = gen_subbytes_table()
    key_words = [None for i in range(60)]
    round_constant = BitVector(intVal = 0x01, size=8)
    for i in range(8):
        key_words[i] = key_bv[i*32 : i*32 + 32]
    for i in range(8,60):
        if i%8 == 0:
            kwd, round_constant = gee(key_words[i-1], round_constant, byte_sub_table)
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

def genKey(key):
    key_words = []
    keysize = 256
    key_bv = BitVector( textstring = key)

    key_words = gen_key_schedule_256(key_bv)

    key_schedule = []
    for word_index,word in enumerate(key_words):
        keyword_in_ints = []
        for i in range(4):
            keyword_in_ints.append(word[i*8:i*8+8].intValue())
            key_schedule.append(keyword_in_ints)

    num_rounds = 14
    round_keys = [None for i in range(num_rounds+1)]
    for i in range(num_rounds+1):
        round_keys[i] = BitVector(hexstring=(key_words[i*4] + key_words[i*4+1] + key_words[i*4+2] +
                         key_words[i*4+3]).get_bitvector_in_hex())
    return round_keys

#----------------------------------statearray functions------------------------#
def SA2bits(SA):
    temp_bv = BitVector(intVal=int(SA[0][0], 0))
    if len(temp_bv) < 8:
        temp_bv.pad_from_left(8 - len(temp_bv) % 8)
    bv = temp_bv
    for j in range(1, 4):
        for i in range(1, 4):
            temp_bv = BitVector(intVal=int(SA[i][j], 0))
            if len(temp_bv) < 8:
                temp_bv.pad_from_left(8-(len(temp_bv)))
            bv = bv + temp_bv
    return bv

def substituteBytes(SA):
    check = BitVector(intVal = 0)
    c = BitVector(bitstring = "01100011")
    for i in range(4):
        for j in range(4):
            x_in = SA[i][j]
            x_inv = BitVector(intVal = int(x_in,0))
            x_inv = x_inv.gf_MI(AES_modulus, 8) if x_inv !=check else BitVector(intVal = 0)
            #rotated versions of itself ^ with c = 0x63
            x1, x2, x3, x4= [x_inv.deep_copy() for x in range(4)]
            x_out = (x_inv) ^ (x1 >> 4) ^ (x2 >> 5) ^ (x3 >> 6) ^ (x4 >> 7) ^ c
            #sub back in state array
            SA[i][j] = x_out = hex(x_out.int_val())
    return SA

def shiftRows(SA):
    #only shift last three rows
    for i in range(1,4):
        SA[0] = SA[i][i:] + SA[i][:i]
    return SA

def mixColumns(SA):
    #make a temp state
    temp = [[BitVector(size=8) for _ in range(4)] for _ in range(4)]
    for i in range(4):
        for j in range(4):
            SA[i][j] = BitVector(intVal=int(SA[i][j], 0))
            if len(SA[i][j]) < 8:
                SA[i][j].pad_from_left(8-len(SA[i][j]))
            temp[i][j] = SA[i][j].deep_copy()

    for i in range(4):
        temp[0][i] = SA[0][i].gf_multiply_modular(BitVector(hexstring='02'), AES_modulus, 8) ^ SA[1][i].gf_multiply_modular(BitVector(hexstring='03'), AES_modulus, 8) ^ SA[2][i] ^ SA[3][i]
        temp[1][i] = SA[0][i] ^ SA[1][i].gf_multiply_modular(BitVector(hexstring='02'), AES_modulus, 8) ^ SA[2][i].gf_multiply_modular(BitVector(hexstring='03'), AES_modulus, 8) ^ SA[3][i]
        temp[2][i] = SA[0][i] ^ SA[1][i] ^ SA[2][i].gf_multiply_modular(BitVector(hexstring='02'), AES_modulus, 8) ^ SA[3][i].gf_multiply_modular(BitVector(hexstring='03'), AES_modulus, 8)
        temp[3][i] = SA[0][i].gf_multiply_modular(BitVector(hexstring='03'), AES_modulus, 8) ^ SA[1][i] ^ SA[2][i] ^ SA[3][i].gf_multiply_modular(BitVector(hexstring='02'), AES_modulus, 8)
    for i in range(4):
        for j in range(4):
            SA[i][j] = hex(temp[i][j].int_val())
    return SA

#------------------------------------------------------------------------------#
def AES_encrypt(key_plaintext, file_in, file_out):
    out = open(file_out, 'wb')
    hexout = open(file_out+'_hex', 'w')
    #Generate all round keys from the key
    round_keys = genKey(key_plaintext)

    #allocate a blank state state
    statearray = [[0 for x in range(4)] for x in range(4)]

    #using initial round key for input vec
    plain_text_bv = BitVector(filename = file_in)
    while( plain_text_bv.more_to_read):
        #get 128 bit block fofr state array
        input_block = plain_text_bv.read_bits_from_file(128)
        if input_block.length() % 128 != 0:
            input_block.pad_from_right(128 - input_block.length() % 128)

        #xor with first round key
        input_block ^= round_keys[0]

        #make a state array of the input block
        for i in range(4):
            for j in range(4):
                statearray[j][i] = hex(input_block[32*i + 8*j:32*i + 8*(j+1)].int_val())

        #go through rounds of AES
        for i in range(1, 14):
            #substite bytes
            statearray = substituteBytes(statearray)
            #shift rows
            statearray = shiftRows(statearray)
            #mix columns for every round but the last round
            if i < 14:
                SA = mixColumns(statearray)
            #add round key
            cipher_block = round_keys[i] ^ SA2bits(SA)
            print(i)
        #write encrypted to file
        cipher_block.write_to_file(out)
        hexout.write(cipher_block.get_bitvector_in_hex())
        statearray  = [[0 for x in range(4)] for x in range(4)]
    out.close()
    hexout.close()




with open(sys.argv[1], 'r') as f:
    key_plaintext = f.read()

AES_encrypt(key_plaintext, sys.argv[2], sys.argv[3])
