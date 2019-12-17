
import collections
import time
from BitVector import *

subBytesTable = [ 99, 124, 119, 123, 242, 107, 111, 197,  48,   1, 103,  43, 254, 215, 171, 118, 202, 130, 201, 125,
                 250,  89,  71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147,  38,  54,  63, 247, 204,
                  52, 165, 229, 241, 113, 216,  49,  21,   4, 199,  35, 195,  24, 150,   5, 154,   7,  18, 128, 226,
                 235,  39, 178, 117,   9, 131,  44,  26,  27, 110,  90, 160,  82,  59, 214, 179,  41, 227,  47, 132,
                  83, 209,   0, 237,  32, 252, 177,  91, 106, 203, 190,  57,  74,  76,  88, 207, 208, 239, 170, 251,
                  67,  77,  51, 133,  69, 249,   2, 127,  80,  60, 159, 168,  81, 163,  64, 143, 146, 157,  56, 245,
                 188, 182, 218,  33,  16, 255, 243, 210, 205,  12,  19, 236,  95, 151,  68,  23, 196, 167, 126,  61,
                 100,  93,  25, 115,  96, 129,  79, 220,  34,  42, 144, 136,  70, 238, 184,  20, 222,  94,  11, 219,
                 224,  50,  58,  10,  73,   6,  36,  92, 194, 211, 172,  98, 145, 149, 228, 121, 231, 200,  55, 109,
                 141, 213,  78, 169, 108,  86, 244, 234, 101, 122, 174,   8, 186, 120,  37,  46,  28, 166, 180, 198,
                 232, 221, 116,  31,  75, 189, 139, 138, 112,  62, 181, 102,  72,   3, 246,  14,  97,  53,  87, 185,
                 134, 193,  29, 158, 225, 248, 152,  17, 105, 217, 142, 148, 155,  30, 135, 233, 206,  85,  40, 223,
                 140, 161, 137,  13, 191, 230,  66, 104,  65, 153,  45,  15, 176,  84, 187,  22]

AES_modulus = BitVector(bitstring='100011011')

def state_array_to_bitvector(state_array):
    temp_bv = BitVector(intVal=int(state_array[0][0], 0))
    if len(temp_bv) < 8:
        temp_bv.pad_from_left(8 - len(temp_bv) % 8)
    bv = temp_bv
    for j in range(0, 4):
        for i in range(0, 4):
            if i | j:
                temp_bv = BitVector(intVal=int(state_array[i][j], 0))
                if len(temp_bv) < 8:
                    temp_bv.pad_from_left(8-(len(temp_bv)))
                bv = bv + temp_bv
    return bv

def mix_columns(state):
    temp = [[BitVector(size=8) for _ in range(4)] for _ in range(4)]
    for i in range(4):
        for j in range(4):
            state[i][j] = BitVector(intVal=int(state[i][j], 0))
            if len(state[i][j]) < 8:
                state[i][j].pad_from_left(8-len(state[i][j]))
            temp[i][j] = state[i][j].deep_copy()

    for i in range(4):
        temp[0][i] = state[0][i].gf_multiply_modular(BitVector(hexstring='02'), AES_modulus, 8) \
                      ^ state[1][i].gf_multiply_modular(BitVector(hexstring='03'), AES_modulus, 8) ^ state[2][i] ^ state[3][i]
        temp[1][i] = state[0][i] ^ state[1][i].gf_multiply_modular(BitVector(hexstring='02'), AES_modulus, 8) \
                      ^ state[2][i].gf_multiply_modular(BitVector(hexstring='03'), AES_modulus, 8) ^ state[3][i]
        temp[2][i] = state[0][i] ^ state[1][i] ^ state[2][i].gf_multiply_modular(BitVector(hexstring='02'), AES_modulus, 8) \
                      ^ state[3][i].gf_multiply_modular(BitVector(hexstring='03'), AES_modulus, 8)
        temp[3][i] = state[0][i].gf_multiply_modular(BitVector(hexstring='03'), AES_modulus, 8) ^ state[1][i] ^ state[2][i] \
                      ^ state[3][i].gf_multiply_modular(BitVector(hexstring='02'), AES_modulus, 8)
    for i in range(4):
        for j in range(4):
            state[i][j] = hex(temp[i][j].int_val())
    return state

def shift_rows(statearray):
    d = collections.deque(statearray[1])
    d.rotate(-1)

    statearray[1] = d
    d = collections.deque(statearray[2])
    d.rotate(-2)
    statearray[2] = d

    d = collections.deque(statearray[3])
    d.rotate(-3)
    statearray[3] = d
    return statearray

def sub_bytes(state):
    for i in range(4):
        for j in range(4):
            #indexing thru lookup sbox table
            state[i][j] = hex(subBytesTable[int(state[i][j], 0)])
    return state

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

def AES_encrypt(key, input_bv, file_out):
    round_keys = genKey(key)
    #input_bv = BitVector(filename = file_in)
    output = open(file_out, 'wb')
    hex_file = open(file_out+'-hexFile', 'wb')

    state_array = [[0 for _ in range(4)] for _ in range(4)]
    following_array = [[0 for _ in range(4)] for _ in range(4)]

    while (1):
        bitvec = input_bv#.read_bits_from_file(128)
        if bitvec.length() % 128 != 0:
            bitvec.pad_from_right(128 - bitvec.length() % 128)
        bitvec ^= round_keys[0]
        for i in range(4):
            for j in range(4):
                following_array[j][i] = hex(bitvec[32*i + 8*j:32*i + 8*(j+1)].int_val())
        for round in range(1, 14):
            state_array = following_array
            state_array = sub_bytes(state_array)
            state_array = shift_rows(state_array)
            state_array = mix_columns(state_array)
            state_array = round_keys[round] ^ state_array_to_bitvector(state_array)
            for i in range(4):
                for j in range(4):
                    following_array[j][i] = hex(state_array[32*i + 8*j:32*i + 8*(j+1)].int_val())
        state_array = sub_bytes(following_array)
        state_array = shift_rows(state_array)
        state_array = round_keys[14] ^ state_array_to_bitvector(state_array)
        state_array.write_to_file(output)
        hex_file.write(state_array.get_bitvector_in_hex())
        break

    output.close()
    hex_file.close()
    return state_array

def x931(v0,dt, key_file, totalNum):
    v0 = BitVector(textstring = v0)
    num_list = []
    with open(sys.argv[1]) as f:
        key_plaintext = f.read()

    for i in range(totalNum):
        AES_encrypt(key_plaintext, dt, 'I.txt')
        I_bv = BitVector(filename = 'I.txt')
        I = I_bv.read_bits_from_file(128)
        X = I ^ v0

        AES_encrypt(key_plaintext, X, 'Xprior.txt')
        X_bv = BitVector(filename = 'Xprior.txt')
        X = X_bv.read_bits_from_file(128)

        X_I = X^I
        AES_encrypt(key_plaintext, X_I, 'X_I.txt')
        nexNum_bv = BitVector(filename = 'X_I.txt')
        nexNum = nexNum_bv.read_bits_from_file(128)
        v0 = nexNum

        gg = int(X.get_bitvector_in_hex(), 16)
        print(gg)
        num_list.append(gg)
    return num_list



if __name__ == "__main__":
    #getting dt
    nums = []
    left_half  = int(time.time() * 1000000)
    right_half =int(time.time() * 1000000)
    left_half  = BitVector(intVal = left_half, size = 64)
    right_half = BitVector(intVal = right_half, size = 64)
    dt = left_half + right_half
    x931('computersecurity',dt, sys.argv[1], 2)
