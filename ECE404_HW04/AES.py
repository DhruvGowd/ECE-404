import sys
from BitVector import *

Table = [ 99, 124, 119, 123, 242, 107, 111, 197,  48,   1, 103,  43, 254, 215, 171, 118, 202, 130, 201, 125,
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
                 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22]

AES_modulus = BitVector(bitstring='100011011')

def gee(keyword, round_constant, byte_sub_table):
    '''
    This is the g() function you see in Figure 4 of Lecture 8.
    '''
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
            #if word_index % 4 == 0: print("\n")
            #print("word %d:  %s" % (word_index, str(keyword_in_ints)))
            key_schedule.append(keyword_in_ints)

    num_rounds = 14
    round_keys = [None for i in range(num_rounds+1)]
    for i in range(num_rounds+1):
        round_keys[i] = (key_words[i*4] + key_words[i*4+1] + key_words[i*4+2] +
                                                       key_words[i*4+3]).get_bitvector_in_hex()
    return key_schedule, round_keys

def genStateArray(block):
    ##generates State Array
    stateArray = [[0 for x in range(8)] for x in range(4)]
    for i in range(4):
        for j in range(8):
            stateArray[j][i] = hex(block[32*i + 8*j:32*i + 8*(j+1)].int_val())
    return stateArray

def subbytes(array):
    for i in range(4):
        for j in range(8):
            array[i][j] = hex(int(Table[int(array[i][j], 16)]))
    return array

def shift_rows(array):
    for r in range(1, 4):
            state[r] = state[r][r:] + state[r][:r]
    return array
def toBV(array):
    temp = BitVector(intVal = int(array[0][0], 0))
    if len(temp) < 8:
        temp.pad_from_left(8 - len(temp) % 8)

    bits = temp
    for j in range(0,4):
        for i in range(0,8):
            if i != 0 or j != 0:
                temp = BitVector(intVal = int(array[j][i], 0))
                if len(temp) < 8:
                    temp.pad_from_left(8 - len(temp) % 8)
                bits = bits + temp
    return bits

def encrypt(round_keys, message_plaintext, output):
    file = open(output, 'wb')
    input_bv = BitVector(textstring = message_plaintext)

    #init empty state arrays
    state_array = [[0 for i in range(8)] for i in range(4)]
    next_array  = [[0 for i in range(8)] for i in range(4)]

    #encrypting
    while (input_bv.more_to_read()):
        pb_block = input_bv.read_bits_from_file(256)
        if pb_block.length() != 256:
            pb.pad_from_right(256 - pb_block.length % 256)

        #adding initial round key and initial state array
        pb_block ^= BitVector(textstring = round_keys[0])
        next_array = genStateArray(pb_block)

        #doing all the rounds
        for i in range(1, 14):
            state_array = next_array
            state_array = subbytes(state_array)
            state_array = shift_rows(state_array)
            state_array = BitVector(textstring = round_key[i]) ^ toBV(state_array)
            for i in range(4):
                for j in range(8):
                    next_array[i][j] = hex(state_array[32*i + 8*j:32*i + 8*(j+1)].int_val())

        state_array = subbytes(next_array)
        state_array = shift_rows(state_array)
        state_array = BitVector(round_keys[15]) ^ toBV(state_array)
        state_array.write_to_file(file)
    file.close()

if __name__ == "__main__":
    # Call as python AES.py key.txt message.txt

    with open(sys.argv[1], 'r') as f:
        key_plaintext = f.read()
    with open(sys.argv[2], 'r') as f:
        message_plaintext = f.read()

    #create round keys and key schedule
    key_schedule, round_keys = genKey(key_plaintext)
    encrypt(round_keys, message_plaintext, 'output.txt')
