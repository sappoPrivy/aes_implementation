import sys

# Standard S-box (256 entries)
sbox = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

# Standard rcon constant value for each round including initial round
rcon = [
    0x00000000,
    0x01000000,
    0x02000000,
    0x04000000,
    0x08000000,
    0x10000000,
    0x20000000,
    0x40000000,
    0x80000000,
    0x1B000000,
    0x36000000
]    

# Read the initial key and blocks
def read_input():
    
    # Read key and blocks
    # input = bytes.fromhex(sys.stdin.buffer.read())
    # input = sys.stdin.buffer.read()
    raw = sys.stdin.read() #.strip().replace(" ", "").replace("\n", "")
    input = bytes.fromhex(raw)
    init_key = input[0:16]                                          # Initial keys is 16 bytes (32 hex values)
    m = input[16:]                                                  # The rest of input is the message
    input_blocks = [m[i:i+16] for i in range(0, len(m), 16)]        # Each block is 16 bytes (32 hex values)
    # print(input_blocks)
    for i in range(len(input_blocks)):
        if len(input_blocks[i]) < 16:
            input_blocks[i] += bytes(16 - len(input_blocks[i]))

    
    # Check inputs
    # print('-------INPUTS---------')
    # print("The input:", input)
    # print("Key:", init_key)
    # print("Blocks:", input_blocks)
    
    return init_key, input_blocks

# Rotate the word's bytes one byte to the left in cyclic manner
def rot_word(w):
    # Rotate to left 8 bits, rotate right 24 bits so first 8 bits are filling out empty bits, ensure length is always 4 bytes (32 bits)
    return ((w << 8) | (w>>(32-8))) & 0xFFFFFFFF

# Replace each byte in word w with entry in the AES S-box
def sub_word(w):
    w = w & 0xFFFFFFFF          # mask to 32 bit
    
    # Extract bytes from word
    bytes_list=[(w >> 24) & 0xFF, (w >> 16) & 0xFF,(w >> 8)  & 0xFF,w & 0xFF]
    
    # For each byte substitute it with b' = sbox[b]
    for idx, b in enumerate(bytes_list):
        # print(f'{b} -> {sbox[b]}')
        bytes_list[idx]=sbox[b]
    
    # Turn into resulting word with 4 bytes
    res_word = (bytes_list[0]<< 24) | (bytes_list[1] << 16) | (bytes_list[2] << 8) | bytes_list[3]
    return res_word

# Expand keys using words
def key_expansion(init_key, tot_words, word_count):
    # The word array contains 44 words with 4 bytes each
    W=[None]*tot_words
    
    # Initialize round key 0 with the initial key, dividing into 4 bytes each
    W[0:4]=[int.from_bytes(init_key[i:i+4], "big") for i in range(0, len(init_key), 4)]
    # print("Initial words:", W[0:4])

    # Generate round keys via key expansion method
    for i in range(word_count, tot_words):
        temp = W[i-1]                     # Previous word
        # if it is a multiple of 4
        if i % word_count == 0:
            t=rot_word(temp)              # Shift word one byte to left
            t=sub_word(t)                 # Substitute each byte in word
            rc=rcon[i // 4]               # Get round constant value for this round
            temp = t ^ rc                 # sub(rot(wi-1)) xor rcon
        W[i] = W[i-4] ^ temp
        # print(f'Word {i}: {W[i]}')
    
    return W

# Generate round keys using the words from key expansion
def key_generation(W, num_rounds, word_count):
    # Create round keys with 4 inner elements, each 4 bytes, tot 16 bytes
    round_keys = [[0 for _ in range(4)] for _ in range(num_rounds+1)]
    
    # Iterate through the words
    for i in range(0, len(W)):
        # print('Round:',i//word_count)
        # print(W[i].to_bytes(4, 'big'))
        
        # Set the 4 bytes as element (i mod 4) for round (i//4) key, meaning e.g. element 0-3 at round 0-10
        round_keys[i//word_count][i % 4] = W[i]
        
        # End of a round with finalized key
        # if (i+1)//word_count != (i)//word_count:
        #     print(f'Round key {i//word_count}: {round_keys[i//word_count]}')
    
    return round_keys

# Create states with 4x4 matrices, column wise
def block_to_state(input_blocks):
    
    # Initialize list of 4x4 matrices
    states = [[[0]*4 for _ in range(4)] for _ in range(len(input_blocks))]
    
    # Fill the states with the input blocks
    for idx_block in range(len(input_blocks)):
        for idx_col in range(4):
            for idx_row in range(4):
                states[idx_block][idx_row][idx_col] = input_blocks[idx_block][4*idx_col + idx_row]
    
    # print('States: ',states)
    return states

# Perform xor operation for block with the round key
def add_round_key(b, k):
    
    # Result matrix
    res_matrix = [[0]*4 for _ in range(4)]
    
    # Column wise xor with a word of round key
    for idx_col in range(len(b)):
        
        # Extract the column word and round key word
        col_word = (b[0][idx_col] << 24) | (b[1][idx_col] << 16) | (b[2][idx_col] << 8) | b[3][idx_col]
        key_word = k[idx_col]
        res_word = col_word ^ key_word
        
        # Turn resulting word into a column with 1 byte in each
        res_matrix[0][idx_col] = (res_word >> 24) & 0xFF
        res_matrix[1][idx_col] = (res_word >> 16) & 0xFF  
        res_matrix[2][idx_col] = (res_word >> 8)  & 0xFF
        res_matrix[3][idx_col] = res_word & 0xFF
        
    return res_matrix

# Substitute each byte in the block
def sub_bytes(b):
    
    # Result matrix
    res_matrix = [[0]*4 for _ in range(4)]
    
    # For each byte replace with corresponding sbox element
    for idx_row, (b0, b1, b2, b3) in enumerate(b):
        res_matrix[idx_row] = [sbox[b0], sbox[b1], sbox[b2], sbox[b3]]
    
    return res_matrix

# Shift the bytes in each row of the block
def shift_rows(b):
    
    # Incrementally higher bytes are shifted for each row, WHY
    for idx_row, (b0, b1, b2, b3) in enumerate(b):
        
        # Extract bytes to create a word
        row_word = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
        
        # Rotate the word
        rot_word = ((row_word << (idx_row*8)) | (row_word>>(32-(idx_row*8)))) & 0xFFFFFFFF
        
        # Turn resulting word into a row with 1 byte in each
        b[idx_row] = [(rot_word >> 24) & 0xFF, (rot_word >> 16) & 0xFF,(rot_word >> 8)  & 0xFF,rot_word & 0xFF]
    
    return b

# Multiplication in gf
def xtime(x):
    # Multiplying two in polynomial form by shifting
    two_x = x << 1
    
    # Check if b7 is 1
    if x & 0x80:
        
        # Reduce modulo AES polynomial using 00011011
        two_x ^= 0x1B
        
    # Mask to 8 bits
    return two_x & 0xFF

# Repeated application of xtimes in gf
def gf(a, b):
    if a == 1:                # Identity 1*b = b
        return b
    elif a == 2:              # 2*b = xtime(b)
        return xtime(b)
    elif a == 3:              # 3*b = (02 xor 01)*b = 2*b xor 1b = xtime(b) xor b
        return xtime(b) ^ b

# Mix each column 
def mix_column(col, m):
    
    # Column with bytes
    b0, b1, b2, b3 = col
    
    # Resulting column
    res_col = [0]*4
    
    # For each row in matrix xor accordingly with column
    for idx, (a0, a1, a2, a3) in enumerate(m):
        res_col[idx] = gf(a0, b0) ^gf(a1, b1) ^ gf(a2, b2) ^ gf(a3, b3)
    return res_col

# Mix all columns using a fixed matrix
def mix_columns(b):
    fixed_matrix = [
      [0x02, 0x03, 0x01, 0x01],
      [0x01, 0x02, 0x03, 0x01],
      [0x01, 0x01, 0x02, 0x03],
      [0x03, 0x01, 0x01, 0x02]
    ]
    
    # Result matrix
    res_matrix = [[0]*4 for _ in range(4)]
    
    # Perform mix operations for each column
    for idx_col in range(len(b)):
        col = b[0][idx_col], b[1][idx_col], b[2][idx_col], b[3][idx_col]
        b0, b1, b2, b3 = mix_column(col, fixed_matrix)
        
        # Turn resulting word into a column with 1 byte in each
        res_matrix[0][idx_col] = b0
        res_matrix[1][idx_col] = b1
        res_matrix[2][idx_col] = b2
        res_matrix[3][idx_col] = b3
    return res_matrix


# Flatten a matrix and compute the hex values
def matrix_to_hex(b):
    b_list = []
    
    # For each byte in the 4x4 matrix add it to a one dimensional list
    for idx_col in range(4):
        for idx_row in range(4):
            b_list.append(b[idx_row][idx_col])
            
    # Convert to hex values
    return bytes(b_list).hex().upper()

# AES transformation for one block at a time
def cipher(block, round_keys, num_rounds):
    
    # Initial operation with intiial key
    block = add_round_key(block, round_keys[0])
    # print(f'Add round key: {block[0]}')
    
    # Perform aes transformation on 1-10 rounds
    for i in range(1, num_rounds+1):              
        # print(f'Round {i}')
        
        block=sub_bytes(block)
        # print('Substitute bytes:',block)
        
        block=shift_rows(block)
        # print('Shift rows:',block)
        
        # Mix columns is not used in the last round
        if i!=num_rounds:
            block=mix_columns(block)
            # print('Mix columns: ', block)
        
        block=add_round_key(block, round_keys[i])
        # print(f'Add round key:', block)
    return block

# Output the final cipher of all blocks
def cipher_output(blocks):
    output = ""
    for i in range(0, len(blocks)):
        output += matrix_to_hex(blocks[i])      # Append each block cipher in hex
    print(output)

if __name__ == "__main__":
    
    # Initial variables
    init_key, input_blocks = read_input()   # Input key and blocks
    num_rounds = 10                         # Number of rounds for 16 bytes (128 bits) key
    word_count=4                            # Each round key contains 4 words
    tot_words = (num_rounds+1)*word_count   # Total number of words for the round keys
    
    # Expand the words for key generation
    W=key_expansion(init_key, tot_words, word_count)
    
    # Generate keys
    round_keys = key_generation(W, num_rounds, word_count)
    
    # Create list of states from the input blocks
    states = block_to_state(input_blocks)
    
    # Compute the cipher for each block
    for idx, block in enumerate(states):
        states[idx] = cipher(block, round_keys, num_rounds)
        
    # Output the ciphers
    cipher_output(states)