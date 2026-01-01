#simple DES CRYPTO SYSTEM IN PYTHON

#my reference https://simewu.com/des/ to verify
#16 sub keys generation
#encyrption and decryption process

#NOTE: THIS ONLY WORKS FOR  a hexdecimal chars

#TODO
#accepts any char
#padding mechanism
#operation modes cbc ecb and ctr
#interactive cli using argparse


import pprint


# S-Boxes: 8 substitution boxes, each takes 6 bits and outputs 4 bits
SBox =[
		# S1
		[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
		 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
		 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
		 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],

		# S2
		[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
		 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
		 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
		 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],

		# S3
		[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
		 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
		 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
		 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],

		# S4
		[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
		 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
		 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
		 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],

		# S5
		[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
		 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
		 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
		 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],

		# S6
		[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
		 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
		 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
		 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],

		# S7
		[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
		 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
		 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
		 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],

		# S8
		[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
		 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
		 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
		 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
	]


# Expansion box: expands 32 bits to 48 bits
EBox = [32,1,2,3,4,5,
            4,5,6,7,8,9,
            8,9,10,11,12,13,
            12,13,14,15,16,17,
            16,17,18,19,20,21,
            20,21,22,23,24,25,
            24,25,26,27,28,29,
            28,29,30,31,32,1]

 
# Permuted Choice 1: reduces 64-bit key to 56 bits
PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
]


# DES cumulative left-shift values per round
ls_table = [1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28]


# Permuted Choice 2: reduces 56-bit key to 48-bit subkey
pc_2 = [14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32]

# Initial Permutation: applied to plaintext at the start
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

# Final Permutation table (FP): applied in the Feistel function
FP = [
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
]


# Inverse Initial Permutation: applied at the end to produce ciphertext
IP_INV = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

# Dictionary to store 16 subkeys before PC-2
sub_keys  = {}

# Dictionary to store 16 subkeys after PC-2
sub_keys_pc2 = {}


def convert_to_bits(user_key):
    """Convert hexadecimal string to list of bits"""
    try:
        # Convert hex string to bytes
        key_bytes = bytes.fromhex(user_key)
        
        # Check if it's 64 bits (8 bytes)
        if len(key_bytes) != 8:
            print(f"Error: Key must be 64 bits , but got {len(key_bytes)} bytes")
        else:
            # Convert bytes to bits
            bits_128 = ''.join(format(byte, '08b') for byte in key_bytes)
            
            # Convert to list of bits
            bits_list = [int(bit) for bit in bits_128]
        return bits_list
            
    except ValueError:
        print("Error: Invalid hex string. Use only 0-9 and a-f characters")



def permute(bin_key,pc_table,verbose=False):
    """Apply permutation table to binary data"""
    new_key = []

    if pc_table:
        for p in pc_table:
                new_key.append(bin_key[p-1])  #p-1 to avoid key out of range error
    return new_key


# Array to store left and right halves through the rounds
left_right_halves = []

# Global counters for nested list handling
rl = 0
ll=0

def mangler(key,right_half,left_half,verbose=False):
    """Feistel function (F-function): Expansion, XOR, S-box, Permutation"""
    
    global rl,ll

    i=0
    j=6
    ar = []
    msg_after_sbox = []
    final_msg=[]

    # Extract right half from nested list structure
    if rl==0:
         right_half = right_half[0]
    rl+=1
    
    # Expand right half from 32 bits to 48 bits
    expanded_right_half = permute(right_half,EBox)
    
    # XOR expanded right half with subkey
    new_msg=[]
    for b,c in zip(expanded_right_half,key):
                new_msg.append(int(b)^int(c))
    
    # S-box substitution: process 48 bits in 8 groups of 6 bits
    if len(new_msg)==48:
            for sbx_n in range(0,8):
                # Extract 6-bit slice
                slice_6bit = new_msg[i:j]
                ar.append(slice_6bit)
                i+=6
                j+=6
                
                # Calculate row from outer bits (first and last)
                row = int(int("".join(b for b in str(slice_6bit[0]) + str(slice_6bit[-1])), 2))

                # Calculate column from inner 4 bits
                col = int(int("".join(str(b) for b in slice_6bit[1:5]), 2))
        
                # Look up value in S-box based on row and column
                if row==0:
                    a=0
                    binary_repr = format(SBox[sbx_n][a+col], '04b')
                    msg_after_sbox.append(binary_repr)
                    
                if row==1:
                    a=16
                    binary_repr = format(SBox[sbx_n][a+col], '04b')
                    msg_after_sbox.append(binary_repr)
                if row==2:
                    a=32
                    binary_repr = format(SBox[sbx_n][a+col], '04b')
                    msg_after_sbox.append(binary_repr)
                if row==3:
                    a=48
                    binary_repr = format(SBox[sbx_n][a+col], '04b')
                    msg_after_sbox.append(binary_repr)

    # Concatenate S-box outputs into 32-bit result
    msg_after_sbox2 = [int(b) for b in "".join(str(b) for b in msg_after_sbox)]
    
    # Apply final permutation (P-box)
    final_right_half = permute(msg_after_sbox2,FP)

    # Extract left half from nested list if needed
    for ob in left_half:
        if isinstance(ob,list):
             left_half  = ob

    # XOR result with left half
    for b,c in zip(final_right_half,left_half):
                final_msg.append(int(b)^int(c))
    return final_msg  



if __name__ == "__main__":

    user_key = input("Enter your DES 64bits key ( hex characters): ")

    ### SUBKEY GENERATION ###
    
    # Apply PC-1 permutation to key
    key_pc1 = permute(convert_to_bits(user_key),PC1)
    key_l = key_pc1
    print(key_pc1)


    # Generate 16 subkeys using left circular shifts
    sub_keys[f"k{0}"] = "".join(str(b) for b in (key_l[0:28]+key_l[28:56]))
    for index, shift_n in enumerate(ls_table):
        l=key_l[0:28]
        r=key_l[28:56]        
        print(f"k{index+1}",shift_n)
        sub_keys[f"k{index+1}"] =  "".join([str(b) for b in (l[shift_n:]+l[:shift_n]+r[shift_n:]+r[:shift_n])])

    pprint.pprint(sub_keys)

    # Apply PC-2 permutation to generate 48-bit subkeys
    for i,key in sub_keys.items():
        sub_keys_pc2[i] = "".join(str(b) for b in permute(key,pc_2))
    pprint.pprint(sub_keys_pc2)

    
    
    ### DES ENCRYPTION ###
    
    user_msg = input("user message hexdecimal format:")

    # Apply initial permutation to message
    msg_ip = permute(convert_to_bits(user_msg),IP)

    # Sort subkeys in ascending order for encryption
    sub_keys_values = [ sub_keys_pc2[k] for k in sorted(sub_keys_pc2.keys(), key=lambda x: int(x[1:])) if int(k[1:]) > 0]
    pprint.pprint(sub_keys_values)
    
    # Split message into left and right halves
    l = msg_ip[0:32]
    r = msg_ip[32:64]
    
    # Store initial halves
    left_right_halves.append([l])
    left_right_halves.append([r])

    # Perform 16 rounds of Feistel network
    for i,key in enumerate(sub_keys_values):
        
        # Get previous left and right halves
        if i==0:
            l_f = left_right_halves[i]
            print("l0",l_f)
            r_f = left_right_halves[i+1]
            print("r0",r_f)
        else:
            l_f = left_right_halves[i+i]
            r_f = left_right_halves[i+i+1]
            print(f"l{i}",l_f)
            print(f"r{i}",r_f)

        print(f"key{i+1}",key)
        print(f"mangler func iter {i} right half" ,len(r_f))
        
        # Apply Feistel function
        r = mangler(key=key,right_half=r_f,left_half=l_f) 
        
        l  = r_f
        r = r
        
        # Store results
        left_right_halves.append(l)
        left_right_halves.append(r)

    # Get final left and right halves
    l16 = left_right_halves[-2]
    r16 = left_right_halves[-1]
    print("l16",l16,"\nr16",r16)
    
    # Swap and concatenate (R16 + L16)
    reverse_r16l16 = r16+l16

    # Convert to binary list
    final_msgg = [int(b) for b in "".join(str(b) for b in reverse_r16l16)]
    print("reverse msg",final_msgg,len(reverse_r16l16))

    # Apply inverse initial permutation
    cipher_text_bin = permute(final_msgg,IP_INV)
    cipher_text_bin = "".join(str(b) for b in cipher_text_bin)
    
    print(cipher_text_bin)
    
    def binary_to_hex(bin_str):
        """Convert binary string to hexadecimal"""
        return hex(int(bin_str, 2))[2:].upper()

    print(binary_to_hex(cipher_text_bin))


    # Reset counters for decryption
    rl=0
    ll=0



    ### DES DECRYPTION ###
    
    user_msg = input("enter the cipher text")

    # Apply initial permutation to ciphertext
    msg_ip = permute(convert_to_bits(user_msg),IP)

    # Sort subkeys in REVERSE order for decryption
    sub_keys_values = [ sub_keys_pc2[k] for k in sorted(sub_keys_pc2.keys() , reverse=True, key=lambda x: int(x[1:])) if int(k[1:]) > 0]
    pprint.pprint(sub_keys_values)
    
    # Reset left_right_halves array
    left_right_halves= []
    
    # Split ciphertext into left and right halves
    l = msg_ip[0:32]
    r = msg_ip[32:64]
    
    # Store initial halves
    left_right_halves.append([l])
    left_right_halves.append([r])

    # Perform 16 rounds of Feistel network with reversed keys
    for i,key in enumerate(sub_keys_values):
        
        # Get previous left and right halves
        if i==0:
            l_f = left_right_halves[i]
            print("l0",l_f)
            r_f = left_right_halves[i+1]
            print("r0",r_f)
        else:
            l_f = left_right_halves[i+i]
            r_f = left_right_halves[i+i+1]
            print(f"l{i}",l_f)
            print(f"r{i}",r_f)

        print(f"key{16-i}",key)
        print(f"mangler func iter {i} right half" ,len(r_f))
        
        # Apply Feistel function
        r = mangler(key=key,right_half=r_f,left_half=l_f,verbose=True) 
        
        l  = r_f
        r = r
        
        # Store results
        left_right_halves.append(l)
        left_right_halves.append(r)

    # Get final left and right halves
    l16 = left_right_halves[-2]
    r16 = left_right_halves[-1]
    print("l16",l16,"\nr16",r16)
    
    # Swap and concatenate (R16 + L16)
    reverse_r16l16 = r16+l16

    # Convert to binary list
    final_msgg = [int(b) for b in "".join(str(b) for b in reverse_r16l16)]
    print("reverse msg",final_msgg,len(reverse_r16l16))

    # Apply inverse initial permutation
    plain_text = permute(final_msgg,IP_INV)
    plain_text = "".join(str(b) for b in plain_text)
    
    print(plain_text)
    
    def binary_to_hex(bin_str):
        """Convert binary string to hexadecimal"""
        return hex(int(bin_str, 2))[2:].upper()

    print(binary_to_hex(plain_text))
