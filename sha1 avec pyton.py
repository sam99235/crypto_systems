import struct

# these are the starting numbers for sha1 - dont change them
H0 = 0x67452301
H1 = 0xEFCDAB89
H2 = 0x98BADCFE
H3 = 0x10325476
H4 = 0xC3D2E1F0


# this just moves bits around in a 32 bit number
def rotate_left(num, how_many):
    num = num & 0xffffffff  # make sure its 32 bits
    result = ((num << how_many) | (num >> (32 - how_many)))
    result = result & 0xffffffff  # trim back to 32 bits again
    return result


# takes a 64 byte block and mixes it with the current hash values
def process_block(block, h0, h1, h2, h3, h4):
    # block must always be 64 bytes
    if len(block) != 64:
        print("ERROR: block is wrong size!")
        return

    # split block into 16 chunks of 4 bytes each
    words = []
    for i in range(16):
        piece = block[i * 4 : i * 4 + 4]
        num = struct.unpack('>I', piece)[0]  # big endian unsigned int
        words.append(num)

    # extend to 80 words total
    for i in range(16, 80):
        mixed = words[i-3] ^ words[i-8] ^ words[i-14] ^ words[i-16]
        words.append(rotate_left(mixed, 1))

    # copy the hash values so we can work with them
    a = h0
    b = h1
    c = h2
    d = h3
    e = h4

    # main loop - 80 rounds
    for i in range(80):

        # pick f and k based on which round we are in
        if i <= 19:
            f = d ^ (b & (c ^ d))
            k = 0x5A827999
        elif i <= 39:
            f = b ^ c ^ d
            k = 0x6ED9EBA1
        elif i <= 59:
            f = (b & c) | (b & d) | (c & d)
            k = 0x8F1BBCDC
        else:
            f = b ^ c ^ d
            k = 0xCA62C1D6

        # calc new a value
        new_a = (rotate_left(a, 5) + f + e + k + words[i]) & 0xffffffff

        # shift everything along
        e = d
        d = c
        c = rotate_left(b, 30)
        b = a
        a = new_a

    # add this block result back into the running totals
    h0 = (h0 + a) & 0xffffffff
    h1 = (h1 + b) & 0xffffffff
    h2 = (h2 + c) & 0xffffffff
    h3 = (h3 + d) & 0xffffffff
    h4 = (h4 + e) & 0xffffffff

    return h0, h1, h2, h3, h4


def sha1(data):
    # make sure data is bytes
    if type(data) == str:
        data = data.encode('utf-8')

    # set up the starting hash values
    h0 = H0
    h1 = H1
    h2 = H2
    h3 = H3
    h4 = H4

    # remember how long the original message was (in bytes)
    original_length = len(data)

    # --- padding the message ---
    # we need to pad the data so its length is a multiple of 64 bytes

    # step 1: add a 1 bit (0x80 byte)
    data = data + b'\x80'

    # step 2: add zero bytes until length is 56 mod 64
    while len(data) % 64 != 56:
        data = data + b'\x00'

    # step 3: add original length in bits as 8 bytes at the end
    bit_length = original_length * 8
    data = data + struct.pack('>Q', bit_length)  # big endian 64bit number

    # now process the data 64 bytes at a time
    total_blocks = len(data) // 64

    for block_num in range(total_blocks):
        start = block_num * 64
        end = start + 64
        block = data[start:end]
        h0, h1, h2, h3, h4 = process_block(block, h0, h1, h2, h3, h4)

    # turn the 5 hash values into a hex string
    final_hash = '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)
    return final_hash


# ---- tests ----

if __name__ == '__main__':
    import hashlib

    print("Running SHA-1 tests...\n")

    all_passed = True

    def test(description, input_data):
        global all_passed
        # get our result
        my_result = sha1(input_data)
        # get python's built in sha1 result to compare
        real_result = hashlib.sha1(input_data if type(input_data) == bytes else input_data.encode()).hexdigest()

        if my_result == real_result:
            print(f"  PASS  [{description}]")
            print(f"        hash: {my_result}\n")
        else:
            print(f"  FAIL  [{description}]")
            print(f"        got:      {my_result}")
            print(f"        expected: {real_result}\n")
            all_passed = False

    # basic tests
    test("empty string",        "")
    test("hello world",         "hello world")
    test("abc",                 "abc")
    test("single letter a",     "a")
    test("numbers",             "1234567890")

    # test with bytes directly
    test("bytes input",         b"hello bytes")

    # longer input (more than 64 bytes so multiple blocks get processed)
    long_msg = "this is a longer message that should span more than one block when we hash it with sha1 algorithm"
    test("long message",        long_msg)

    # classic sha1 test vector from the spec
    test("SHA1 spec vector",    "abc")
    test("SHA1 spec vector 2",  "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")

    print("--------------------")
    if all_passed:
        print("All tests passed!")
    else:
        print("Some tests FAILED - check above.")
