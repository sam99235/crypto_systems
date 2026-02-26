import struct
import sys
import os


H0 = 0x67452301
H1 = 0xEFCDAB89
H2 = 0x98BADCFE
H3 = 0x10325476
H4 = 0xC3D2E1F0


def rotate_left(num, how_many):
    num = num & 0xffffffff
    return ((num << how_many) | (num >> (32 - how_many))) & 0xffffffff


def process_block(block, h0, h1, h2, h3, h4):
    words = []
    for i in range(16):
        words.append(struct.unpack('>I', block[i*4:i*4+4])[0])
    for i in range(16, 80):
        words.append(rotate_left(words[i-3] ^ words[i-8] ^ words[i-14] ^ words[i-16], 1))

    a, b, c, d, e = h0, h1, h2, h3, h4

    for i in range(80):
        if i <= 19:
            f = d ^ (b & (c ^ d)); k = 0x5A827999
        elif i <= 39:
            f = b ^ c ^ d;         k = 0x6ED9EBA1
        elif i <= 59:
            f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC
        else:
            f = b ^ c ^ d;         k = 0xCA62C1D6

        new_a = (rotate_left(a, 5) + f + e + k + words[i]) & 0xffffffff
        a, b, c, d, e = new_a, a, rotate_left(b, 30), c, d

    return (h0+a)&0xffffffff, (h1+b)&0xffffffff, (h2+c)&0xffffffff, (h3+d)&0xffffffff, (h4+e)&0xffffffff


def sha1(data):
    if isinstance(data, str):
        data = data.encode('utf-8')

    h0, h1, h2, h3, h4 = H0, H1, H2, H3, H4
    original_length = len(data)

    data += b'\x80'
    while len(data) % 64 != 56:
        data += b'\x00'
    data += struct.pack('>Q', original_length * 8)

    for i in range(len(data) // 64):
        h0, h1, h2, h3, h4 = process_block(data[i*64:i*64+64], h0, h1, h2, h3, h4)

    return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)


# ── CLI ──────────────────────────────────────────────────────────────────────

def print_help():
    print("""
sha1 hasher - simple command line tool

Usage:
  python my_sha1.py string "your text here"
  python my_sha1.py file   path/to/file.txt
  python my_sha1.py help

Examples:
  python my_sha1.py string "hello world"
  python my_sha1.py string "password123"
  python my_sha1.py file   notes.txt
  python my_sha1.py file   photo.jpg
""")


if __name__ == '__main__':

    # no arguments given
    if len(sys.argv) < 2:
        print_help()
        sys.exit()

    command = sys.argv[1].lower()

    if command == 'help':
        print_help()

    elif command == 'string':
        if len(sys.argv) < 3:
            print("Error: please provide a string to hash.")
            print('Example: python my_sha1.py string "hello world"')
        else:
            text = sys.argv[2]
            print(f"Input : {text}")
            print(f"SHA-1 : {sha1(text)}")

    elif command == 'file':
        if len(sys.argv) < 3:
            print("Error: please provide a file path.")
            print("Example: python my_sha1.py file notes.txt")
        else:
            path = sys.argv[2]
            if not os.path.isfile(path):
                print(f"Error: could not find file '{path}'")
            else:
                with open(path, 'rb') as f:
                    data = f.read()
                print(f"File  : {path}")
                print(f"SHA-1 : {sha1(data)}")

    else:
        print(f"Unknown command '{command}'. Try: python my_sha1.py help")
