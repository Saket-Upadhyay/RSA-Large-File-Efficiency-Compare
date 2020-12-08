import base64
import hashlib
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Random import new as Random
from base64 import b64encode
from base64 import b64decode
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
from cryptography.fernet import Fernet
import random

global global_aes_key
DataList = [
    "B",
    "A",
    "D",
    "C",
    "E",
    "F",
    "G",
    "H",
    "I",
    "J",
    "K",
    "L",
    "M",
    "N",
    "O",
    "P",
    "Q",
    "R",
    "S",
    "T",
    "U",
    "V",
    "W",
    "X",
    "Y",
    "Z",
    "a",
    "b",
    "c",
    "d",
    "e",
    "f",
    "g",
    "h",
    "i",
    "j",
    "k",
    "l",
    "m",
    "n",
    "o",
    "p",
    "q",
    "r",
    "s",
    "t",
    "u",
    "v",
    "w",
    "x",
    "y",
    "z",
    "0",
    "1",
    "2",
    "3",
    "4",
    "5",
    "6",
    "7",
    "8",
    "9",
]


class RSA_Cipher:
    def generate_key(self, key_length):
        assert key_length in [1024, 2048, 4096]
        rng = Random().read
        self.key = RSA.generate(key_length, rng)

    def save_key(self):
        PK = self.key
        with open("RSAPrivateKeyFile", "wb") as RKF:
            RKF.write(PK.export_key("PEM"))

    def load_key(self):
        with open("RSAPrivateKeyFile", "rb") as PKF:
            self.key = RSA.import_key(PKF.read())

    def encrypt(self, data):
        plaintext = b64encode(data.encode())
        rsa_encryption_cipher = PKCS1_v1_5.new(self.key)
        ciphertext = rsa_encryption_cipher.encrypt(plaintext)
        return b64encode(ciphertext).decode()

    def decrypt(self, data):
        ciphertext = b64decode(data.encode())
        rsa_decryption_cipher = PKCS1_v1_5.new(self.key)
        plaintext = rsa_decryption_cipher.decrypt(ciphertext, 16)
        return b64decode(plaintext).decode()


def genrandpass(n):
    passw = ""
    for i in range(n):
        passw += random.choice(DataList)
    return passw


def genrandomkey(ret=0):
    global global_aes_key
    password_provided = genrandpass(40)
    password = password_provided.encode()
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))

    with open("AES_KEY", "w") as ak:
        ak.write(key.decode())
    if ret != 0:
        global_aes_key = str(key.decode())


def encryptAESDF2():
    with open("AES_KEY", "r") as DF2:
        key = DF2.readline()

    with open("DataFile2", "r") as DF2:
        dat = DF2.readline()

    message = dat.encode()

    f = Fernet(key.encode())
    encrypted = f.encrypt(message)
    with open("EncAESD2File", "w") as ef:
        ef.write(encrypted.decode())


def decryptAESD2F():
    with open("AES_KEY", "r") as DF2:
        key = DF2.readline()

    with open("EncAESD2File") as ef:
        encr = ef.read()

    f = Fernet(key.encode())
    decrypted = f.decrypt(encr.encode())
    with open("DecAESD2File", "w") as df:
        df.write(decrypted.decode())


if __name__ == "__main__":
    global global_aes_key
    MainTimeStart = time.time()
    RSACipherObject = RSA_Cipher()
    print("Generating RSA Key | ", end="")
    Mark = time.time()
    RSACipherObject.generate_key(1024)
    print("RSA Key Generation Runtime = " + str(time.time() - Mark))

    print("Generating AES Key | ", end="")
    Mark = time.time()
    genrandomkey(1)
    print("AES Key Generation Runtime = " + str(time.time() - Mark))

    print("Encrypting AES KEYS | ", end="")
    Mark = time.time()
    AES_RSA_KEY = RSACipherObject.encrypt(global_aes_key)
    print("KEY Encryption Runtime = " + str(time.time() - Mark))

    print("Encrypting File | ", end="")
    Mark = time.time()
    encryptAESDF2()
    print("Encryption Runtime = " + str(time.time() - Mark))
    print("Decrypting AES Key | ", end="")
    Mark = time.time()
    RSACipherObject.decrypt(AES_RSA_KEY)
    print("Key Decryption Runtime = " + str(time.time() - Mark))

    print("Decrypting File | ", end="")
    Mark = time.time()
    decryptAESD2F()
    print("File Decryption Runtime = " + str(time.time() - Mark))

    print("Integrity Check = ", end="")
    TarHash = hashlib.md5(open("DecAESD2File", "rb").read()).hexdigest()
    OrgHash = hashlib.md5(open("DataFile2", "rb").read()).hexdigest()
    if TarHash == OrgHash:
        print("PASS! [MD5 : " + OrgHash + "]")
    else:
        print("Fail! [MD5 : " + OrgHash + "]")
    MainTimeEnd = time.time()
    print("Total Time = " + str(MainTimeEnd - MainTimeStart))
