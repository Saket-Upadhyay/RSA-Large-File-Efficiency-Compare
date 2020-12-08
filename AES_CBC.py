import base64
import hashlib
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
from cryptography.fernet import Fernet
import random

DataList = [
    "B",
    "A",
    "C",
    "D",
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


def genrandpass(n):
    passw = ""
    for i in range(n):
        passw += random.choice(DataList)
    return passw


def genrandomkey():
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
    MainTimeStart = time.time()
    print("Generating Key | ", end="")
    Mark = time.time()
    genrandomkey()
    print("Key Generation Runtime = " + str(time.time() - Mark))

    print("Encrypting File | ", end="")
    Mark = time.time()
    encryptAESDF2()
    print("Encryption Runtime = " + str(time.time() - Mark))
    print("Decrypting File | ", end="")
    Mark = time.time()
    decryptAESD2F()
    print("Decryption Runtime = " + str(time.time() - Mark))

    print("Integrity Check = ", end="")
    TarHash = hashlib.md5(open("DecAESD2File", "rb").read()).hexdigest()
    OrgHash = hashlib.md5(open("DataFile2", "rb").read()).hexdigest()
    if TarHash == OrgHash:
        print("PASS! [MD5 : " + OrgHash + "]")
    else:
        print("Fail! [MD5 : " + OrgHash + "]")
    MainTimeEnd = time.time()
    print("Total Time = " + str(MainTimeEnd - MainTimeStart))
