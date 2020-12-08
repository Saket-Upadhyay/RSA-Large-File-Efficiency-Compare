import hashlib
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Random import new as Random
from base64 import b64encode
from base64 import b64decode
import random
import time
from os import system

DataList = [
    "A",
    "B",
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


def generatedata(charnum):
    data = ""
    for i in range(charnum):
        RC = random.choice(DataList)
        data = data + RC
    return data


def generatedatafile(charnum):
    with open("DataFile2", "w") as DF:
        for i in range(charnum):
            RC = random.choice(DataList)
            DF.write(RC)


def encryptD2file():
    EncryptedDataList = []
    RSACipherObject = RSA_Cipher()
    RSACipherObject.load_key()

    with open("DataFile2", "r") as DF2:
        Fdata = DF2.read()
    s = 0
    e = s + 80

    for i in range(10000):

        if Fdata[s:e] == "":
            break
        EncryptedDataList.append(RSACipherObject.encrypt(Fdata[s:e]))
        s = s + 80
        e = e + 80
    try:
        system("del EncD2File")
    except Exception:
        print("NF : Ignore")
    with open("EncD2File", "a+") as EF:
        for line in EncryptedDataList:
            EF.write(line + "\n")


def decryptD2file():
    RSACipherObject = RSA_Cipher()
    RSACipherObject.load_key()
    with open("EncD2File", "r") as EF:
        ETs = EF.readlines()
    try:
        system("del DecD2File")
    except Exception:
        print("NF: Ignore")
    with open("DecD2File", "a+") as DF:
        t = 0
        for i in ETs:

            DF.write(RSACipherObject.decrypt(i))
            t += 1


if __name__ == "__main__":
    MainTimeStart = time.time()
    RSACipherObject = RSA_Cipher()

    # Generate Keys youself by using these functions :
    # RSACipherObject.generate_key(1024)
    # RSACipherObject.save_key()

    print("Generating Key | ", end="")
    Mark = time.time()
    RSACipherObject.generate_key(1024)
    RSACipherObject.save_key()
    print("Key Generation Runtime = " + str(time.time() - Mark))

    print("Encrypting File | ", end="")
    Mark = time.time()
    encryptD2file()
    print("Encryption Runtime = " + str(time.time() - Mark))

    print("Decrypting File | ", end="")
    Mark = time.time()
    decryptD2file()
    print("Decryption Runtime = " + str(time.time() - Mark))

    print("Integrity Check = ", end="")
    TarHash = hashlib.md5(open("DecD2File", "rb").read()).hexdigest()
    OrgHash = hashlib.md5(open("DataFile2", "rb").read()).hexdigest()
    if TarHash == OrgHash:
        print("PASS! [MD5 : " + OrgHash + "]")
    else:
        print("Fail! [MD5 : " + OrgHash + "]")

    MainTimeEnd = time.time()
    print("Total Time = " + str(MainTimeEnd - MainTimeStart))
