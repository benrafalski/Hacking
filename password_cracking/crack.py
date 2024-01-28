#!/bin/python3
import hashlib
import base64

# from: https://github.com/apache/ofbiz/blob/trunk/framework/base/src/main/java/org/apache/ofbiz/base/crypto/HashCrypt.java

def cryptBytes(hashType, salt, bytes):
    hash = f"${hashType}${salt}${bytes}"
    return hash

def getCyptedBytes(salt, bytes):
    hash_object = hashlib.sha1(str.encode(salt) + str.encode(bytes))
    pbHash = hash_object.digest()
    return base64.urlsafe_b64encode(pbHash)


with open("/usr/share/wordlists/kali-wordlists/rockyou.txt", "r", encoding='latin1') as f:
    lines = f.readlines()
    for l in lines:
        test = getCyptedBytes('d', l.strip())
        if(b"uP0_QaVBpDWFeo8-dRzDqRwXQ2I" in test):
            print(f'b64hash: {test} --- password: {l}')






