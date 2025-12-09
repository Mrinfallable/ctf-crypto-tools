#!/usr/bin/env python3
import threading
from itertools import product
from Crypto.Cipher import AES
import base64

BS = 16
TARGET_CIPHERTEXT = '6FhQN3nf+eleGf2G2goGBQKKCuC5JQJvq6d4E9sG9x3D7OF6ZIDWXMwg4VQFnC0P'
KEY_PREFIX = "000000000000000000000000008a"
KNOWN_PLAINTEXT_CHECK = b'flag'
NUM_THREADS = 8

found = {'key': None, 'flag': None}
lock = threading.Lock()

def unpad_bytes(b):
    return b[:-b[-1]]

def decrypt_attempt(key_bytes, msg):
    try:
        decoded = base64.b64decode(msg)
        iv = decoded[:BS]
        encrypted_msg = decoded[BS:]
        cipher = AES.new(key_bytes, AES.MODE_CFB, iv, segment_size=AES.block_size * 8)
        decrypted_padded = cipher.decrypt(encrypted_msg)
        if KNOWN_PLAINTEXT_CHECK in unpad_bytes(decrypted_padded):
            plain = unpad_bytes(decrypted_padded).decode('utf-8')
            with lock:
                found['key'] = key_bytes.hex()
                found['flag'] = plain
            return True
    except Exception:
        return False
    return False

def worker(suffixes):
    fixed = bytes.fromhex(KEY_PREFIX)
    for s in suffixes:
        with lock:
            if found['key'] is not None:
                return
        suffix_str = "".join(s)
        key_bytes = fixed + bytes.fromhex(suffix_str)
        if decrypt_attempt(key_bytes, TARGET_CIPHERTEXT):
            return

def main():
    hex_chars = '0123456789abcdef'
    all_suffixes = list(product(hex_chars, repeat=4))
    total = len(all_suffixes)
    if total == 0:
        print("ERR")
        return
    chunk = total // NUM_THREADS
    threads = []
    for i in range(NUM_THREADS):
        start = i * chunk
        end = (i + 1) * chunk if i != NUM_THREADS - 1 else total
        t = threading.Thread(target=worker, args=(all_suffixes[start:end],))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    if found['key']:
        print(found['key'] + " " + found['flag'])
    else:
        print("N")

if __name__ == "__main__":
    main()
