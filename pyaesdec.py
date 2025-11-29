import os
import io
import time
import argparse
import tempfile
from multiprocessing import Pool, Manager, cpu_count
import pyAesCrypt

def try_decrypt_stream(enc_path, password):
        try:
        filesize = os.path.getsize(enc_path)
    except OSError:
        return False
    try:
        with open(enc_path, "rb") as fin:
            out = io.BytesIO()
            pyAesCrypt.decryptStream(fin, out, password, 64 * 1024, filesize)
            return True

def try_decrypt_file(enc_path, password, tmp_out):
    try:
        pyAesCrypt.decryptFile(enc_path, tmp_out, password)
        try:
            os.remove(tmp_out)
        except Exception:
            pass
        return True

def worker(chunk_passwords, enc_path, use_stream, tmp_out):
    # iterate chunk
    for pw in chunk_passwords:
        if use_stream:
            try:
                ok = try_decrypt_stream(enc_path, pw)
            except AttributeError:
                ok = try_decrypt_file(enc_path, pw, tmp_out)
        else:
            ok = try_decrypt_file(enc_path, pw, tmp_out)
        if ok:
            return pw
    return None

def chunked_passwords(wordlist_path, chunk_size):
    with open(wordlist_path, "r", encoding="latin-1", errors="ignore") as fh:
        chunk = []
        for line in fh:
            pw = line.rstrip("\n\r")
            if not pw:
                continue
            chunk.append(pw)
            if len(chunk) >= chunk_size:
                yield chunk
                chunk = []
        if chunk:
            yield chunk

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("encfile")
    ap.add_argument("wordlist")
    ap.add_argument("--processes", "-n", type=int, default=cpu_count())
    ap.add_argument("--chunk", "-c", type=int, default=1024)
    ap.add_argument("--tmpout")
    args = ap.parse_args()

    enc = args.encfile
    wordlist = args.wordlist
    procs = max(1, args.processes)
    chunk_size = max(1, args.chunk)

    # decide stream vs file method
    use_stream = hasattr(pyAesCrypt, "decryptStream")
    if not use_stream:
        tmp_dir = "/dev/shm" if os.path.isdir("/dev/shm") and os.access("/dev/shm", os.W_OK) else tempfile.gettempdir()
        tmp_out = args.tmpout or os.path.join(tmp_dir, "pyaes_bruteforce.tmp")
    else:
        tmp_out = None

    print(f"enc={enc} wordlist={wordlist} processes={procs} chunk={chunk_size} use_stream={use_stream} tmp_out={tmp_out}")

    manager = Manager()
    found = manager.dict()
    start = time.time()
    attempts = manager.Value('i', 0)

    def init_worker():
        pass

    pool = Pool(processes=procs, initializer=init_worker)
    try:
        gen = chunked_passwords(wordlist, chunk_size)
        processed_chunks = 0
        for result in pool.imap_unordered(lambda chunk: worker(chunk, enc, use_stream, tmp_out), gen, chunksize=1):
            processed_chunks += 1
            if result:
                found['pw'] = result
                print(f"\npassword: {result}")
                pool.terminate()
                pool.join()
                return
            if processed_chunks % 10 == 0:
                elapsed = time.time() - start
                approx = processed_chunks * chunk_size
                print(f"processed {processed_chunks}")
        pool.close()
        pool.join()
        print("not found in wordlist")
    except KeyboardInterrupt:
        print("terminating workers")
        pool.terminate()
        pool.join()

if __name__ == "__main__":
    main()

