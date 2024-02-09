from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def diffie_hellman(p, g, a):
    # Compute public value (Y)
    A = pow(g, a, p)
    return A

def generate_session_key(p, B, a):
    s = pow(B, a, p)
    return sha256(str(s).encode()).digest()

def aes_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return ciphertext

def aes_decrypt(key, ciphertext):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()

def main():
    # Parameters
    q = 23
    alpha = 5
    X_Alice = 6
    X_Bob = 15
    message0 = "Hi Bob!"
    message1 = "Hi Alice!"
    
    alpha_mod = q - 1 


    #a computes and sends YA to Bob
    Y_Alice = diffie_hellman(q, alpha, X_Alice)
    #b computes and sends YB to Alice
    Y_Bob = diffie_hellman(q, alpha_mod, X_Bob)

    #m computes session keys using modified alpha
    s_Alice = generate_session_key(q, alpha_mod, X_Alice)
    s_Bob = generate_session_key(q, alpha_mod, X_Bob)

    key = sha256(str(s_Alice).encode()).digest()
    ciphertext0 = aes_encrypt(key, message0)
    ciphertext1 = aes_encrypt(key, message1)

    #decrypts
    decrypted_message0 = aes_decrypt(key, ciphertext0)
    decrypted_message1 = aes_decrypt(key, ciphertext1)

    print("Decrypted message 0:", decrypted_message0)
    print("Decrypted message 1:", decrypted_message1)

if __name__ == "__main__":
    main()
