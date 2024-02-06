import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

#long parameters from assignment
q = int("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371", 16)
alpha = int("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5", 16)

#aes encrypt with the libraries
def aes_encrypt(key, message):
    cipher = AES.new(key, AES.MODE_CBC, iv=b'1234567890123456')
    ciphertext = cipher.encrypt(pad(message, AES.block_size))
    return ciphertext

#aes decrypt with the libraries
def aes_decrypt(key, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv=b'1234567890123456')
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext

def diffie_hellman():
    #private keys
    XA = 12345  #alice
    XB = 67890  #bob

    #pubilc keys
    YA = pow(alpha, XA, q) #alice
    YB = pow(alpha, XB, q) #bob

    #shared
    s_a = pow(YB, XA, q)  #alice
    s_b = pow(YA, XB, q)  #bob

    #assert s_a == s_b  # Ensure both parties compute the same shared secret

    #get the symmetric key
    shared_secret = hashlib.sha256(str(s_a).encode()).digest()[:16]

    #sneaky messages teehee
    message_to_bob = b"Hi Bob!"
    encrypted_message_to_bob = aes_encrypt(shared_secret, message_to_bob)

    message_to_alice = b"Hi Alice!"
    encrypted_message_to_alice = aes_encrypt(shared_secret, message_to_alice)

    decrypted_message_to_bob = aes_decrypt(shared_secret, encrypted_message_to_bob)
    decrypted_message_to_alice = aes_decrypt(shared_secret, encrypted_message_to_alice)

    print("Encrypted message to Bob:", encrypted_message_to_bob)
    print("Decrypted message from Bob:", decrypted_message_to_bob.decode())
    print("Encrypted message to Alice:", encrypted_message_to_alice)
    print("Decrypted message from Alice:", decrypted_message_to_alice.decode())

#main to run the program
diffie_hellman()