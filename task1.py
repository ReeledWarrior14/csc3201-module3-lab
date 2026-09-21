from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256

# IETF hex 1024 bit numbers
q_1024 = 0xB10B8F96_A080E01D_DE92DE5E_AE5D54EC_52C99FBC_FB06A3C6_9A6A9DCA_52D23B61_6073E286_75A23D18_9838EF1E_2EE652C0_13ECB4AE_A9061123_24975C3C_D49B83BF_ACCBDD7D_90C4BD70_98488E9C_219A7372_4EFFD6FA_E5644738_FAA31A4F_F55BCCC0_A151AF5F_0DC8B4BD_45BF37DF_365C1A65_E68CFDA7_6D4DA708_DF1FB2BC_2E4A4371
g_1024 = 0xA4D1CBD5_C3FD3412_6765A442_EFB99905_F8104DD2_58AC507F_D6406CFF_14266D31_266FEA1E_5C41564B_777E690F_5504F213_160217B4_B01B886A_5E91547F_9E2749F4_D7FBD7D3_B9A92EE1_909D0D22_63F80A76_A6A24C08_7A091F53_1DBF0A01_69B6A28A_D662A4D1_8E73AFA3_2D779D59_18D08BC8_858F4DCE_F97C2A24_855E6EEB_22B3B2E5

private_key_1 = 43
private_key_2 = 200

iv = get_random_bytes(16)

def pad(message):
    padding_length = 16 - (len(message) % 16)
    padding = bytes([padding_length] * padding_length)
    return message + padding

class Alice:
    private_key = None
    public_key = None
    shared_secret = None
    key = None
    q = None
    g = None

    def __init__(self, private_key):
        self.private_key = private_key

    def generate_public_key(self, q, g):
        self.q = q
        self.g = g
        self.public_key = pow(self.g, self.private_key, self.q)
        return self.public_key

    def generate_shared_secret(self, bob_public_key):
        self.shared_secret = pow(bob_public_key, self.private_key, self.q)

    def generate_key(self):
        if self.shared_secret is None:
            raise ValueError("Shared secret has not been generated yet.")
        self.key = SHA256.new(str(self.shared_secret).encode()).digest()[:16]

    def encrypt_message(self, message):
        if self.key is None:
            raise ValueError("Key has not been generated yet.")
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        padded_message = pad(message.encode("ascii"))
        ciphertext = cipher.encrypt(padded_message)
        return ciphertext

    def decrypt_message(self, ciphertext):
        if self.key is None:
            raise ValueError("Key has not been generated yet.")
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted_padded_message = cipher.decrypt(ciphertext)
        padding_length = decrypted_padded_message[-1]
        decrypted_message = decrypted_padded_message[:-padding_length]
        print("Alice received: " + decrypted_message.decode("ascii"))
        return decrypted_message.decode("ascii")

class Bob:
    private_key = None
    public_key = None
    shared_secret = None
    key = None

    def __init__(self, private_key):
        self.private_key = private_key

    def generate_public_key(self, q, g):
        self.q = q
        self.g = g
        self.public_key = pow(self.g, self.private_key, self.q)
        return self.public_key

    def generate_shared_secret(self, alice_public_key):
        self.shared_secret = pow(alice_public_key, self.private_key, self.q)

    def generate_key(self):
        if self.shared_secret is None:
            raise ValueError("Shared secret has not been generated yet.")
        self.key = SHA256.new(str(self.shared_secret).encode()).digest()[:16]

    def encrypt_message(self, message):
        if self.key is None:
            raise ValueError("Key has not been generated yet.")
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        padded_message = pad(message.encode("ascii"))
        ciphertext = cipher.encrypt(padded_message)
        return ciphertext

    def decrypt_message(self, ciphertext):
        if self.key is None:
            raise ValueError("Key has not been generated yet.")
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted_padded_message = cipher.decrypt(ciphertext)
        padding_length = decrypted_padded_message[-1]
        decrypted_message = decrypted_padded_message[:-padding_length]
        print("Bob received: " + decrypted_message.decode("ascii"))
        return decrypted_message.decode("ascii")


#DH example
print("\nfixed small nums")
q = 37
g = 5

alice = Alice(private_key_1)
bob = Bob(private_key_2)

alice_pub_key = alice.generate_public_key(q,g)
bob_pub_key = bob.generate_public_key(q,g)

alice.generate_shared_secret(bob_pub_key)
bob.generate_shared_secret(alice_pub_key)

print("Alice's shared secret: ", alice.shared_secret)
print("Bob shared secret: ", bob.shared_secret)
print("Shared secrets are the same! ", alice.shared_secret == bob.shared_secret)

alice.generate_key()
bob.generate_key()

print("AES keys are the same! ", alice.key == bob.key)

# Diffie-Hellman Key Exchange (1024 bit)
print("\n1024 bits")
alice = Alice(private_key_1)
bob = Bob(private_key_2)

alice_pub_key = alice.generate_public_key(q_1024, g_1024)
bob_pub_key = bob.generate_public_key(q_1024, g_1024)

alice.generate_shared_secret(bob_pub_key)
bob.generate_shared_secret(alice_pub_key)

print("Alice shared secret: ", alice.shared_secret)
print("Bob shared secret: ", bob.shared_secret)
print("Shared secrets are the same! ", alice.shared_secret == bob.shared_secret)

alice.generate_key()
bob.generate_key()

print("Alice AES key:", alice.key.hex())
print("Bob AES key:", bob.key.hex())
print("AES keys are the same! ", alice.key == bob.key)

#Alice to Bob
secret_message = alice.encrypt_message("Hello Bob, this is Alice!")
print("Encrypted message from Alice to Bob:", ''.join([hex(x)[2:].zfill(2) for x in secret_message]))

bob.decrypt_message(secret_message)

#Bob to Alice
secret_message_bob = bob.encrypt_message("Hello Alice, this is Bob!")
print("\nEncrypted message from Bob to Alice:", ''.join([hex(x)[2:].zfill(2) for x in secret_message_bob]))

alice.decrypt_message(secret_message_bob)
