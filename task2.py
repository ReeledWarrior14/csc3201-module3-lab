from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256


# q = 37
# g = 5

# IETF hex 1024 bit numbers
q = 0xB10B8F96_A080E01D_DE92DE5E_AE5D54EC_52C99FBC_FB06A3C6_9A6A9DCA_52D23B61_6073E286_75A23D18_9838EF1E_2EE652C0_13ECB4AE_A9061123_24975C3C_D49B83BF_ACCBDD7D_90C4BD70_98488E9C_219A7372_4EFFD6FA_E5644738_FAA31A4F_F55BCCC0_A151AF5F_0DC8B4BD_45BF37DF_365C1A65_E68CFDA7_6D4DA708_DF1FB2BC_2E4A4371
g = 0xA4D1CBD5_C3FD3412_6765A442_EFB99905_F8104DD2_58AC507F_D6406CFF_14266D31_266FEA1E_5C41564B_777E690F_5504F213_160217B4_B01B886A_5E91547F_9E2749F4_D7FBD7D3_B9A92EE1_909D0D22_63F80A76_A6A24C08_7A091F53_1DBF0A01_69B6A28A_D662A4D1_8E73AFA3_2D779D59_18D08BC8_858F4DCE_F97C2A24_855E6EEB_22B3B2E5

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

        # undo padding
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

        # undo padding
        padding_length = decrypted_padded_message[-1]
        decrypted_message = decrypted_padded_message[:-padding_length]

        print("Bob received: " + decrypted_message.decode("ascii"))
        return decrypted_message.decode("ascii")

class Mallory: 
    shared_secret = None
    q = None

    def __init__(self, q):
        self.q = q

    def intercept_public_key(self):
        self.shared_secret = 0
        return self.q
    
    def change_generator_one(self):
        self.shared_secret = 1
        return 1

    def change_generator_q(self):
        self.shared_secret = 0
        return self.q

    def change_generator_q_minus_one(self):
        self.shared_secret = 1
        return self.q - 1

    def decrypt_message(self, ciphertext):
        if self.shared_secret is None:
            raise ValueError("Shared secret has not been generated yet.")
        key = SHA256.new(str(self.shared_secret).encode()).digest()[:16]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_padded_message = cipher.decrypt(ciphertext)

        # undo padding
        padding_length = decrypted_padded_message[-1]
        decrypted_message = decrypted_padded_message[:-padding_length]

        print("Mallory intercepted and decrypted: " + decrypted_message.decode("ascii"))
        return decrypted_message.decode("ascii")
    


# Mallory intercepts public keys
alice = Alice(private_key_1)
bob = Bob(private_key_2)

mallory = Mallory(q)

alice_pub_key = alice.generate_public_key(q, g)
bob_pub_key = bob.generate_public_key(q, g)

### Mallory intervenes
bob_pub_key = mallory.intercept_public_key()
alice_pub_key = mallory.intercept_public_key()

alice.generate_shared_secret(bob_pub_key)
bob.generate_shared_secret(alice_pub_key)

alice.generate_key()
bob.generate_key()

#do Alice and Bob think they have the same shared secret
print("\npublic key replacement")
print("Alice shared secret: ", alice.shared_secret)
print("Bob shared secret: ", bob.shared_secret)
print("Shared secrets match! ", alice.shared_secret == bob.shared_secret)

encrypted_message = alice.encrypt_message("Oh no! Mallory intercepted the public keys!")

# Mallory knows the secret will be 0, (since she changed the public keys to q), so she can compute the key and decrypt the message
mallory.decrypt_message(encrypted_message)

bob.decrypt_message(encrypted_message)

#mallory can decrypt in both ways
secret_message_bob = bob.encrypt_message("Bob's message has been intercepted!")
mallory.decrypt_message(secret_message_bob)
alice.decrypt_message(secret_message_bob)


print("\n\n\n")


# Mallory replaces the generator with 1
alice = Alice(private_key_1)
bob = Bob(private_key_2)

mallory = Mallory(q)

### Mallory intervenes
g = mallory.change_generator_one()

alice_pub_key = alice.generate_public_key(q, g)
bob_pub_key = bob.generate_public_key(q, g)

alice.generate_shared_secret(bob_pub_key)
bob.generate_shared_secret(alice_pub_key)

alice.generate_key()
bob.generate_key()

print("\nGenerator Attack")
print("Alice shared secret: ", alice.shared_secret)
print("Bob shared secret: ", bob.shared_secret)
print("Shared secrets match! ", alice.shared_secret == bob.shared_secret)

encrypted_message = alice.encrypt_message("Oh no! Mallory changed the generator to 1!")

# Mallory knows the secret will be 1, (since she changed the generator to 1)
mallory.decrypt_message(encrypted_message)

bob.decrypt_message(encrypted_message)

#bob to Alice
secret_message_bob = bob.encrypt_message("Bob's message has been intercepted with g = 1")
mallory.decrypt_message(secret_message_bob)
alice.decrypt_message(secret_message_bob)

print("\n\n\n")


# Mallory replaces the generator with q
alice = Alice(private_key_1)
bob = Bob(private_key_2)

mallory = Mallory(q)

### Mallory intervenes
g = mallory.change_generator_q()

alice_pub_key = alice.generate_public_key(q, g)
bob_pub_key = bob.generate_public_key(q, g)

alice.generate_shared_secret(bob_pub_key)
bob.generate_shared_secret(alice_pub_key)

alice.generate_key()
bob.generate_key()

print("\nGenerator Attack: g=q")
print("Alice shared secret: ", alice.shared_secret)
print("Bob shared secret: ", bob.shared_secret)
print("Shared secrets match! ", alice.shared_secret == bob.shared_secret)

encrypted_message = alice.encrypt_message("Oh no! Mallory changed the generator to q!")

# Mallory knows the secret will be 0, (since she changed the generator to q)
mallory.decrypt_message(encrypted_message)

bob.decrypt_message(encrypted_message)

secret_message_bob = bob.encrypt_message("Bob's message has been intercepted with g=q")
mallory.decrypt_message(secret_message_bob)
alice.decrypt_message(secret_message_bob)


print("\n\n\n")


# Mallory replaces the generator with q - 1
alice = Alice(private_key_1)
bob = Bob(private_key_2)

mallory = Mallory(q)

### Mallory intervenes
g = mallory.change_generator_q_minus_one()

alice_pub_key = alice.generate_public_key(q, g)
bob_pub_key = bob.generate_public_key(q, g)

alice.generate_shared_secret(bob_pub_key)
bob.generate_shared_secret(alice_pub_key)

alice.generate_key()
bob.generate_key()

print("\nGenerator Attack: g=q-1")
print("Alice public key: ", alice_pub_key)
print("Bob public key: ", bob_pub_key)
print("Alice shared secret: ", alice.shared_secret)
print("Bob shared secret: ", bob.shared_secret)
print("Shared secrets match! ", alice.shared_secret == bob.shared_secret)

encrypted_message = alice.encrypt_message("Oh no! Mallory changed the generator to q-1!")

# Mallory knows the secret will be 1, (since she changed the generator to q-1)
mallory.decrypt_message(encrypted_message)

bob.decrypt_message(encrypted_message)

secret_message_bob = bob.encrypt_message("Bob's message has been intercepted with g = q-1")
mallory.decrypt_message(secret_message_bob)

alice.decrypt_message(secret_message_bob)