from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256

from Crypto.Util.number import getPrime
import math

# assume all parties already know the iv and shared it
iv = get_random_bytes(16)

def pad(message):
    padding_length = 16 - (len(message) % 16)
    padding = bytes([padding_length] * padding_length)
    return message + padding

def mod_inverse(a, m):
    """compute the multiplicative inverse"""

    def egcd(a, b):
        if a == 0:
            return b, 0, 1
        else:
            g, y, x = egcd(b % a, a)
            return g, x - (b // a) * y, y

    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("Inverse does not exist")
    else:
        return x % m

def RSA_keygen(p, q, e=65537):
    """Generate a pair of RSA keys (public and private)"""
    n = p * q
    lambda_n = math.lcm(p - 1, q - 1)

    # Compute d
    d = mod_inverse(e, lambda_n)

    public = (e, n)
    private = (d, n)

    return public, private

def RSA_encrypt(message, public_key):
    """Encrypt a message using the RSA public key"""
    e, n = public_key
    ciphertext = pow(message, e, n)
    return ciphertext

def RSA_decrypt(ciphertext, private_key):
    """Decrypt a message using the RSA private key"""
    d, n = private_key
    decrypted_message = pow(ciphertext, d, n)
    return decrypted_message

def message_to_int(message):
    """Convert a string message to an integer"""
    return int.from_bytes(message.encode('ascii'), byteorder='big')

def int_to_message(message_int):
    """Convert an integer back to a string message"""
    bytes_length = (message_int.bit_length() + 7) // 8
    return message_int.to_bytes(bytes_length, byteorder='big').decode('ascii')

def RSA_encrypt_text(message, public_key):
    """Encrypt message using RSA public key"""
    return RSA_encrypt(message_to_int(message), public_key)

def RSA_decrypt_text(ciphertext_int, private_key):
    """Decrypt a message using the RSA private key"""
    d, n = private_key
    decrypted_int = pow(ciphertext_int, d, n)
    return int_to_message(decrypted_int)

def CBC_encrypt(message, key, iv):
    """Encrypt a message using AES in CBC mode"""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(message.encode('ascii'))
    ciphertext = cipher.encrypt(padded_message)
    return ciphertext

def CBC_decrypt(ciphertext, key, iv):
    """Decrypt a message using AES in CBC mode"""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = cipher.decrypt(ciphertext)
    padding_length = padded_message[-1]
    message = padded_message[:-padding_length].decode('ascii')
    return message

def verify_signature(message, signature, public_key):
    """Verify a signature using a public key"""
    if isinstance(message, str):
        message = message_to_int(message)
    e, n = public_key
    return message % n == pow(signature, e, n)


class Alice:
    public_key = None
    private_key = None
    secret = None
    key = None

    def __init__(self, public_key, private_key):
        self.public_key = public_key
        self.private_key = private_key

    def receive_secret(self, bob_secret):
        """Compute the shared secret from Bob"""
        self.secret = RSA_decrypt(bob_secret, self.private_key)

    def generate_key(self):
        if self.secret is None:
            raise ValueError("Shared secret has not been generated yet.")
        self.key = SHA256.new(str(self.secret).encode()).digest()[:16]

    def encrypt_message(self, message):
        if self.key is None:
            raise ValueError("Key has not been generated yet.")
        ciphertext = CBC_encrypt(message, self.key, iv)
        return ciphertext

    def decrypt_message(self, ciphertext):
        if self.key is None:
            raise ValueError("Key has not been generated yet.")
        message = CBC_decrypt(ciphertext, self.key, iv)
        return message

    def sign_message(self, message):
        """Sign a message using Alice's private key"""
        signature = pow(message_to_int(message), self.private_key[0], self.private_key[1])
        return signature

class Bob:
    secret = None
    key = None

    def send_secret(self, alice_public_key):
        """Compute and encrypt a shared secret using Alice's public key"""
        self.secret = getPrime(128)  # Generate a random prime as the shared secret
        encrypted_secret = RSA_encrypt(self.secret, alice_public_key)

        # Bob already has the secret so he can generate the key for AES encryption
        self.generate_key()

        return encrypted_secret

    def generate_key(self):
        if self.secret is None:
            raise ValueError("Shared secret has not been generated yet.")
        self.key = SHA256.new(str(self.secret).encode()).digest()[:16]

    def encrypt_message(self, message):
        if self.key is None:
            raise ValueError("Key has not been generated yet.")
        ciphertext = CBC_encrypt(message, self.key, iv)
        return ciphertext

    def decrypt_message(self, ciphertext):
        if self.key is None:
            raise ValueError("Key has not been generated yet.")
        message = CBC_decrypt(ciphertext, self.key, iv)
        return message

class Mallory:
    secret = None
    key = None
    
    def intercept_and_replace_secret(self, alice_public_key):
        """Intercept the secret sent from Bob to Alice and replace it"""

        # Generate a new secret to send to Alice
        self.secret = getPrime(128)  # Generate a random prime as the new shared secret
        encrypted_secret = RSA_encrypt(self.secret, alice_public_key)

        self.generate_key()

        return encrypted_secret

    def generate_key(self):
        if self.secret is None:
            raise ValueError("Shared secret has not been generated yet.")
        self.key = SHA256.new(str(self.secret).encode()).digest()[:16]

    def encrypt_message(self, message):
            if self.key is None:
                raise ValueError("Key has not been generated yet.")
            ciphertext = CBC_encrypt(message, self.key, iv)
            return ciphertext
    
    def decrypt_message(self, ciphertext):
        if self.key is None:
            raise ValueError("Key has not been generated yet.")
        message = CBC_decrypt(ciphertext, self.key, iv)
        return message

    def forge_signature(self, signature1, signature2, alice_public_key):
        """Forge a signature for a message from Alice's using two previous messages"""
        n = alice_public_key[1]
        new_signature = (signature1 * signature2) % n

        return new_signature



p = getPrime(1024)
q = getPrime(1024)


# apparently technically e has to be coprime and less than lambda_n?
e = 65537

alice_rsa_public_key, alice_rsa_private_key = RSA_keygen(p, q, e)

alice = Alice(alice_rsa_public_key, alice_rsa_private_key)
bob = Bob()
mallory = Mallory()

test = "This is a secret message!"
encrypted_message = RSA_encrypt_text(test, alice_rsa_public_key)
decrypted_message = RSA_decrypt_text(encrypted_message, alice_rsa_private_key)
print("Orginal Message: ", test)
print("Encrypted Message: ", encrypted_message)
print("Decrypted Message: ", decrypted_message)

# RSA handshake
bob_secret = bob.send_secret(alice.public_key)
intercepted_secret = mallory.intercept_and_replace_secret(alice.public_key) # Mallory intercepts and replaces the secret
alice.receive_secret(intercepted_secret) # Alice receives the intercepted secret

alice.generate_key()
print("Bob's original secret: ", bob.secret)
print("Mallory's secret: ", mallory.secret)
print("Alice's secret: ", alice.secret)
print("Mallory knows secret of Alice: ", mallory.secret == alice.secret)

# Conversation with AES-CBC
encrypted_message = alice.encrypt_message("Hi Bob!")
# print("Encrypted message: ", encrypted_message)
print("Bob received: ", bob.decrypt_message(encrypted_message))
print("Mallory intercepted: ", mallory.decrypt_message(encrypted_message))



print("\n\n")

# signature forgery

alice_message1 = "Hi Bob!"
alice_message2 = "This is Alice!"

signature1 = alice.sign_message(alice_message1)
signature2 = alice.sign_message(alice_message2)

print("verify: " + str(verify_signature(alice_message1, signature1, alice.public_key)) + ", " + str(verify_signature(alice_message2, signature2, alice.public_key)))

# m3 = m1 * m2
mallory_message = message_to_int(alice_message1) * message_to_int(alice_message2)
new_signature = mallory.forge_signature(signature1, signature2, alice.public_key)

# print("Forged signature: ", new_signature)

print("verify forged signature: " + str(verify_signature(mallory_message, new_signature, alice.public_key)))











# p = 61
# q = 53

# e = 17

# m = 65
# encrypted = pow(m, public_key[0], public_key[1])
# print("Encrypted message:", encrypted)

# decrypted = pow(encrypted, private_key[0], private_key[1])
# print("Decrypted message:", decrypted)