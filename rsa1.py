import random
import math
from sympy import isprime, gcd
from sympy.ntheory.generate import randprime
import hashlib

class RSA:
    def __init__(self, bits=1023):  # Set to 1023 bits for primes to make N approximately 2046 bits
        self.bits = bits
        self._generate_keys()  # Private method to generate keys

    def _generate_prime(self):
        """Generate a random prime number with specified bit length."""
        return randprime(2**(self.bits - 1), 2**self.bits)

    def _generate_keys(self):
        """Generate the public key components (e, N) for RSA encryption."""
        # Step 1: Generate two distinct prime numbers, p and q
        p = self._generate_prime()
        q = self._generate_prime()
        while p == q:  # Ensure p and q are different
            q = self._generate_prime()

        # Step 2: Calculate N and Euler's totient (f_elar)
        self.N = p * q  # Public modulus with approximately 2046 bits
        self.f_elar = (p - 1) * (q - 1)

        # Step 3: Find a public exponent e
        self.e = random.randrange(2, self.f_elar)
        while gcd(self.e, self.f_elar) != 1 or not isprime(self.e):
            self.e = random.randrange(2, self.f_elar)

    def _oaep_pad(self, message, label=b"", hash_alg=hashlib.sha256):
        """Apply OAEP padding to the message."""
        k = (self.N.bit_length() + 7) // 8  # Length of the RSA modulus in bytes
        h_len = hash_alg().digest_size  # Hash output length

        if len(message) > k - 2 * h_len - 2:
            raise ValueError("Message too long.")

        l_hash = hash_alg(label).digest()
        ps = b"\x00" * (k - len(message) - 2 * h_len - 2)
        db = l_hash + ps + b"\x01" + message
        seed = random.randbytes(h_len)
        db_mask = self._mgf1(seed, k - h_len - 1, hash_alg)
        masked_db = bytes(a ^ b for a, b in zip(db, db_mask))
        seed_mask = self._mgf1(masked_db, h_len, hash_alg)
        masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))
        return b"\x00" + masked_seed + masked_db

    def _oaep_unpad(self, padded_message, label=b"", hash_alg=hashlib.sha256):
        """Remove OAEP padding from the message."""
        k = (self.N.bit_length() + 7) // 8
        h_len = hash_alg().digest_size

        if len(padded_message) != k or padded_message[0] != 0:
            raise ValueError("Decryption error.")

        masked_seed = padded_message[1:h_len + 1]
        masked_db = padded_message[h_len + 1:]

        seed_mask = self._mgf1(masked_db, h_len, hash_alg)
        seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))
        db_mask = self._mgf1(seed, k - h_len - 1, hash_alg)
        db = bytes(a ^ b for a, b in zip(masked_db, db_mask))

        l_hash = hash_alg(label).digest()
        if not db.startswith(l_hash):
            raise ValueError("Decryption error.")

        db = db[len(l_hash):]
        sep_index = db.find(b"\x01")
        if sep_index == -1:
            raise ValueError("Decryption error.")

        return db[sep_index + 1:]

    def _mgf1(self, seed, mask_len, hash_alg):
        """Mask Generation Function (MGF1) based on a hash function."""
        h_len = hash_alg().digest_size
        mask = b""
        for counter in range((mask_len + h_len - 1) // h_len):
            c = counter.to_bytes(4, byteorder="big")
            mask += hash_alg(seed + c).digest()
        return mask[:mask_len]

    def encrypt(self, message):
        """Encrypt the message with the public key (e, N)."""
        padded_message = self._oaep_pad(message.encode())
        message_int = int.from_bytes(padded_message, 'big')  # Convert padded message to integer
        if message_int >= self.N:
            raise ValueError("Message is too long for encryption with the current key size.")
        ciphertext = pow(message_int, self.e, self.N)
        return ciphertext

    def decrypt(self, ciphertext):
        """Decrypt the ciphertext using a private decryption key (d) calculated locally."""
        d = pow(self.e, -1, self.f_elar)  # Calculate d as the modular inverse of e mod f_elar
        decrypted_int = pow(ciphertext, d, self.N)
        padded_message = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, 'big')
        return self._oaep_unpad(padded_message).decode('utf-8', 'ignore')

# Example usage
rsa = RSA(bits=1023)  # Initialize RSA with 1023-bit primes to create a 2046-bit modulus N

# Display the public keys
print(f"Public key (e, N): ({rsa.e})")
print(f"N: {rsa.N}")
print(f"N bit length: {rsa.N.bit_length()} bits")  # Should be close to 2046 bits

# Get the message from the user
message = input("Enter the message to encrypt: ")
print(f"Original message: {message}")

# Encrypt the message
ciphertext = rsa.encrypt(message)
print(f"Encrypted message (as integer): {ciphertext}")

# Decrypt the message
decrypted_message = rsa.decrypt(ciphertext)
print(f"Decrypted message: {decrypted_message}")