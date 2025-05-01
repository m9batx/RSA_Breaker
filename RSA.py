import random
import math
from sympy import isprime, gcd
from sympy.ntheory.generate import randprime

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

    def encrypt(self, message):
        """Encrypt the message with the public key (e, N)."""
        message_int = int.from_bytes(message.encode(), 'big')  # Convert message to integer
        if message_int >= self.N:
            raise ValueError("Message is too long for encryption with the current key size.")
        ciphertext = pow(message_int, self.e, self.N)
        return ciphertext

    def decrypt(self, ciphertext):
        """Decrypt the ciphertext using a private decryption key (d) calculated locally."""
        # Calculate d as the modular inverse of e mod f_elar (private to this function)
        d = pow(self.e, -1, self.f_elar)
        
        # Perform decryption using the locally calculated d
        decrypted_int = pow(ciphertext, d, self.N)
        
        # Decode carefully, ignoring invalid bytes if necessary
        decrypted_message = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, 'big').decode('utf-8', 'ignore')
        
        return decrypted_message

# Custom function to check if a number is a perfect square
def is_square(n):
    return int(n)**2 == n

# Attack function
def rsa_attack(N, e, ciphertext):
    """Attempt to break RSA by factorizing N using Fermat's factorization method."""
    print("Attacking RSA...")
    
    a = math.isqrt(N) + 1  # Use math.isqrt for integer square root
    while True:
        b2 = a * a - N
        if is_square(b2):  # Check if b2 is a perfect square
            b = math.isqrt(b2)  # Use math.isqrt for integer square root
            break
        a += 1

    # Calculate p and q based on Fermat's factorization
    p1 = a + b
    q1 = a - b

    # Verify if we successfully factored N
    if N == p1 * q1:
        print("Attack successful! Found factors of N.")
        f_elar_brk = (p1 - 1) * (q1 - 1)
        d_brkr = pow(e, -1, f_elar_brk)  # Calculate the private key from factors

        # Decrypt the message using the broken private key
        decrypted_int = pow(ciphertext, d_brkr, N)
        broken_message = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, 'big').decode('utf-8', 'ignore')
        
        print("Decrypted message using broken key:", broken_message)
    else:
        print("Attack failed: could not factorize N.")

# Example usage
rsa = RSA(bits=1023)  # Initialize RSA with 1023-bit primes to create a 2046-bit modulus N

# Display the public keys
print(f"Public key (e, N): ({rsa.e}, {rsa.N})")
print(f"N bit length: {rsa.N.bit_length()} bits")  # Should be close to 2046 bits

# Get the message from the user
message = input("Enter the message to encrypt: ")
print(f"Original message: {message}")

# Encrypt the message
ciphertext = rsa.encrypt(message)
print(f"Encrypted message (as integer): {ciphertext}")

# Attempt an attack
rsa_attack(rsa.N, rsa.e, ciphertext)
