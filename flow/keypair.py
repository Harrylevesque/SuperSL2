from kyber_py.ml_kem import ML_KEM_1024
import hashlib


# Generate keypair
ek, dk = ML_KEM_1024.keygen()  # ek: encapsulation key (public), dk: decapsulation key (private)



print("Encapsulation Key (Public):", ek)
print("Decapsulation Key (Private):", dk)


# Use the actual key bytes for encapsulation/decapsulation
shared_key, ciphertext = ML_KEM_1024.encaps(ek)  # 32-byte shared_key, ciphertext ~1568 bytes for 1024

# Decapsulate to check
recovered_key = ML_KEM_1024.decaps(dk, ciphertext)

# Verify it's "ok"
assert shared_key == recovered_key, "Key mismatch!"
print("Kyber-1024 check passed: keys match.")
