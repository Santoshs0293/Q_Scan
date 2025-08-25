#crypto_db.py
CLASSICAL_ALGORITHMS = {
    "RSA": {"quantum_vulnerable": True, "pqc_alternative": "Kyber, FrodoKEM, CRYSTALS-Dilithium (signatures)"},
    "ECDH": {"quantum_vulnerable": True, "pqc_alternative": "Kyber, NTRU"},
    "ECDSA": {"quantum_vulnerable": True, "pqc_alternative": "Sphincs+, Falcon, CRYSTALS-Dilithium"},
    "AES-128": {"quantum_vulnerable": True, "pqc_alternative": "AES-256, ChaCha20"},
    "3DES": {"quantum_vulnerable": True, "pqc_alternative": "AES-256, ChaCha20"},
    "SHA1": {"quantum_vulnerable": True, "pqc_alternative": "SHA-256"},
    "MD5": {"quantum_vulnerable": True, "pqc_alternative": "SHA-256"},
    "AES-256": {"quantum_vulnerable": False, "pqc_alternative": None},
    "SHA-256": {"quantum_vulnerable": False, "pqc_alternative": None}
}

def is_quantum_vulnerable(algorithm):
    return CLASSICAL_ALGORITHMS.get(algorithm, {}).get("quantum_vulnerable", False)

def get_pqc_alternative(algorithm):
    return CLASSICAL_ALGORITHMS.get(algorithm, {}).get("pqc_alternative", "Unknown")