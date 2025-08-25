ALGORITHMS = {
    # Classical Asymmetric (vulnerable to Shor's algorithm)
    "RSA": {
        "type": "SIG/KEM",
        "vulnerable": True,
        "alternative": "CRYSTALS-Dilithium for signatures or CRYSTALS-Kyber for key exchange",
        "security_level": lambda bits: bits // 18 if bits else 0,  # e.g., 2048 -> ~112 bits
        "severity": lambda bits: "High"  # Shor's algorithm breaks RSA
    },
    "DSA": {
        "type": "SIG",
        "vulnerable": True,
        "alternative": "CRYSTALS-Dilithium",
        "security_level": lambda bits: bits // 18 if bits else 0,
        "severity": lambda bits: "High"
    },
    "DH": {
        "type": "KEM",
        "vulnerable": True,
        "alternative": "CRYSTALS-Kyber",
        "security_level": lambda bits: bits // 18 if bits else 0,
        "severity": lambda bits: "High"
    },
    "ECDSA": {
        "type": "SIG",
        "vulnerable": True,
        "alternative": "CRYSTALS-Dilithium",
        "security_level": lambda bits: bits // 2 if bits else 0,
        "severity": lambda bits: "High"
    },
    "ECDH": {
        "type": "KEM",
        "vulnerable": True,
        "alternative": "CRYSTALS-Kyber",
        "security_level": lambda bits: bits // 2 if bits else 0,
        "severity": lambda bits: "High"
    },
    
    # Classical Symmetric (vulnerable to Grover's if key too small)
    "AES": {
        "type": "SYM",
        "vulnerable": lambda bits: bits < 256,
        "alternative": "AES-256",
        "security_level": lambda bits: bits // 2 if bits else 0,
        "severity": lambda bits: "High" if bits < 128 else "Medium" if bits < 256 else "Low"
    },
    "3DES": {
        "type": "SYM",
        "vulnerable": True,
        "alternative": "AES-256",
        "security_level": lambda bits: 56,
        "severity": lambda bits: "High"
    },
    "DES": {
        "type": "SYM",
        "vulnerable": True,
        "alternative": "AES-256",
        "security_level": lambda bits: 56,
        "severity": lambda bits: "High"
    },
    "Blowfish": {
        "type": "SYM",
        "vulnerable": lambda bits: bits < 128,
        "alternative": "AES-256",
        "security_level": lambda bits: bits // 2 if bits else 0,
        "severity": lambda bits: "High" if bits < 128 else "Medium"
    },
    "Twofish": {
        "type": "SYM",
        "vulnerable": lambda bits: bits < 256,
        "alternative": "AES-256",
        "security_level": lambda bits: bits // 2 if bits else 0,
        "severity": lambda bits: "High" if bits < 128 else "Medium" if bits < 256 else "Low"
    },
    "ChaCha20": {
        "type": "SYM",
        "vulnerable": False,
        "alternative": None,
        "security_level": lambda bits: 128,
        "severity": lambda bits: "Low"
    },
    "RC4": {
        "type": "SYM",
        "vulnerable": True,
        "alternative": "ChaCha20",
        "security_level": lambda bits: bits // 2 if bits else 0,
        "severity": lambda bits: "High"
    },
    
    # Hashes (collision attacks possible with Grover)
    "MD5": {
        "type": "HASH",
        "vulnerable": True,
        "alternative": "SHA-256",
        "security_level": lambda bits: 64,
        "severity": lambda bits: "High"
    },
    "SHA1": {
        "type": "HASH",
        "vulnerable": True,
        "alternative": "SHA-256",
        "security_level": lambda bits: 80,
        "severity": lambda bits: "High"
    },
    "SHA-256": {
        "type": "HASH",
        "vulnerable": False,
        "alternative": None,
        "security_level": lambda bits: 128,
        "severity": lambda bits: "Medium"
    },
    "SHA-384": {
        "type": "HASH",
        "vulnerable": False,
        "alternative": None,
        "security_level": lambda bits: 192,
        "severity": lambda bits: "Low"
    },
    "SHA-512": {
        "type": "HASH",
        "vulnerable": False,
        "alternative": None,
        "security_level": lambda bits: 256,
        "severity": lambda bits: "Low"
    },
    
    # Post-Quantum (safe)
    "CRYSTALS-Kyber": {
        "type": "KEM",
        "vulnerable": False,
        "alternative": None,
        "security_level": lambda level: {512: 128, 768: 192, 1024: 256}.get(level, 128),
        "severity": lambda level: "Low"
    },
    "Kyber": {
        "type": "KEM",
        "vulnerable": False,
        "alternative": None,
        "security_level": lambda level: {512: 128, 768: 192, 1024: 256}.get(level, 128),
        "severity": lambda level: "Low"
    },
    "CRYSTALS-Dilithium": {
        "type": "SIG",
        "vulnerable": False,
        "alternative": None,
        "security_level": lambda level: {2: 128, 3: 192, 5: 256}.get(level, 128),
        "severity": lambda level: "Low"
    },
    "Dilithium": {
        "type": "SIG",
        "vulnerable": False,
        "alternative": None,
        "security_level": lambda level: {2: 128, 3: 192, 5: 256}.get(level, 128),
        "severity": lambda level: "Low"
    },
    "FALCON": {
        "type": "SIG",
        "vulnerable": False,
        "alternative": None,
        "security_level": lambda level: {512: 128, 1024: 256}.get(level, 128),
        "severity": lambda level: "Low"
    },
    "SPHINCS+": {
        "type": "SIG",
        "vulnerable": False,
        "alternative": None,
        "security_level": lambda level: 128,
        "severity": lambda level: "Low"
    },
    "XMSS": {
        "type": "SIG",
        "vulnerable": False,
        "alternative": None,
        "security_level": lambda level: 128,
        "severity": lambda level: "Low"
    },
    "LMS": {
        "type": "SIG",
        "vulnerable": False,
        "alternative": None,
        "security_level": lambda level: 128,
        "severity": lambda level: "Low"
    },
    "BIKE": {
        "type": "KEM",
        "vulnerable": False,
        "alternative": None,
        "security_level": lambda level: {1: 128, 3: 192, 5: 256}.get(level, 128),
        "severity": lambda level: "Low"
    },
    "HQC": {
        "type": "KEM",
        "vulnerable": False,
        "alternative": None,
        "security_level": lambda level: {128: 128, 192: 192, 256: 256}.get(level, 128),
        "severity": lambda level: "Low"
    },
    "Classic McEliece": {
        "type": "KEM",
        "vulnerable": False,
        "alternative": None,
        "security_level": lambda level: 128,
        "severity": lambda level: "Low"
    },
    "NTRU": {
        "type": "KEM",
        "vulnerable": False,
        "alternative": None,
        "security_level": lambda level: 128,
        "severity": lambda level: "Low"
    },
    "FrodoKEM": {
        "type": "KEM",
        "vulnerable": False,
        "alternative": None,
        "security_level": lambda level: 128,
        "severity": lambda level: "Low"
    },
}

def is_quantum_vulnerable(base, bits=None):
    if base not in ALGORITHMS:
        return False
    vuln = ALGORITHMS[base]['vulnerable']
    return vuln if isinstance(vuln, bool) else vuln(bits)

def get_pqc_alternative(base, bits=None):
    if base not in ALGORITHMS:
        return "Unknown"
    return ALGORITHMS[base]['alternative']

def get_security_level(base, bits=None):
    if base not in ALGORITHMS:
        return 0
    return ALGORITHMS[base]['security_level'](bits)

def get_severity(base, bits=None):
    if base not in ALGORITHMS:
        return "Unknown"
    return ALGORITHMS[base]['severity'](bits)