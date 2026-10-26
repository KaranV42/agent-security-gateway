import jwt
import datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

class SimulatedIdP:
    """
    Simulates an external Identity Provider (e.g., Auth0, Okta).
    Holds the private key for signing and exposes the public key for verification.
    """
    def __init__(self):
        # Generate a 2048-bit RSA key pair
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self._public_key = self._private_key.public_key()
        self._kid = "prototype-key-1" # Key ID for JWKS

    def get_jwks(self) -> dict:
        """Returns the public key in standard JWKS format."""
        public_numbers = self._public_key.public_numbers()
        return {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": self._kid,
                    "use": "sig",
                    "alg": "RS256",
                    "n": self._int_to_base64url(public_numbers.n),
                    "e": self._int_to_base64url(public_numbers.e)
                }
            ]
        }

    def generate_token(self, principal_id: str) -> str:
        """Signs a JWT using the private key."""
        payload = {
            "sub": principal_id,
            "iss": "https://idp.asg-prototype.local",
            "aud": "https://api.asg-prototype.local",
            "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
        }
        # Serialize private key to PEM format for PyJWT
        private_pem = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        return jwt.encode(payload, private_pem, algorithm="RS256", headers={"kid": self._kid})

    def get_public_key_pem(self) -> bytes:
        """Returns the public key in PEM format for verification."""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @staticmethod
    def _int_to_base64url(num: int) -> str:
        """Converts an integer to base64url encoding (required for JWKS)."""
        hex_string = hex(num)[2:]
        if len(hex_string) % 2:
            hex_string = '0' + hex_string
        import base64
        return base64.urlsafe_b64encode(bytes.fromhex(hex_string)).rstrip(b'=').decode('utf-8')

# Singleton instance for the prototype
idp = SimulatedIdP()