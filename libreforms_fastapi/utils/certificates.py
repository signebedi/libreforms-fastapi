"""
# Example usage:
username = 'user123'
ds_manager = DigitalSignatureManager(username)
ds_manager.generate_rsa_key_pair()

data_to_sign = b"Important document content."
signature = ds_manager.sign_data(data_to_sign)
print("Signature:", signature)

verification_result = ds_manager.verify_signature(data_to_sign, signature)
print("Verification:", verification_result)


username = 'user123'
record_to_sign = {"data": {"text_input": "Sample text"}, "metadata": {"_signature": None}}
signed_record = sign_record(record_to_sign, username=username)
print("Signed Record:", signed_record)

verification_result = verify_record_signature(signed_record, username=username)
print("Verification Result:", verification_result)
"""
import os, json, copy
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


class RuntimeKeypair:
    """
    A class to manage RSA key pairs for different runtime environments, supporting key generation,
    storage, and retrieval. Particularly useful to pair with JWT, see the following:
    https://pyjwt.readthedocs.io/en/latest/usage.html#encoding-decoding-tokens-with-rs256-rsa.

    Attributes:
        env (str): Specifies the runtime environment (e.g., 'development', 'production'). This affects
            the naming of the key files to differentiate between environments.
        key_storage_path (str): The file system path where the key pair files are stored. Ensures that
            keys are organized and accessible.
        flush_on_start (bool): If set to True, the class will generate a new RSA key pair upon
            instantiation, overwriting any existing keys for the environment.

    Methods:
        generate_runtime_keypair():     Generates a new RSA key pair with a 2048-bit size and a public
                                        exponent of 65537. It saves the private and public keys to files
                                        within the specified `key_storage_path`, named according to the
                                        `env` attribute.
        get_private_key(as_bytes=True): Retrieves the private key from its storage file. The key can be
                                        returned either as bytes (default) or as a decoded string,
                                        depending on the `as_bytes` parameter.
        get_public_key(as_bytes=True):  Retrieves the public key from its storage file, similarly allowing
                                        for the key to be returned as bytes or a decoded string.

    This class relies on the `cryptography` package for RSA key generation, serialization, and
    deserialization. It is designed to facilitate secure key management in applications requiring
    RSA encryption or signing capabilities.
    """

    def __init__(
        self,
        env="development", 
        key_storage_path=os.path.join('instance', 'keys'),
        flush_on_start=False
    ):
        self.env = env        
        self.key_storage_path = key_storage_path

        # Ensure the key storage path exists
        os.makedirs(self.key_storage_path, exist_ok=True)

        # If flush on start is set to True, generate new keys when this class is instantiated.
        if flush_on_start:
            self.generate_runtime_keypair()
        else:
            # Check if the key files exist. If not, generate new keypair.
            self._check_and_generate_keys_if_needed()

    def _check_and_generate_keys_if_needed(self):
        private_key_path = os.path.join(self.key_storage_path, f"{self.env}_private.key")
        public_key_path = os.path.join(self.key_storage_path, f"{self.env}_public.key")

        # Check if both the private and public key files exist.
        if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
            # If either file does not exist, generate a new keypair.
            self.generate_runtime_keypair()

    def generate_runtime_keypair(self):
        # Generate the keypair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # Save the keys to files
        self._save_private_key(private_key)
        self._save_public_key(public_key)

    def _save_private_key(self, private_key):
        # Save the private key
        private_key_path = os.path.join(self.key_storage_path, f"{self.env}_private.key")
        with open(private_key_path, "wb") as private_file:
            private_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )

    def _save_public_key(self, public_key):
        # Save the public key
        public_key_path = os.path.join(self.key_storage_path, f"{self.env}_public.key")
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(public_key_path, "wb") as public_file:
            public_file.write(public_key_bytes)

    def get_private_key(self, as_bytes=True):
        # Load the private key from file
        private_key_path = os.path.join(self.key_storage_path, f"{self.env}_private.key")
        with open(private_key_path, "rb") as private_file:
            private_key = private_file.read()
            return private_key if as_bytes else private_key.decode()

    def get_public_key(self, as_bytes=True):
        # Load the public key from file
        public_key_path = os.path.join(self.key_storage_path, f"{self.env}_public.key")
        with open(public_key_path, "rb") as public_file:
            public_key = public_file.read()
            return public_key if as_bytes else public_key.decode()



class DigitalSignatureManager:
    def __init__(
        self, 
        username, 
        env="development", 
        key_storage_path=os.path.join('instance', 'keys'),
        public_key_path=None,
        private_key_path=None,
    ):
        self.username = username
        self.env = env
        self.key_storage_path = key_storage_path
        self.ensure_key_storage()
        self.public_key_path=public_key_path
        self.private_key_path=private_key_path

    def ensure_key_storage(self):
        if not os.path.exists(self.key_storage_path):
            os.makedirs(self.key_storage_path)

    def get_private_key_file(self):

        if self.private_key_path:
            return self.private_key_path

        return os.path.join(self.key_storage_path, f"{self.env}_{self.username}_private.key")

    def get_public_key_file(self):
        
        if self.public_key_path:
            return self.public_key_path

        return os.path.join(self.key_storage_path, f"{self.env}_{self.username}_public.key")

    def generate_rsa_key_pair(self):
        """
        Generates an RSA key pair and saves them to files.
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        self.public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )


        # Save the private key
        with open(self.get_private_key_file(), "wb") as private_file:
            private_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )

        # Save the public key
        with open(self.get_public_key_file(), "wb") as public_file:
            public_file.write(self.public_key_bytes)

    def sign_data(self, data):
        """
        Signs data using the private key.
        """
        with open(self.get_private_key_file(), "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def verify_signature(self, data, signature, public_key=None):
        """
        Verifies the signature of the data using the provided public key.
        
        :param data: The original data that was signed.
        :param signature: The signature to verify.
        :param public_key: Optional. The public key used for verification. This can be
                        either a PEM-encoded string or a loaded public key object.
                        If None, the public key will be read from the file specified
                        by `get_public_key_file()`.
        :return: True if the signature is valid; False otherwise.
        """
        if public_key is None:
            # Load the public key from file if not provided
            with open(self.get_public_key_file(), "rb") as key_file:
                public_key = serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                )
        elif isinstance(public_key, str):
            # Load the public key from a PEM-encoded string if provided as such
            public_key = serialization.load_pem_public_key(
                public_key.encode('utf-8'),
                backend=default_backend()
            )
            print(public_key)
        
        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            print(f"Verification failed: {str(e)}")
            return False

def sign_record(record, username, env="development", private_key_path=None):
    """
    Generates a signature for the given record and returns it.
    """
    ds_manager = DigitalSignatureManager(username=username, env=env, private_key_path=private_key_path)

    serialized = json.dumps(record, sort_keys=True)
    signature = ds_manager.sign_data(serialized.encode())

    s = signature.hex()

    return s

def verify_record_signature(record, signature, username, env="development", public_key=None, private_key_path=None):
    """
    Verifies the signature of the given record.
    Returns True if the signature is valid, False otherwise.
    """
    
    ds_manager = DigitalSignatureManager(username=username, env=env, private_key_path=private_key_path)

    # record_copy = copy.deepcopy(record)

    signature_bytes = bytes.fromhex(signature)
    serialized = json.dumps(record, sort_keys=True)
    
    # This is hackish, because ds_manager.verify_signature should be able to accept bytes. It's a workaround for now.
    if isinstance(public_key, bytes):
        public_key = public_key.decode('utf-8')

    try:
        return ds_manager.verify_signature(serialized.encode(), signature_bytes, public_key=public_key)
    except InvalidSignature:
        return False

