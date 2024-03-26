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

    # def verify_signature(self, data, signature):
    #     """
    #     Verifies the signature of the data using the public key.
    #     """
    #     with open(self.get_public_key_file(), "rb") as key_file:
    #         public_key = serialization.load_pem_public_key(
    #             key_file.read(),
    #             backend=default_backend()
    #         )

    #     try:
    #         public_key.verify(
    #             signature,
    #             data,
    #             padding.PSS(
    #                 mgf=padding.MGF1(hashes.SHA256()),
    #                 salt_length=padding.PSS.MAX_LENGTH
    #             ),
    #             hashes.SHA256()
    #         )
    #         return True
    #     except Exception as e:
    #         return False
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


def serialize_record_for_signing(record):
    """
    Serializes the record in a consistent, deterministic manner for signing.
    Excludes the '_signature' field from the serialization.
    """
    record_copy = dict(copy.deepcopy(record))  # Make a copy to avoid modifying the original
    # The logic of selecting only the data field is that, while metadata is subject (and really
    # expected) to change, eg. through the form approval process, we expect the data to remain 
    # the same.
    select_data_fields = record_copy['data']
    # print(select_data_fields)
    return json.dumps(select_data_fields, sort_keys=True)

def sign_record(record, username, env="development", private_key_path=None):
    """
    Generates a signature for the given record and inserts it into the '_signature' field.
    """
    ds_manager = DigitalSignatureManager(username=username, env=env, private_key_path=private_key_path)
    serialized = serialize_record_for_signing(record)
    signature = ds_manager.sign_data(serialized.encode())
    s = signature.hex()
    record['metadata']['_signature'] = s  # Store the signature as a hex string
    return record, s

def verify_record_signature(record, username, env="development", public_key=None, private_key_path=None):
    """
    Verifies the signature of the given record.
    Returns True if the signature is valid, False otherwise.
    """
    if '_signature' not in record['metadata'] or record['metadata']['_signature'] is None:
        return False  # No signature to verify
    
    ds_manager = DigitalSignatureManager(username=username, env=env, private_key_path=private_key_path)

    record_copy = copy.deepcopy(record)
    signature_bytes = bytes.fromhex(record['metadata']['_signature'])
    serialized = serialize_record_for_signing(record_copy)
    
    # This is hackish, because ds_manager.verify_signature should be able to accept bytes. It's a workaround for now.
    if isinstance(public_key, bytes):
        public_key = public_key.decode('utf-8')

    try:
        return ds_manager.verify_signature(serialized.encode(), signature_bytes, public_key=public_key)
    except InvalidSignature:
        return False

