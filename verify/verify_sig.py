
import os
import base64
import glob

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature


def verify(signature : str, statement : str, path_to_pubkey : str) -> bool:
    public_key_file = open(path_to_pubkey, 'rb')
    public_key = serialization.load_pem_public_key(public_key_file.read())
    public_key_file.close()

    try:
        public_key.verify(
            base64.b64decode(signature),
            statement,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False



def main():

    folder_path = "./"
    signature_f = []
    statement_f = []

    for file_path in glob.glob(os.path.join(folder_path, "*.signature")):
        signature_f.append(file_path.replace("\\","/"))
    
    
    for file_path in glob.glob(os.path.join(folder_path, "*.statement")):
        statement_f.append(file_path.replace("\\","/"))

    for field, sign in zip(statement_f, signature_f):
        statement = field
        signature = sign

        with open(field, "rb") as f:
            statement = f.read()
        f.close()

        with open(sign, "rb") as f:
            signature = f.read()
        f.close()

        verified = verify(signature, statement, "./user1.pub.pem")
        print(f"verified={verified}")
        

if __name__ == "__main__":
    main()