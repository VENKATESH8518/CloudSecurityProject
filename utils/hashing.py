import hashlib


def generate_sha256(file_path):

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:

        while True:

            data = file.read(4096)

            if not data:
                break

            sha256.update(data)

    return sha256.hexdigest()

def verify_file_integrity(file_path, stored_hash):

    current_hash = generate_sha256(file_path)

    return current_hash == stored_hash