import hashlib


def generate_sha256(file_path):
    """
    Generate SHA-256 hash of a file.
    """

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:

        while True:

            data = f.read(4096)

            if not data:
                break

            sha256.update(data)

    return sha256.hexdigest()