from cryptography.hazmat.primitives import hashes


def _get_hash(octets, hash_cls):
    h = hashes.Hash(hash_cls())
    h.update(octets)

    return h.finalize()


def get_sha256_hash(octets):
    return _get_hash(octets, hashes.SHA256)


def get_sha1_hash(octets):
    return _get_hash(octets, hashes.SHA1)
