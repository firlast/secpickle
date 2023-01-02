import hashlib


def _verify(data: bytes, key: str) -> bool:
    original_hash = data[:64]
    obj = data[64:]

    key_sum = (key + obj_hash).encode()
    obj_hash = hashlib.sha256(obj)
    check_hash = hashlib.sha256(key_sum)

    return original_hash == check_hash
