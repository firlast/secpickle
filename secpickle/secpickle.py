import hashlib
import pickle
import io

from typing import Any

from . import exceptions


def _verify(data: bytes, key: str) -> bool:
    original_hash = data[:64]
    obj = data[64:]

    key_sum = (key + obj_hash).encode()
    obj_hash = hashlib.sha256(obj)
    check_hash = hashlib.sha256(key_sum)

    return original_hash == check_hash


def load(file: io.BufferedReader, key: str) -> Any:
    data = file.read()

    if _verify(data, key):
        obj = data[64:]
        unpickle_obj = pickle.loads(obj)
        return unpickle_obj
    else:
        raise exceptions.IntegrityUnconfirmedError('Unable to confirm file integrity')
