import hashlib
import pickle
import io

from typing import Any

from . import exceptions


def _verify(data: bytes, key: str) -> bool:
    original_hash = data[:64]
    obj = data[64:]

    obj_hash = hashlib.sha256(obj).hexdigest()
    key_sum = (key + obj_hash).encode()
    check_hash = hashlib.sha256(key_sum)

    return original_hash == check_hash


def _sign_obj(obj: Any, key: str) -> bytes:
    obj_pickle = pickle.dumps(obj)
    obj_hash = hashlib.sha256(obj_pickle).hexdigest()

    key_sum = (key + obj_hash).encode()
    check_hash = hashlib.sha256(key_sum)
    result = check_hash + obj_pickle
    return result


def load(file: io.BufferedReader, key: str) -> Any:
    data = file.read()
    file.close()

    if _verify(data, key):
        obj = data[64:]
        unpickle_obj = pickle.loads(obj)
        return unpickle_obj
    else:
        raise exceptions.IntegrityUnconfirmedError('Unable to confirm file integrity')


def dump(obj: Any, file: io.BufferedWriter, key: str) -> None:
    signed_obj = _sign_obj(obj, key)
    file.write(signed_obj)
    file.close()
