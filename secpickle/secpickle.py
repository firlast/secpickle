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
    check_hash = hashlib.sha256(key_sum).hexdigest()
    check_hash = check_hash.encode()

    return original_hash == check_hash


def _sign_obj(obj: Any, key: str) -> bytes:
    obj_pickle = pickle.dumps(obj)
    obj_hash = hashlib.sha256(obj_pickle).hexdigest()

    key_sum = (key + obj_hash).encode()
    check_hash = hashlib.sha256(key_sum).hexdigest()
    check_hash = check_hash.encode()
    result = check_hash + obj_pickle
    return result


def loads(data: bytes, key: str) -> Any:
    if _verify(data, key):
        obj = data[64:]
        unpickle_obj = pickle.loads(obj)
        return unpickle_obj
    else:
        raise exceptions.IntegrityUnconfirmedError('Unable to confirm file integrity')


def load(file: io.BufferedReader, key: str) -> Any:
    with file as _file:
        data = _file.read()

    return loads(data, key)


def dumps(obj: Any, key: str) -> bytes:
    signed_obj = _sign_obj(obj, key)
    return signed_obj


def dump(obj: Any, file: io.BufferedWriter, key: str) -> None:
    with file as _file:
        _sign_obj = dumps(obj, key)
        _file.write(_sign_obj)
