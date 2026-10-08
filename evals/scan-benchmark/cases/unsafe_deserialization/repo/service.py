import json
import pickle


def unsafe_decode(untrusted_bytes):
    return pickle.loads(untrusted_bytes)


def safe_decode(untrusted_bytes):
    return json.loads(untrusted_bytes)
