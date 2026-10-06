"""JSON float decoding that rejects overflow before evidence processing."""
import math


def finite_json_float(token):
    value = float(token)
    if not math.isfinite(value):
        raise ValueError("JSON numeric token exceeds finite float range")
    return value
