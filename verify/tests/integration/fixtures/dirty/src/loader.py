# Deliberately insecure — triggers CODE-01 HIGH patterns
import pickle
import yaml
import marshal


def load_model(path: str):
    """Deserialise model — pickle.load() triggers CODE-01."""
    with open(path, "rb") as f:
        return pickle.load(f)


def load_config(path: str):
    """Load YAML without safe loader — yaml.load() triggers CODE-01."""
    with open(path) as f:
        return yaml.load(f, Loader=yaml.FullLoader)


def deserialize_state(data: bytes):
    """Deserialise bytecode — marshal.loads() triggers CODE-01."""
    return marshal.loads(data)
