"""Plugin namespace. Third-party analyzers may expose an ``analyze(records)`` callable."""

from importlib.metadata import entry_points


def load_plugins():
    return [entry.load() for entry in entry_points(group="corspectra.analyzers")]
