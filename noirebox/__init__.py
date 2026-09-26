"""NoireBox — the tamper-proof journal (flight data recorder) for AI agents."""
from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("noirebox")
except PackageNotFoundError:  # running from a repo clone without installation
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
