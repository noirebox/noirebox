"""NoireBox standalone third-party verifier (`verifier/verifier.py`).

Shipped inside the wheel so `noirebox audit-pack` (ADR 010) works from an
installed package, not only from a repository checkout. Run as a script
(`python verifier/verifier.py export.json`) or import the API:

    from verifier.verifier import verify_export
"""
from .verifier import verify_export  # noqa: F401
