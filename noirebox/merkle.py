from __future__ import annotations

import hashlib
from dataclasses import dataclass


def _pair_hash(left: str, right: str) -> str:
    """Hashes a pair of hex hashes — one round of the tournament."""
    return hashlib.sha256((left + right).encode("ascii")).hexdigest()


def _is_hash(value: str) -> bool:
    return len(value) == 64 and all(c in "0123456789abcdef" for c in value)


@dataclass(frozen=True)
class ProofStep:
    """One level of the leaf → root path: the neighboring hash and its side."""

    sibling: str
    side: str


@dataclass
class MerkleTree:
    """Tree built over a batch of chain heads (sorted leaves)."""

    leaves: list[str]
    levels: list[list[str]]

    @property
    def root(self) -> str:
        """The root: 32 bytes that commit to every leaf."""
        return self.levels[-1][0]

    @property
    def size(self) -> int:
        return len(self.leaves)

    def proof(self, leaf: str) -> list[ProofStep]:
        """Inclusion path of `leaf` up to the root.

        ~log2(N) steps: 11 hashes for 1,200 devices, 30 for a billion.
        Raises ValueError if the leaf does not participate in the tree.
        """
        try:
            index = self.leaves.index(leaf)
        except ValueError:
            raise ValueError(
                "this head does not participate in the tree (box omitted from the "
                "batch, or wrong fleet)"
            ) from None

        steps: list[ProofStep] = []
        for level in self.levels[:-1]:
            sibling_index = index ^ 1
            if sibling_index >= len(level):


                raise RuntimeError("malformed tree: level without sibling")
            sibling = level[sibling_index]
            side = "left" if sibling_index < index else "right"
            steps.append(ProofStep(sibling=sibling, side=side))
            index //= 2
        return steps


def build_tree(heads: list[str]) -> MerkleTree:
    """Builds the tree over a batch of chain heads.

    Canonical ordering of the leaves: collecting the same batch in a
    different order yields exactly the same tree (the proof stays verifiable).
    """
    if not heads:
        raise ValueError("an empty fleet has nothing to seal")
    for h in heads:
        if not _is_hash(h):
            raise ValueError(f"not a SHA-256 hex hash: {h[:20]}…")

    leaves = sorted(set(heads))
    levels: list[list[str]] = [leaves]
    while len(levels[-1]) > 1:


        level = list(levels[-1])
        if len(level) % 2:
            level.append(level[-1])
        levels[-1] = level
        levels.append([
            _pair_hash(level[i], level[i + 1]) for i in range(0, len(level), 2)
        ])
    return MerkleTree(leaves=leaves, levels=levels)


def verify_inclusion(leaf: str, proof: list[ProofStep], root: str) -> bool:
    """Recomputes the leaf → root branch and compares it with the seal.

    Purely local: no network, no trust — arithmetic decides.
    """
    node = leaf
    for step in proof:
        node = (
            _pair_hash(step.sibling, node) if step.side == "left"
            else _pair_hash(node, step.sibling)
        )
    return node == root
