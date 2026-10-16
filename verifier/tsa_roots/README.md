# Pinned TSA roots (ADR 008)

Trust anchors the auditor-side verifier uses INSTEAD of the certificate an
operator ships inside its anchors (TOFU). One `<profile-name>.pem` per TSA
profile; a token from profile `universign` is checked against
`universign.pem` when it exists, else against its embedded certificate
(TOFU — reported as such in the verifier output).

**Append-only in practice.** A retired root stays here to keep verifying
PAST anchors — deleting a root means editing the judge, the very attack
this tool exists to prevent. Root rotation = add the new root, stop issuing
anchors with the old profile; old anchors keep verifying with the old root.
Pin ROOTS only: intermediates/signers rotate (~yearly) and travel inside
each token; roots live for years.

Current pinned roots (public, well-known certificates):

- `digicert.pem` — DigiCert Trusted Root G4 (public RFC 3161 TSA
  `timestamp.digicert.com`); verifies live-stamped tokens as of 2026-09-25.
- `freetsa.pem` — FreeTSA Root CA (`freetsa.org`, free public TSA).

For qualified eIDAS TSAs (Universign, Certigna, CertEurope…), pin the root
published on the EU Trusted List (https://trustedlist.european-union.eu) so
the auditor's trust anchor is the Union's official list, not this repo's
choice. `NOIREBOX_TSA_ROOTS_DIR` overrides this directory for tests.
