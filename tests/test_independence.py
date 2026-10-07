"""ADR 021 — the shared-dependency test as a runnable assertion.

'Can one compromise reach both?' becomes an empty-or-not list: the audit
flow and the truth flow must share NOTHING — not the journal, not the key,
not an endpoint, and each must anchor its own heads."""
from noirebox.independence import Flow, conflicts


def test_two_flows_sharing_a_store_are_theater():
    audit = Flow("audit", "shared/.noirebox/journal.db", "audit/.key", anchor_cadence_min=60)
    truth = Flow("truth", "shared/.noirebox/journal.db", "truth/.key", anchor_cadence_min=60)
    out = conflicts(audit, truth)
    assert any("same journal file" in c for c in out)
    assert "one compromised endpoint" not in "".join(out)


def test_two_flows_sharing_a_key_cannot_name_writers():
    audit = Flow("audit", "audit/journal.db", "shared/.key", anchor_cadence_min=60)
    truth = Flow("truth", "truth/journal.db", "shared/.key", anchor_cadence_min=60)
    out = conflicts(audit, truth)
    assert any("same key" in c for c in out)


def test_a_flow_that_never_anchors_inherits_the_other_clock():
    audit = Flow("audit", "audit/j.db", "audit/k", anchor_cadence_min=60)
    truth = Flow("truth", "truth/j.db", "truth/k")  # no cadence: the clock is borrowed
    out = conflicts(audit, truth)
    assert any("never anchors its own heads" in c and "'truth'" in c for c in out)


def test_fully_separated_flows_are_independent():
    audit = Flow("audit", "audit/journal.db", "audit/journal.db.key",
                 anchor_cadence_min=60, hosts=("freetsa.org",))
    truth = Flow("truth", "truth/journal.db", "truth/journal.db.key",
                 anchor_cadence_min=60, hosts=("registry.example",))
    assert conflicts(audit, truth) == []


def test_shared_endpoint_is_one_compromise_reaching_both():
    audit = Flow("audit", "audit/j.db", "audit/k", anchor_cadence_min=60,
                 hosts=("proxy.internal",))
    truth = Flow("truth", "truth/j.db", "truth/k", anchor_cadence_min=60,
                 hosts=("proxy.internal",))
    out = conflicts(audit, truth)
    assert any("proxy.internal" in c for c in out)
