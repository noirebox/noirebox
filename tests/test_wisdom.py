"""The wall — one easter egg, one invariant: it prints what was promised,
dedicated to the reviewer who asked for a frame (SCAR-BENCH-114)."""
from noirebox.wisdom import FRAME


def test_the_sentence_is_on_the_wall():
    assert "Context suggests;" in FRAME
    assert "boundaries decide;" in FRAME


def test_the_dedication_is_there():
    assert "RANDAL" in FRAME
    assert "frame" in FRAME


def test_the_cli_hides_it_but_ships_it(capsys):
    from noirebox.cli import main

    assert main(["wisdom"]) == 0
    out = capsys.readouterr().out
    assert "Context suggests;" in out
    assert "RANDAL" in out
