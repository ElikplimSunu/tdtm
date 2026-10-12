import pytest

from tdtm import __version__
from tdtm.cli import main


def test_version(capsys):
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_unimplemented_commands_say_where_to_look(capsys):
    assert main(["inspect", "x.json"]) == 1
    assert "PLAN.md" in capsys.readouterr().err
