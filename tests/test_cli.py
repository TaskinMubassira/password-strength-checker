import json

import password_checker.cli as cli


def run(monkeypatch, capsys, password, *args, breaches=0):
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": password)
    monkeypatch.setattr(cli, "times_pwned", lambda pw: breaches)
    code = cli.main(list(args))
    return code, capsys.readouterr().out


def test_json_output_for_a_strong_password(monkeypatch, capsys):
    code, out = run(monkeypatch, capsys, "river-candle-orbit-mango", "--json")
    data = json.loads(out)
    assert code == 0
    assert data["score"] == 4 and data["breach_count"] == 0


def test_json_output_marks_breached_passwords_as_weak(monkeypatch, capsys):
    code, out = run(monkeypatch, capsys, "river-candle-orbit-mango", "--json", breaches=12)
    data = json.loads(out)
    assert code == 1
    assert data["score"] == 0 and data["breach_count"] == 12


def test_offline_json_has_no_breach_count(monkeypatch, capsys):
    _, out = run(monkeypatch, capsys, "password", "--json", "--offline")
    assert json.loads(out)["breach_count"] is None
