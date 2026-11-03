import importlib.util
import pathlib
import sys
import types


SOURCE = pathlib.Path(__file__).resolve().parents[1] / "piv-phone-reader-poc.py"
SPEC = importlib.util.spec_from_file_location("piv_phone_reader_poc", SOURCE)
assert SPEC and SPEC.loader
POC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POC)


class FakeRegistryKey:
    def __init__(self, values):
        self.values = values

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


def install_fake_winreg(monkeypatch, values):
    def query_value(key, name):
        if name not in key.values:
            raise FileNotFoundError(name)
        return key.values[name]

    fake = types.SimpleNamespace(
        HKEY_LOCAL_MACHINE=1,
        KEY_QUERY_VALUE=2,
        KEY_SET_VALUE=4,
        KEY_WOW64_64KEY=8,
        REG_SZ=1,
        OpenKey=lambda *_args: FakeRegistryKey(values),
        QueryValueEx=query_value,
        DeleteValue=lambda key, name: key.values.pop(name),
    )
    monkeypatch.setitem(sys.modules, "winreg", fake)


def test_request_id_is_consumed_once_at_signature_start(monkeypatch):
    values = {"PivPhoneRequestId": ("approved-request-123456", 1)}
    install_fake_winreg(monkeypatch, values)

    assert POC.consume_registry_request_id("S-1-5-21-100-200-300-1106") == "approved-request-123456"
    assert "PivPhoneRequestId" not in values
    assert POC.consume_registry_request_id("S-1-5-21-100-200-300-1106") is None


def test_invalid_request_id_is_not_consumed(monkeypatch):
    values = {"PivPhoneRequestId": ("not a valid token!", 1)}
    install_fake_winreg(monkeypatch, values)

    assert POC.consume_registry_request_id("S-1-5-21-100-200-300-1106") is None
    assert "PivPhoneRequestId" in values


def test_invalid_sid_does_not_open_registry(monkeypatch):
    fake = types.SimpleNamespace(OpenKey=lambda *_args: (_ for _ in ()).throw(AssertionError()))
    monkeypatch.setitem(sys.modules, "winreg", fake)

    assert POC.consume_registry_request_id("S-1-5-21-../../users") is None
