"""Quick validation: _is_routine_sysmon_event helper."""
from backend.app.services.enrichment.mappers.endpoint import _is_routine_sysmon_event


def test_defender_safe_path():
    raw = {"file": {"fileName": "MsMpEng.exe", "filePath": r"C:\Windows\System32\MsMpEng.exe"}}
    assert _is_routine_sysmon_event(raw) is True


def test_edge_safe_path():
    raw = {"file": {"fileName": "msedge.exe", "filePath": r"C:\Program Files\Microsoft\Edge\msedge.exe"}}
    assert _is_routine_sysmon_event(raw) is True


def test_onedrive_safe_path():
    raw = {"file": {"fileName": "OneDrive.exe", "filePath": r"C:\Program Files\Microsoft OneDrive\OneDrive.exe"}}
    assert _is_routine_sysmon_event(raw) is True


def test_windows_update_worker():
    raw = {"file": {"fileName": "TiWorker.exe", "filePath": r"C:\Windows\WinSxS\TiWorker.exe"}}
    assert _is_routine_sysmon_event(raw) is True


def test_edge_in_temp_not_routine():
    raw = {"file": {"fileName": "msedge.exe", "filePath": r"C:\Users\user\AppData\Local\Temp\msedge.exe"}}
    assert _is_routine_sysmon_event(raw) is False


def test_unknown_process_not_routine():
    raw = {"file": {"fileName": "malware.exe", "filePath": r"C:\Windows\System32\malware.exe"}}
    assert _is_routine_sysmon_event(raw) is False


def test_defender_with_encoded_cmd_not_routine():
    raw = {"file": {"fileName": "MsMpEng.exe", "filePath": r"C:\Windows\MsMpEng.exe"}, "_encodedCommand": True}
    assert _is_routine_sysmon_event(raw) is False


def test_defender_with_lolbin_abuse_not_routine():
    raw = {"file": {"fileName": "MsMpEng.exe", "filePath": r"C:\Windows\MsMpEng.exe"}, "_lolbinAbuse": True}
    assert _is_routine_sysmon_event(raw) is False


def test_process_name_from_processName_field():
    raw = {"file": {}, "_processName": r"C:\Windows\System32\SearchIndexer.exe"}
    assert _is_routine_sysmon_event(raw) is True


def test_empty_process_not_routine():
    raw = {"file": {}}
    assert _is_routine_sysmon_event(raw) is False
