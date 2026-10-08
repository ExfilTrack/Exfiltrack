"""Synthetic live acquisition tests: no real Windows registry or commands are used."""

from __future__ import annotations

import json
import os
import stat
import subprocess
from dataclasses import FrozenInstanceError
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from exfiltrack.config import ExfilTrackError
from exfiltrack.evidence import live
from exfiltrack.evidence.hashing import hash_file

pytestmark = pytest.mark.unit
LOADED = "S-1-5-21-1001"
OFFLINE = "S-1-5-21-1002"
EXTRA = "S-1-5-19"
EVTX = b"ElfFile\x00" + bytes(64)
HIVE = b"regf" + bytes(64)
_NATIVE_ELEVATION = live._is_elevated
_NATIVE_WINDOWS_DIRECTORY = live._windows_directory
_NATIVE_WOW64 = live._is_wow64


def test_handle_ctime_can_differ_from_path_ctime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_fstat = os.fstat

    def different_ctime(fd: int) -> Any:
        info = real_fstat(fd)
        fields = {
            name: getattr(info, name)
            for name in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_atime_ns")
        }
        fields["st_ctime_ns"] += 100
        return SimpleNamespace(**fields)

    monkeypatch.setattr(live.os, "fstat", different_ctime)
    assert not _collect(tmp_path).has_gaps


@pytest.mark.parametrize("elevated", [False, True])
def test_native_elevation_queries_token_and_closes_handle(
    monkeypatch: pytest.MonkeyPatch, elevated: bool
) -> None:
    closed = []

    def current_process() -> int:
        return 123

    def open_token(process: int, access: int, token: Any) -> int:
        assert process == 123 and access == 0x0008
        token._obj.value = 456
        return 1

    def get_token(token: Any, kind: int, output: Any, size: int, length: Any) -> int:
        assert token.value == 456 and kind == 20
        output._obj.value = int(elevated)
        length._obj.value = size
        return 1

    def close(token: Any) -> int:
        closed.append(token.value)
        return 1

    kernel = SimpleNamespace(GetCurrentProcess=current_process, CloseHandle=close)
    advapi = SimpleNamespace(OpenProcessToken=open_token, GetTokenInformation=get_token)
    monkeypatch.setattr(
        live.ctypes,
        "WinDLL",
        lambda name, **kwargs: kernel if name == "kernel32" else advapi,
        raising=False,
    )
    assert _NATIVE_ELEVATION() is elevated
    assert closed == [456]


def test_windows_directory_comes_from_os_api_not_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def get_directory(buffer: Any, size: int) -> int:
        assert size >= len(str(tmp_path))
        buffer.value = str(tmp_path)
        return len(buffer.value)

    monkeypatch.setattr(
        live.ctypes,
        "WinDLL",
        lambda *args, **kwargs: SimpleNamespace(GetWindowsDirectoryW=get_directory),
        raising=False,
    )
    monkeypatch.setenv("WINDIR", "untrusted-environment-path")
    assert _NATIVE_WINDOWS_DIRECTORY() == tmp_path


@pytest.mark.parametrize("wow64", [False, True])
def test_native_wow64_query_for_32_bit_process(
    monkeypatch: pytest.MonkeyPatch, wow64: bool
) -> None:
    real_sizeof = live.ctypes.sizeof
    monkeypatch.setattr(
        live.ctypes,
        "sizeof",
        lambda value: 4 if value is live.ctypes.c_void_p else real_sizeof(value),
    )

    def current_process() -> int:
        return 123

    def query(process: int, value: Any) -> int:
        assert process == 123
        value._obj.value = int(wow64)
        return 1

    monkeypatch.setattr(
        live.ctypes,
        "WinDLL",
        lambda *args, **kwargs: SimpleNamespace(
            GetCurrentProcess=current_process, IsWow64Process=query
        ),
        raising=False,
    )
    assert _NATIVE_WOW64() is wow64


class _Key:
    def __init__(self, name: str) -> None:
        self.name = name

    def __enter__(self) -> _Key:
        return self

    def __exit__(self, *args: object) -> None:
        pass


class _Registry:
    KEY_READ = 0x20019
    KEY_WOW64_64KEY = 0x0100
    HKEY_LOCAL_MACHINE = "HKLM"
    HKEY_USERS = "HKU"

    def __init__(self, root: Path, profiles: dict[str, Path]) -> None:
        self.root = root
        self.profiles = profiles
        self.loaded = {LOADED, LOADED + "_Classes"}
        self.denied: set[str] = set()
        self.invalid: dict[str, str] = {}
        self.views: list[int] = []
        self.fail_enumeration = False

    def OpenKey(self, parent: _Key | str, name: str, reserved: int, access: int) -> _Key:
        self.views.append(access)
        full = (parent.name if isinstance(parent, _Key) else parent) + ("\\" + name if name else "")
        if full in self.denied:
            raise PermissionError(13, "Mock registry access denied", full)
        return _Key(full)

    def QueryInfoKey(self, key: _Key) -> tuple[int, int, int]:
        return (len(self.loaded) if key.name == "HKU" else len(self.profiles), 0, 0)

    def EnumKey(self, key: _Key, index: int) -> str:
        if self.fail_enumeration and key.name == "HKU":
            raise OSError("Mock HKU enumeration failure")
        return sorted(self.loaded if key.name == "HKU" else self.profiles)[index]

    def QueryValueEx(self, key: _Key, name: str) -> tuple[str, int]:
        if name == "ProfilesDirectory":
            return "%PROFILES%", 2
        sid = key.name.rsplit("\\", 1)[-1]
        return self.invalid.get(sid, str(self.profiles[sid])), 2

    def ExpandEnvironmentStrings(self, value: str) -> str:
        return value.replace("%PROFILES%", str(self.root))


class _Windows:
    def __init__(self, tmp_path: Path) -> None:
        self.windows = tmp_path / "Actual Windows Installation"
        self.profiles_root = tmp_path / "Relocated Profiles"
        self.profiles = {
            LOADED: self.profiles_root / "Active User",
            OFFLINE: self.profiles_root / "Offline User",
        }
        for folder in ("System32", "Sysnative"):
            directory = self.windows / folder
            directory.mkdir(parents=True)
            for executable in ("wevtutil.exe", "reg.exe"):
                (directory / executable).write_bytes(b"mock executable: never run")
        for profile in self.profiles.values():
            recent = self.recent(profile)
            (recent / "AutomaticDestinations").mkdir(parents=True)
            (recent / "CustomDestinations").mkdir()
            (profile / "NTUSER.DAT").write_bytes(HIVE)
            (recent / "Document.LNK").write_bytes(b"\x4c\x00\x00\x00" + bytes(64))
            (recent / "AutomaticDestinations" / "abc.automaticDestinations-ms").write_bytes(
                b"jump-a"
            )
            (recent / "CustomDestinations" / "def.customDestinations-ms").write_bytes(b"jump-c")
            (recent / "unrelated.txt").write_bytes(b"must not be acquired")
        self.registry = _Registry(self.profiles_root, self.profiles)
        self.calls: list[list[str]] = []
        self.disabled: set[str] = set()
        self.failed: set[str] = set()
        self.timeouts: set[str] = set()
        self.permission_denied: set[str] = set()
        self.no_output: set[str] = set()
        self.zero_output: set[str] = set()
        self.bad_config: set[str] = set()
        self.config_failures: set[str] = set()
        self.utf16_config = False

    @staticmethod
    def recent(profile: Path) -> Path:
        return profile / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent"

    def run(self, argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess:
        self.calls.append(argv)
        assert kwargs == {
            "shell": False,
            "stdin": subprocess.DEVNULL,
            "capture_output": True,
            "timeout": kwargs["timeout"],
            "check": False,
        }
        assert 0 < kwargs["timeout"] <= 120
        assert Path(argv[0]).is_absolute()
        assert Path(argv[0]).parent in {self.windows / "System32", self.windows / "Sysnative"}
        assert argv[1] in {"gl", "epl", "save"}
        assert "/ow" not in argv and "/y" not in argv
        source = argv[2]
        if argv[1] == "gl":
            assert argv[3:] == ["/f:xml"]
            if source in self.config_failures:
                return subprocess.CompletedProcess(argv, 5, b"", b"mock config denied")
            value = "false" if source in self.disabled else "true"
            xml = f'<channel xmlns="urn:windows-events" enabled="{value}" />'
            data = (
                b"invalid XML"
                if source in self.bad_config
                else xml.encode("utf-16" if self.utf16_config else "utf-8")
            )
            return subprocess.CompletedProcess(argv, 0, data, b"")
        assert len(argv) == 4
        destination = Path(argv[3])
        assert not destination.exists(), "Native exports must not overwrite files"
        if source not in self.no_output:
            destination.write_bytes(
                b"" if source in self.zero_output else EVTX if argv[1] == "epl" else HIVE
            )
        if source in self.timeouts:
            raise subprocess.TimeoutExpired(
                argv, kwargs["timeout"], output=b"partial stdout", stderr=b"timeout stderr"
            )
        if source in self.permission_denied:
            raise PermissionError(13, "Mock command permission denied")
        if source in self.failed:
            return subprocess.CompletedProcess(argv, 5, b"partial stdout", b"mock export denied")
        return subprocess.CompletedProcess(argv, 0, b"ok", b"")


@pytest.fixture(autouse=True)
def windows(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> _Windows:
    # Guard every test, even preflight tests, against touching the actual machine.
    machine = _Windows(tmp_path)
    monkeypatch.setattr(live.platform, "system", lambda: "Windows")
    monkeypatch.setattr(live.platform, "node", lambda: "SYNTHETIC-VM")
    monkeypatch.setattr(live, "_is_elevated", lambda: True)
    monkeypatch.setattr(live, "_windows_directory", lambda: machine.windows)
    monkeypatch.setattr(live, "_is_wow64", lambda: False)
    monkeypatch.setattr(live, "_winreg", lambda: machine.registry)
    monkeypatch.setattr(live.subprocess, "run", machine.run)
    return machine


def _collect(tmp_path: Path, **kwargs: Any) -> live.AcquisitionResult:
    return live.collect_live_evidence(
        tmp_path / "fresh case", case_id="CASE-001", examiner="Examiner", **kwargs
    )


def _find(result: live.AcquisitionResult, source: str, method: str | None = None) -> dict[str, Any]:
    return next(
        record
        for record in result.manifest["records"]
        if record["source"] == source and (method is None or record["method"] == method)
    )


def _reparse(monkeypatch: pytest.MonkeyPatch, target: Path, *, symlink: bool = False) -> None:
    real_lstat = Path.lstat

    def lstat(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self == target:
            return SimpleNamespace(
                st_mode=stat.S_IFLNK if symlink else stat.S_IFDIR,
                st_file_attributes=0 if symlink else live._REPARSE_POINT,
            )
        return real_lstat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", lstat)


def test_success_all_source_types_and_manifest_contract(tmp_path: Path, windows: _Windows) -> None:
    result = _collect(tmp_path)
    assert isinstance(result, live.AcquisitionResult)
    assert result.has_gaps is False
    assert result.manifest["coverage"] == "complete"
    assert result.manifest["computer_name"] == "SYNTHETIC-VM"
    assert result.manifest["case_id"] == "CASE-001"
    assert result.manifest["examiner"] == "Examiner"
    assert result.case_dir.is_absolute()
    assert result.reports_dir.is_dir()
    assert not result.manifest_path.is_relative_to(result.evidence_dir)
    assert result.manifest_path.name == "acquisition_manifest.json"
    assert json.loads(result.manifest_path.read_text(encoding="utf-8")) == result.manifest
    assert set(result.manifest) == {
        "schema_version",
        "case_id",
        "examiner",
        "computer_name",
        "start_time",
        "end_time",
        "coverage",
        "records",
        "limitations",
    }
    assert datetime.fromisoformat(result.manifest["start_time"]).tzinfo is not None
    assert datetime.fromisoformat(result.manifest["end_time"]) >= datetime.fromisoformat(
        result.manifest["start_time"]
    )
    records = result.manifest["records"]
    assert len(records) == 13
    assert {record["category"] for record in records} == {"evtx", "registry", "lnk", "jump_list"}
    assert {record["method"] for record in records} == {
        "wevtutil epl",
        "reg save",
        "read-only copy",
    }
    required = {"category", "source", "method", "status", "started_at", "finished_at"}
    for record in records:
        assert required <= record.keys()
        assert record["status"] == "collected"
        assert datetime.fromisoformat(record["finished_at"]) >= datetime.fromisoformat(
            record["started_at"]
        )
        relative = Path(record["destination"])
        assert not relative.is_absolute() and ".." not in relative.parts
        output = result.evidence_dir / relative
        assert hash_file(output) == record["sha256"]
        assert output.stat().st_size == record["metadata"]["output"]["size_bytes"]
    assert _find(result, f"HKU\\{LOADED}")["destination"] == f"users/{LOADED}/NTUSER.DAT"
    assert (
        _find(result, str(windows.profiles[OFFLINE] / "NTUSER.DAT"))["method"] == "read-only copy"
    )
    assert len(windows.calls) == 9
    assert all(view & windows.registry.KEY_WOW64_64KEY for view in windows.registry.views)
    assert not any("unrelated.txt" in record["source"] for record in records)
    assert any(
        "SACL history are NOT verified" in limitation
        for limitation in result.manifest["limitations"]
    )
    with pytest.raises(FrozenInstanceError):
        result.case_dir = tmp_path  # type: ignore[misc]
    assert issubclass(live.AcquisitionError, ExfilTrackError)


def test_trusted_sysnative_tools_and_utf16_config(
    tmp_path: Path, windows: _Windows, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(live, "_is_wow64", lambda: True)
    windows.utf16_config = True
    result = _collect(tmp_path, command_timeout=7)
    assert not result.has_gaps
    assert all(Path(argv[0]).parent == windows.windows / "Sysnative" for argv in windows.calls)
    assert _find(result, "System")["metadata"]["channel_enabled"] is True


def test_loaded_hives_without_profile_and_classes_exclusion(
    tmp_path: Path, windows: _Windows
) -> None:
    windows.registry.loaded.add(EXTRA)
    result = _collect(tmp_path)
    assert _find(result, f"HKU\\{EXTRA}")["status"] == "collected"
    assert not any("_Classes" in record["source"] for record in result.manifest["records"])


def test_loaded_hive_is_never_directly_read(
    tmp_path: Path, windows: _Windows, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_open = Path.open

    def deny(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self == windows.profiles[LOADED] / "NTUSER.DAT":
            pytest.fail("A loaded hive must be exported, not copied")
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", deny)
    assert not _collect(tmp_path).has_gaps


def test_copy_preserves_timestamps_size_and_digests_only_on_destination(
    tmp_path: Path, windows: _Windows, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = windows.recent(windows.profiles[OFFLINE]) / "Document.LNK"
    os.utime(source, ns=(1_700_000_001_000_000_000, 1_700_000_002_000_000_000))
    before = source.stat()
    real_utime = os.utime
    writes: list[Path] = []

    def track_utime(path: Path, *args: Any, **kwargs: Any) -> None:
        writes.append(Path(path))
        real_utime(path, *args, **kwargs)

    monkeypatch.setattr(live.os, "utime", track_utime)
    result = _collect(tmp_path)
    record = _find(result, str(source))
    output = result.evidence_dir / record["destination"]
    assert output.stat().st_atime_ns == before.st_atime_ns
    assert output.stat().st_mtime_ns == before.st_mtime_ns
    assert output.stat().st_size == before.st_size
    assert record["metadata"]["source_before"]["mtime_ns"] == before.st_mtime_ns
    assert (
        record["metadata"]["source_sha256_before"]
        == record["metadata"]["source_sha256_after"]
        == record["sha256"]
    )
    assert writes and all(path.is_relative_to(result.evidence_dir) for path in writes)
    assert source.stat().st_mtime_ns == before.st_mtime_ns


def test_disabled_channel_export_is_collected_but_partial(
    tmp_path: Path, windows: _Windows
) -> None:
    channel = live._CHANNELS[2]
    windows.disabled.add(channel)
    result = _collect(tmp_path)
    record = _find(result, channel)
    assert record["status"] == "collected"
    assert record["metadata"]["channel_enabled"] is False
    assert "disabled" in record["message"]
    assert result.has_gaps and result.manifest["coverage"] == "partial"
    assert (
        record["destination"] == "evtx/Microsoft-Windows-DriverFrameworks-UserMode_Operational.evtx"
    )
    assert all(argv[1] in {"gl", "epl", "save"} for argv in windows.calls)


@pytest.mark.parametrize(
    "failure", ["failed", "no_output", "zero_output", "timeouts", "permission_denied"]
)
def test_incomplete_exports_removed_with_diagnostics(
    tmp_path: Path, windows: _Windows, failure: str
) -> None:
    getattr(windows, failure).add("Security")
    result = _collect(tmp_path, command_timeout=3)
    record = _find(result, "Security", "wevtutil epl")
    assert record["status"] in {"missing", "unavailable", "error"}
    assert record["message"]
    assert not (result.evidence_dir / "evtx" / "Security.evtx").exists()
    assert result.has_gaps
    assert _find(result, "System")["status"] == "collected"
    if failure == "failed":
        assert record["metadata"]["exit_code"] == 5
        assert record["metadata"]["stderr"] == "mock export denied"
    if failure == "timeouts":
        assert record["metadata"]["timeout_seconds"] == 3
        assert record["metadata"]["stdout"] == "partial stdout"
        assert record["metadata"]["stderr"] == "timeout stderr"
    if failure == "permission_denied":
        assert record["status"] == "unavailable"
        assert record["metadata"]["exception"] == "PermissionError"


@pytest.mark.parametrize("failure", ["bad_config", "config_failures"])
def test_unverified_config_is_a_gap_even_when_export_succeeds(
    tmp_path: Path, windows: _Windows, failure: str
) -> None:
    getattr(windows, failure).add("System")
    result = _collect(tmp_path)
    assert result.has_gaps
    assert _find(result, "System", "wevtutil gl")["status"] == "error"
    assert _find(result, "System", "wevtutil epl")["status"] == "collected"
    assert _find(result, "System", "wevtutil epl")["metadata"]["channel_enabled"] is None


def test_registry_export_failure_does_not_copy_loaded_hive(
    tmp_path: Path, windows: _Windows
) -> None:
    windows.failed.update({r"HKLM\SYSTEM", f"HKU\\{LOADED}"})
    result = _collect(tmp_path)
    assert _find(result, r"HKLM\SYSTEM")["metadata"]["exit_code"] == 5
    assert not (result.evidence_dir / "registry" / "SYSTEM").exists()
    assert not (result.evidence_dir / "users" / LOADED / "NTUSER.DAT").exists()
    assert not any(
        record["source"] == str(windows.profiles[LOADED] / "NTUSER.DAT")
        for record in result.manifest["records"]
    )


def test_missing_files_and_directories_recorded(tmp_path: Path, windows: _Windows) -> None:
    (windows.profiles[OFFLINE] / "NTUSER.DAT").unlink()
    directory = windows.recent(windows.profiles[OFFLINE]) / "AutomaticDestinations"
    for entry in directory.iterdir():
        entry.unlink()
    directory.rmdir()
    result = _collect(tmp_path)
    assert _find(result, str(windows.profiles[OFFLINE] / "NTUSER.DAT"))["status"] == "missing"
    assert _find(result, str(directory))["status"] == "missing"
    assert result.has_gaps


@pytest.mark.parametrize("location", ["file", "directory"])
def test_profile_permissions_recorded(
    tmp_path: Path, windows: _Windows, monkeypatch: pytest.MonkeyPatch, location: str
) -> None:
    source = windows.profiles[OFFLINE] / "NTUSER.DAT"
    recent = windows.recent(windows.profiles[OFFLINE])
    real_open, real_iterdir = Path.open, Path.iterdir

    def deny_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self == source:
            raise PermissionError(13, "Mock file access denied")
        return real_open(self, *args, **kwargs)

    def deny_iterdir(self: Path) -> Any:
        if self == recent:
            raise PermissionError(13, "Mock directory access denied")
        return real_iterdir(self)

    monkeypatch.setattr(
        Path,
        "open" if location == "file" else "iterdir",
        deny_open if location == "file" else deny_iterdir,
    )
    result = _collect(tmp_path)
    record = _find(result, str(source if location == "file" else recent))
    assert record["status"] == "unavailable"
    assert record["metadata"]["exception"] == "PermissionError"
    assert result.has_gaps


def test_readable_empty_directories_are_not_gaps(tmp_path: Path, windows: _Windows) -> None:
    for profile in windows.profiles.values():
        recent = windows.recent(profile)
        for entry in recent.rglob("*"):
            if entry.is_file():
                entry.unlink()
    result = _collect(tmp_path)
    assert not result.has_gaps
    assert sum(record["status"] == "empty" for record in result.manifest["records"]) == 6
    assert result.manifest["coverage"] == "complete"


@pytest.mark.parametrize("mutation", ["during_copy", "after_copy", "digest_only", "bad_output"])
def test_source_mutation_or_output_mismatch_removed(
    tmp_path: Path, windows: _Windows, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    source = windows.profiles[OFFLINE] / "NTUSER.DAT"
    real_copy = live.shutil.copyfileobj
    real_hash = live.hash_file
    calls = 0

    def copy(incoming: Any, outgoing: Any, **kwargs: Any) -> None:
        real_copy(incoming, outgoing, **kwargs)
        if Path(incoming.name) == source:
            if mutation == "during_copy":
                source.write_bytes(HIVE + b"mutation")
            elif mutation == "bad_output":
                outgoing.write(b"corrupt output")

    def digest(path: Path) -> str:
        nonlocal calls
        if path == source:
            calls += 1
            if calls == 2 and mutation == "after_copy":
                source.write_bytes(HIVE + b"late mutation")
            if calls == 2 and mutation == "digest_only":
                return "0" * 64
        return real_hash(path)

    monkeypatch.setattr(live.shutil, "copyfileobj", copy)
    monkeypatch.setattr(live, "hash_file", digest)
    result = _collect(tmp_path)
    record = _find(result, str(source))
    assert record["status"] == "error"
    assert "changed" in record["message"] or "digest" in record["message"]
    assert not (result.evidence_dir / "users" / OFFLINE / "NTUSER.DAT").exists()
    assert record["metadata"]["source_sha256_before"]
    assert result.has_gaps


def test_partial_copy_removed_on_io_failure(
    tmp_path: Path, windows: _Windows, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = windows.profiles[OFFLINE] / "NTUSER.DAT"
    real_copy = live.shutil.copyfileobj

    def fail(incoming: Any, outgoing: Any, **kwargs: Any) -> None:
        if Path(incoming.name) == source:
            outgoing.write(b"partial")
            raise OSError("Mock copy read failure")
        real_copy(incoming, outgoing, **kwargs)

    monkeypatch.setattr(live.shutil, "copyfileobj", fail)
    result = _collect(tmp_path)
    assert _find(result, str(source))["status"] == "error"
    assert not (result.evidence_dir / "users" / OFFLINE / "NTUSER.DAT").exists()


def test_exclusive_copy_never_overwrites_or_removes_existing_destination(
    tmp_path: Path, windows: _Windows
) -> None:
    case = tmp_path / "unit-only-case"
    evidence = case / "evidence"
    evidence.mkdir(parents=True)
    output = evidence / "existing.dat"
    output.write_bytes(b"retain this")
    collector = live._Collector(case, 1, [])
    collector.copy(windows.profiles[OFFLINE] / "NTUSER.DAT", Path("existing.dat"), "registry")
    assert output.read_bytes() == b"retain this"
    assert collector.records[0]["status"] == "error"


def test_export_refuses_existing_output_without_command(tmp_path: Path, windows: _Windows) -> None:
    case = tmp_path / "unit-only-case"
    (case / "evidence").mkdir(parents=True)
    output = case / "evidence" / "SYSTEM"
    output.write_bytes(b"retain this")
    collector = live._Collector(case, 1, [])
    collector.export(
        "registry",
        r"HKLM\SYSTEM",
        "reg save",
        Path("SYSTEM"),
        windows.windows / "System32" / "reg.exe",
        ["save", r"HKLM\SYSTEM"],
    )
    assert output.read_bytes() == b"retain this"
    assert collector.records[0]["status"] == "error"
    assert not windows.calls


@pytest.mark.parametrize("source_type", ["file", "directory", "profile"])
@pytest.mark.parametrize("symlink", [False, True])
def test_reparse_sources_excluded(
    tmp_path: Path,
    windows: _Windows,
    monkeypatch: pytest.MonkeyPatch,
    source_type: str,
    symlink: bool,
) -> None:
    profile = windows.profiles[OFFLINE]
    source = {
        "file": profile / "NTUSER.DAT",
        "directory": windows.recent(profile),
        "profile": profile,
    }[source_type]
    _reparse(monkeypatch, source, symlink=symlink)
    result = _collect(tmp_path)
    affected = [
        record for record in result.manifest["records"] if record["source"].startswith(str(source))
    ]
    assert affected and all(record["status"] == "unavailable" for record in affected)
    assert all("Excluded" in record["message"] for record in affected)
    assert result.has_gaps


def test_case_itself_excluded_as_source(tmp_path: Path) -> None:
    case = tmp_path / "unit-only-case"
    (case / "evidence").mkdir(parents=True)
    source = case / "Document.lnk"
    source.write_bytes(b"do not collect case")
    collector = live._Collector(case, 1, [])
    collector.copy(source, Path("Document.lnk"), "lnk")
    assert collector.records[0]["status"] == "unavailable"
    assert not (case / "evidence" / "Document.lnk").exists()


@pytest.mark.parametrize(
    "failure", ["profile_list", "profile_value", "hku", "hku_enumeration", "invalid_path"]
)
def test_profile_discovery_errors_recorded(tmp_path: Path, windows: _Windows, failure: str) -> None:
    registry = windows.registry
    if failure == "profile_list":
        registry.denied.add("HKLM\\" + live._PROFILE_LIST)
    elif failure == "profile_value":
        registry.denied.add("HKLM\\" + live._PROFILE_LIST + "\\" + OFFLINE)
    elif failure == "hku":
        registry.denied.add("HKU")
    elif failure == "hku_enumeration":
        registry.fail_enumeration = True
    else:
        registry.invalid[OFFLINE] = "relative/unsafe/profile"
    result = _collect(tmp_path)
    errors = [
        record for record in result.manifest["records"] if record["category"] == "profile_discovery"
    ]
    assert errors and all(record["message"] for record in errors)
    assert result.has_gaps
    if failure in {"hku", "hku_enumeration"}:
        assert not any(
            record["method"] == "read-only copy" and record["source"].endswith("NTUSER.DAT")
            for record in result.manifest["records"]
        )
        assert _find(result, f"HKU\\{OFFLINE}")["status"] == "unavailable"


@pytest.mark.parametrize("empty_exports", [False, True])
def test_no_usable_evidence_writes_manifest_before_raising(
    tmp_path: Path, windows: _Windows, empty_exports: bool
) -> None:
    windows.registry.profiles = {}
    windows.registry.loaded = set()
    sources = {*live._CHANNELS, r"HKLM\SYSTEM", r"HKLM\SOFTWARE"}
    (windows.zero_output if empty_exports else windows.failed).update(sources)
    with pytest.raises(live.AcquisitionError, match="No usable evidence") as error:
        _collect(tmp_path)
    path = tmp_path / "fresh case" / "acquisition_manifest.json"
    assert str(path) in str(error.value)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    assert manifest["coverage"] == "partial"
    assert len(manifest["records"]) == 5
    assert all(record["status"] == "error" for record in manifest["records"])
    assert not any(entry.is_file() for entry in (path.parent / "evidence").rglob("*"))


@pytest.mark.parametrize(
    "existing", ["empty_directory", "populated_directory", "file", "symlink", "dangling_symlink"]
)
def test_existing_case_refused_before_commands(
    tmp_path: Path, windows: _Windows, monkeypatch: pytest.MonkeyPatch, existing: str
) -> None:
    case = tmp_path / "fresh case"
    if existing in {"symlink", "dangling_symlink"}:
        _reparse(monkeypatch, case, symlink=True)
    elif existing == "file":
        case.write_bytes(b"retain")
    else:
        case.mkdir()
        if existing == "populated_directory":
            (case / "retain.txt").write_bytes(b"retain")
    with pytest.raises(live.AcquisitionError, match="already exists"):
        _collect(tmp_path)
    assert not windows.calls
    assert not (case / "acquisition_manifest.json").exists()


@pytest.mark.parametrize("tree", ["windows", "profiles_root", "profile"])
def test_source_overlapping_case_refused_before_creation(
    tmp_path: Path, windows: _Windows, tree: str
) -> None:
    root = {
        "windows": windows.windows,
        "profiles_root": windows.profiles_root,
        "profile": windows.profiles[LOADED],
    }[tree]
    case = root / "unsafe fresh case"
    with pytest.raises(live.AcquisitionError, match="overlaps source"):
        live.collect_live_evidence(case, case_id="C", examiner="E")
    assert not case.exists()
    assert not windows.calls


def test_case_cannot_be_ancestor_of_source(tmp_path: Path) -> None:
    case = tmp_path / "uncreated case"
    with pytest.raises(live.AcquisitionError, match="overlaps source"):
        live._validate_case(case, [case / "profile"])
    assert not case.exists()


@pytest.mark.parametrize("symlink", [False, True])
def test_reparse_case_parent_refused(
    tmp_path: Path, windows: _Windows, monkeypatch: pytest.MonkeyPatch, symlink: bool
) -> None:
    parent = tmp_path / "alias"
    parent.mkdir()
    _reparse(monkeypatch, parent, symlink=symlink)
    with pytest.raises(live.AcquisitionError, match="reparse|symlink"):
        live.collect_live_evidence(parent / "fresh", case_id="C", examiner="E")
    assert not windows.calls
    assert not (parent / "fresh").exists()


def test_reparse_native_tool_is_not_executed(
    tmp_path: Path, windows: _Windows, monkeypatch: pytest.MonkeyPatch
) -> None:
    _reparse(monkeypatch, windows.windows / "System32" / "wevtutil.exe", symlink=True)
    result = _collect(tmp_path)
    assert result.has_gaps
    assert _find(result, "System", "wevtutil epl")["status"] == "unavailable"
    assert all(Path(argv[0]).name == "reg.exe" for argv in windows.calls)


@pytest.mark.parametrize("case_id", ["", "  ", None])
def test_empty_case_id_refused(tmp_path: Path, windows: _Windows, case_id: Any) -> None:
    with pytest.raises(live.AcquisitionError, match="case_id"):
        live.collect_live_evidence(tmp_path / "fresh", case_id=case_id, examiner="E")
    assert not windows.calls
    assert not (tmp_path / "fresh").exists()


@pytest.mark.parametrize("examiner", ["", "  ", None])
def test_empty_examiner_refused(tmp_path: Path, windows: _Windows, examiner: Any) -> None:
    with pytest.raises(live.AcquisitionError, match="examiner"):
        live.collect_live_evidence(tmp_path / "fresh", case_id="C", examiner=examiner)
    assert not windows.calls


@pytest.mark.parametrize("timeout", [0, -1, True, 1.5])
def test_invalid_timeout_refused(tmp_path: Path, windows: _Windows, timeout: Any) -> None:
    with pytest.raises(live.AcquisitionError, match="command_timeout"):
        _collect(tmp_path, command_timeout=timeout)
    assert not windows.calls


def test_non_windows_refused_without_elevation_or_discovery(
    tmp_path: Path, windows: _Windows, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(live.platform, "system", lambda: "Linux")

    def forbidden() -> Any:
        pytest.fail("Non-Windows preflight must not call Windows APIs")

    monkeypatch.setattr(live, "_is_elevated", forbidden)
    monkeypatch.setattr(live, "_winreg", forbidden)
    with pytest.raises(live.AcquisitionError, match="requires Windows"):
        _collect(tmp_path)
    assert not windows.calls
    assert not (tmp_path / "fresh case").exists()


def test_non_elevated_token_refused(
    tmp_path: Path, windows: _Windows, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(live, "_is_elevated", lambda: False)
    with pytest.raises(live.AcquisitionError, match="elevated administrator token"):
        _collect(tmp_path)
    assert not windows.calls
    assert not (tmp_path / "fresh case").exists()


def test_elevation_query_failure_refused(
    tmp_path: Path, windows: _Windows, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail() -> bool:
        raise OSError("Mock token query failed")

    monkeypatch.setattr(live, "_is_elevated", fail)
    with pytest.raises(live.AcquisitionError, match="token query failed"):
        _collect(tmp_path)
    assert not windows.calls


def test_manifest_write_failure_is_acquisition_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_open = Path.open

    def deny(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self.name == "acquisition_manifest.json":
            raise PermissionError(13, "Mock manifest write denied")
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", deny)
    with pytest.raises(live.AcquisitionError, match="Cannot write acquisition manifest"):
        _collect(tmp_path)
