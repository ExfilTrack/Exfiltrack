"""Bounded, best-effort live Windows acquisition; never configure source logging.

Only the public collector performs acquisition. Importing this module is safe on
non-Windows hosts, and all Windows access is isolated for synthetic unit tests.
"""

from __future__ import annotations

import ctypes
import importlib
import json
import locale
import os
import platform
import re
import shutil
import stat
import subprocess
import xml.etree.ElementTree as ET
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from exfiltrack.config import ExfilTrackError
from exfiltrack.evidence.hashing import hash_file
from exfiltrack.evidence.manifest import utc_now

# Windows-only ctypes entry points, resolved through getattr so this module
# stays importable and type-checkable on non-Windows hosts (CI runs mypy on
# Linux, where ctypes has no WinDLL/WinError/get_last_error attributes).
# They are only ever called from Windows-only code paths guarded at
# collection time.
_WinError: Any = getattr(ctypes, "WinError", None)
_get_last_error: Any = getattr(ctypes, "get_last_error", None)


def _windll(name: str, **kwargs: Any) -> Any:
    """Load a Windows DLL, resolved at call time so tests can patch ctypes.WinDLL."""
    # getattr is deliberate: attribute access would fail mypy on non-Windows CI.
    return getattr(ctypes, "WinDLL")(name, **kwargs)  # noqa: B009


_CHANNELS = (
    "System",
    "Security",
    "Microsoft-Windows-DriverFrameworks-UserMode/Operational",
)
_PROFILE_LIST = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
_SID = re.compile(r"S-\d+(?:-\d+)+\Z")
_REPARSE_POINT = 0x400
_GAP_STATUSES = {"missing", "unavailable", "error"}
_LIMITATIONS = [
    "Live collection is not an atomic disk or volume snapshot; sources can change during acquisition.",
    "EVTX and loaded registry hives are logical exports, not byte-for-byte source-file images.",
    "Channel configuration describes collection time only. File auditing and SACL history are NOT "
    "verified; absent events do not prove absent activity. Logging and auditing are never enabled, "
    "cleared, or changed by this collector.",
    "Unloaded NTUSER.DAT copies do not include transaction logs or recovery and are not mounted. "
    "Matching copy hashes alone do not establish registry transactional consistency.",
    "Only ProfileList profiles and their standard Recent/Jump List locations are examined; "
    "reparse points, junctions, symlinks, and redirected locations are excluded. No full-disk scan.",
    "Source size and timestamps are recorded; copied access/modification times are retained. "
    "Destination creation time is not preserved. Read-only access may update source access times "
    "through Windows/filesystem policy; source attributes are never explicitly written.",
]


class AcquisitionError(ExfilTrackError):
    """Unsafe preflight, case/manifest I/O failure, or no usable acquired evidence."""


@dataclass(frozen=True)
class AcquisitionResult:
    """Fresh case and acquisition provenance, separate from pipeline manifests."""

    case_dir: Path
    evidence_dir: Path
    reports_dir: Path
    manifest_path: Path
    manifest: dict[str, Any]

    @property
    def has_gaps(self) -> bool:
        return _has_gaps(self.manifest["records"])


def _has_gaps(records: list[dict[str, Any]]) -> bool:
    return any(
        record["status"] in _GAP_STATUSES
        or record.get("metadata", {}).get("channel_enabled") is False
        for record in records
    )


def _record(category: str, source: str, method: str) -> dict[str, Any]:
    return {
        "category": category,
        "source": source,
        "method": method,
        "status": "error",
        "started_at": utc_now().isoformat(),
        "finished_at": utc_now().isoformat(),
        "metadata": {},
    }


def _failure(record: dict[str, Any], exc: Exception) -> None:
    record["status"] = (
        "missing"
        if isinstance(exc, FileNotFoundError)
        else "unavailable" if isinstance(exc, PermissionError) else "error"
    )
    record["message"] = str(exc)
    record["metadata"]["exception"] = type(exc).__name__
    if isinstance(exc, OSError):
        record["metadata"].update(errno=exc.errno, winerror=getattr(exc, "winerror", None))
    record["finished_at"] = utc_now().isoformat()


def _is_elevated() -> bool:
    # Query TokenElevation rather than infer elevation from username/group names.
    kernel = _windll("kernel32", use_last_error=True)
    advapi = _windll("advapi32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    advapi.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    token = wintypes.HANDLE()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
        raise _WinError(_get_last_error())
    try:
        elevated = wintypes.DWORD()
        length = wintypes.DWORD()
        if not advapi.GetTokenInformation(
            token, 20, ctypes.byref(elevated), ctypes.sizeof(elevated), ctypes.byref(length)
        ):
            raise _WinError(_get_last_error())
        return bool(elevated.value)
    finally:
        kernel.CloseHandle(token)


def _windows_directory() -> Path:
    kernel = _windll("kernel32", use_last_error=True)
    kernel.GetWindowsDirectoryW.argtypes = [wintypes.LPWSTR, wintypes.UINT]
    kernel.GetWindowsDirectoryW.restype = wintypes.UINT
    buffer = ctypes.create_unicode_buffer(32768)
    length = kernel.GetWindowsDirectoryW(buffer, len(buffer))
    if not length or length >= len(buffer):
        raise AcquisitionError("Cannot discover the actual Windows directory.")
    path = Path(buffer.value)
    if not path.is_absolute():
        raise AcquisitionError("Windows returned a non-absolute system directory.")
    return path


def _is_wow64() -> bool:
    if ctypes.sizeof(ctypes.c_void_p) != 4:
        return False
    kernel = _windll("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.IsWow64Process.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
    value = wintypes.BOOL()
    if not kernel.IsWow64Process(kernel.GetCurrentProcess(), ctypes.byref(value)):
        raise _WinError(_get_last_error())
    return bool(value.value)


@dataclass
class _Discovery:
    profiles: dict[str, Path]
    loaded_sids: set[str] | None
    roots: list[Path]
    records: list[dict[str, Any]]


def _winreg() -> Any:
    return importlib.import_module("winreg")


def _discover_profiles() -> _Discovery:
    registry = _winreg()
    found = _Discovery({}, None, [], [])
    view = registry.KEY_READ | registry.KEY_WOW64_64KEY

    def problem(source: str, exc: Exception) -> None:
        record = _record("profile_discovery", source, "winreg (64-bit view)")
        _failure(record, exc)
        found.records.append(record)

    def profile_path(value: str) -> Path:
        path = Path(registry.ExpandEnvironmentStrings(value))
        if not path.is_absolute() or "%" in str(path):
            raise ValueError(f"Invalid or unresolved profile path: {value!r}")
        return path

    try:
        with registry.OpenKey(registry.HKEY_LOCAL_MACHINE, _PROFILE_LIST, 0, view) as key:
            try:
                found.roots.append(profile_path(registry.QueryValueEx(key, "ProfilesDirectory")[0]))
            except (OSError, ValueError, TypeError) as exc:
                problem(f"HKLM\\{_PROFILE_LIST}\\ProfilesDirectory", exc)
            count = registry.QueryInfoKey(key)[0]
            for index in range(count):
                sid = ""
                try:
                    sid = registry.EnumKey(key, index)
                    if not _SID.fullmatch(sid):
                        continue
                    with registry.OpenKey(key, sid, 0, view) as profile:
                        path = profile_path(registry.QueryValueEx(profile, "ProfileImagePath")[0])
                        found.profiles[sid] = path
                        found.roots.append(path)
                except (OSError, ValueError, TypeError) as exc:
                    problem(f"HKLM\\{_PROFILE_LIST}\\{sid or index}", exc)
    except OSError as exc:
        problem(f"HKLM\\{_PROFILE_LIST}", exc)

    try:
        with registry.OpenKey(registry.HKEY_USERS, "", 0, view) as key:
            loaded = set()
            for index in range(registry.QueryInfoKey(key)[0]):
                sid = registry.EnumKey(key, index)
                if _SID.fullmatch(sid):
                    loaded.add(sid)
            found.loaded_sids = loaded
    except OSError as exc:
        problem("HKU (loaded user hive discovery)", exc)
    return found


def _no_reparse(path: Path, *, allow_missing: bool = False) -> None:
    for component in reversed((path, *path.parents)):
        try:
            info = component.lstat()
        except FileNotFoundError:
            if allow_missing:
                continue
            raise
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & _REPARSE_POINT:
            raise PermissionError(f"Excluded reparse point/symlink/junction: {component}")


def _validate_case(case_dir: Path, roots: list[Path]) -> Path:
    candidate = case_dir.absolute()
    try:
        candidate.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise AcquisitionError(f"Cannot validate fresh case path '{candidate}': {exc}") from exc
    else:
        raise AcquisitionError(f"Case path already exists; refusing overwrite: '{candidate}'")
    try:
        _no_reparse(candidate, allow_missing=True)
        candidate = candidate.resolve()
        for root in roots:
            for source in (root.absolute(), root.resolve()):
                if candidate.is_relative_to(source) or source.is_relative_to(candidate):
                    raise AcquisitionError(
                        f"Unsafe case path '{candidate}' overlaps source tree '{source}'."
                    )
    except (OSError, RuntimeError) as exc:
        raise AcquisitionError(f"Cannot validate safe case path '{candidate}': {exc}") from exc
    return candidate


def _metadata(info: os.stat_result) -> dict[str, Any]:
    result: dict[str, Any] = {
        "size_bytes": info.st_size,
        "atime_ns": info.st_atime_ns,
        "mtime_ns": info.st_mtime_ns,
        "ctime_ns": info.st_ctime_ns,
    }
    birthtime = getattr(info, "st_birthtime", None)
    if birthtime is not None:
        result["birthtime"] = birthtime
    return result


def _fingerprint(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _diagnostic(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        encoding = (
            "utf-16"
            if value.startswith((b"\xff\xfe", b"\xfe\xff"))
            else ("utf-16-le" if b"\x00" in value else locale.getpreferredencoding(False))
        )
        value = value.decode(encoding, errors="replace")
    return value[:8192] + ("\n[diagnostic truncated]" if len(value) > 8192 else "")


class _Collector:
    def __init__(self, case_dir: Path, timeout: int, records: list[dict[str, Any]]) -> None:
        self.case_dir = case_dir
        self.evidence_dir = case_dir / "evidence"
        self.timeout = timeout
        self.records = records
        self.cleanup_failed = False

    def command(
        self, record: dict[str, Any], argv: list[str]
    ) -> subprocess.CompletedProcess | None:
        record["metadata"]["argv"] = argv
        try:
            executable = Path(argv[0])
            if not executable.is_absolute():
                raise PermissionError("Native executable must be an absolute Windows system path.")
            _no_reparse(executable)
            result = subprocess.run(
                argv,
                shell=False,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=self.timeout,
                check=False,
            )
            record["metadata"].update(
                exit_code=result.returncode,
                stdout=_diagnostic(result.stdout),
                stderr=_diagnostic(result.stderr),
            )
            if result.returncode:
                record["status"] = "error"
                record["message"] = f"Command failed with exit code {result.returncode}."
                return None
            return result
        except subprocess.TimeoutExpired as exc:
            record["status"] = "error"
            record["message"] = f"Command timed out after {self.timeout} seconds."
            record["metadata"].update(
                timeout_seconds=self.timeout,
                stdout=_diagnostic(exc.stdout),
                stderr=_diagnostic(exc.stderr),
            )
        except OSError as exc:
            _failure(record, exc)
        finally:
            record["finished_at"] = utc_now().isoformat()
        return None

    def discard(self, destination: Path, record: dict[str, Any]) -> None:
        try:
            destination.unlink(missing_ok=True)
        except OSError as exc:
            self.cleanup_failed = True
            record["metadata"]["cleanup_error"] = str(exc)
            record["message"] = record.get("message", "") + f" Partial output cleanup failed: {exc}"

    def finish_file(self, destination: Path, record: dict[str, Any], digest: str) -> None:
        record.update(
            status="collected",
            destination=destination.relative_to(self.evidence_dir).as_posix(),
            sha256=digest,
        )
        record["metadata"]["output"] = _metadata(destination.stat())

    def export(
        self,
        category: str,
        source: str,
        method: str,
        relative: Path,
        executable: Path,
        arguments: list[str],
        metadata: dict[str, Any] | None = None,
        warning: str | None = None,
    ) -> None:
        record = _record(category, source, method)
        record["metadata"].update(metadata or {})
        destination = self.evidence_dir / relative
        owned = False
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            # Native exporters require a nonexistent path; never pass /ow or /y.
            try:
                destination.lstat()
            except FileNotFoundError:
                owned = True
            else:
                raise FileExistsError(f"Refusing existing export destination: {destination}")
            argv = [str(executable), *arguments, str(destination)]
            if self.command(record, argv) is not None:
                _no_reparse(destination)
                info = destination.stat()
                if not stat.S_ISREG(info.st_mode) or info.st_size == 0:
                    raise OSError("Export produced no non-empty regular evidence file.")
                self.finish_file(destination, record, hash_file(destination))
                if warning:
                    record["message"] = warning
        except OSError as exc:
            _failure(record, exc)
        finally:
            if owned and record["status"] != "collected":
                self.discard(destination, record)
            record["finished_at"] = utc_now().isoformat()
            self.records.append(record)

    def channel(self, executable: Path, channel: str) -> None:
        config = _record("evtx", channel, "wevtutil gl")
        response = self.command(config, [str(executable), "gl", channel, "/f:xml"])
        enabled = None
        if response is not None:
            try:
                root = ET.fromstring(response.stdout)
                value = root.attrib.get("enabled")
                if value is None:
                    value = next(
                        (node.text for node in root.iter() if node.tag.split("}")[-1] == "enabled"),
                        None,
                    )
                if value is None or value.strip().lower() not in {"true", "false"}:
                    raise ValueError("Channel configuration did not report an enabled state.")
                enabled = value.strip().lower() == "true"
            except (ET.ParseError, ValueError) as exc:
                _failure(config, exc)
        if enabled is None:
            self.records.append(config)
        config["finished_at"] = utc_now().isoformat()
        metadata = {
            "channel_enabled": enabled,
            "channel_configuration": {
                **config["metadata"],
                "started_at": config["started_at"],
                "finished_at": config["finished_at"],
            },
        }
        warning = (
            "Channel is currently disabled; exported history may be incomplete. "
            "The collector did not enable it."
            if enabled is False
            else None
        )
        # The slash in the channel name is a channel identifier, not an output directory.
        relative = Path("evtx") / (channel.replace("/", "_") + ".evtx")
        self.export(
            "evtx",
            channel,
            "wevtutil epl",
            relative,
            executable,
            ["epl", channel],
            metadata,
            warning,
        )

    def source(self, path: Path) -> os.stat_result:
        absolute = path.absolute()
        if absolute.is_relative_to(self.case_dir) or self.case_dir.is_relative_to(absolute):
            raise PermissionError(f"Excluded case-overlapping source: {path}")
        _no_reparse(absolute)
        return absolute.stat()

    def copy(self, source: Path, relative: Path, category: str) -> None:
        record = _record(category, str(source), "read-only copy")
        destination = self.evidence_dir / relative
        owned = False
        try:
            before = self.source(source)
            record["metadata"]["source_before"] = _metadata(before)
            if not stat.S_ISREG(before.st_mode) or not before.st_size:
                raise OSError("Source is not a non-empty regular evidence file.")
            before_hash = hash_file(source)
            record["metadata"]["source_sha256_before"] = before_hash
            destination.parent.mkdir(parents=True, exist_ok=True)
            with source.open("rb") as incoming, destination.open("xb") as outgoing:
                owned = True
                opened = os.fstat(incoming.fileno())
                record["metadata"]["source_handle_before"] = _metadata(opened)
                # Windows stat(path) and fstat(handle) can give ctime different
                # meanings (creation vs. change time). Compare shared fields here.
                if _fingerprint(opened)[:4] != _fingerprint(before)[:4]:
                    raise OSError("Source changed before copy.")
                shutil.copyfileobj(incoming, outgoing, length=65536)
                closed = os.fstat(incoming.fileno())
                record["metadata"]["source_handle_after"] = _metadata(closed)
                if _fingerprint(closed) != _fingerprint(opened):
                    raise OSError("Source changed during copy.")
            after_hash = hash_file(source)
            output_hash = hash_file(destination)
            after = self.source(source)
            record["metadata"].update(
                source_after=_metadata(after),
                source_sha256_after=after_hash,
                output_sha256=output_hash,
            )
            if _fingerprint(before) != _fingerprint(after) or not (
                before_hash == after_hash == output_hash
            ):
                raise OSError("Source changed during acquisition or copied digest does not match.")
            # Set only destination timestamps, using the source's pre-read metadata.
            os.utime(destination, ns=(before.st_atime_ns, before.st_mtime_ns))
            self.finish_file(destination, record, output_hash)
        except OSError as exc:
            _failure(record, exc)
        finally:
            if owned and record["status"] != "collected":
                self.discard(destination, record)
            record["finished_at"] = utc_now().isoformat()
            self.records.append(record)

    def directory(self, source: Path, relative: Path, category: str, suffix: str) -> None:
        record = _record(category, str(source), "directory enumeration (non-recursive)")
        try:
            info = self.source(source)
            if not stat.S_ISDIR(info.st_mode):
                raise NotADirectoryError(str(source))
            entries = sorted(
                (entry for entry in source.iterdir() if entry.name.lower().endswith(suffix)),
                key=lambda entry: entry.name.lower(),
            )
            if not entries:
                record.update(
                    status="empty", message="Readable directory contains no matching artifacts."
                )
                self.records.append(record)
            for entry in entries:
                self.copy(entry, relative / entry.name, category)
        except OSError as exc:
            _failure(record, exc)
            self.records.append(record)
        finally:
            record["finished_at"] = utc_now().isoformat()


def collect_live_evidence(
    case_dir: Path, *, case_id: str, examiner: str, command_timeout: int = 120
) -> AcquisitionResult:
    """Acquire selected artifacts into a strictly fresh case on elevated Windows.

    Returns partial results when some sources are inaccessible. If no usable files
    are acquired, persist the diagnostic manifest and raise ``AcquisitionError``
    containing its path. Preflight refusal creates no case and runs no commands.
    The caller owns CLI/pipeline integration; this function never analyses evidence.
    """
    if platform.system() != "Windows":
        raise AcquisitionError("Live evidence acquisition requires Windows.")
    if not isinstance(case_id, str) or not case_id.strip():
        raise AcquisitionError("case_id must not be empty.")
    if not isinstance(examiner, str) or not examiner.strip():
        raise AcquisitionError("examiner must not be empty.")
    if (
        isinstance(command_timeout, bool)
        or not isinstance(command_timeout, int)
        or command_timeout <= 0
    ):
        raise AcquisitionError("command_timeout must be a positive integer in seconds.")
    started = utc_now().isoformat()
    try:
        if not _is_elevated():
            raise AcquisitionError("Live acquisition requires an elevated administrator token.")
        windows = _windows_directory()
        tools = windows / ("Sysnative" if _is_wow64() else "System32")
        _no_reparse(windows)
        discovery = _discover_profiles()
    except (OSError, ImportError) as exc:
        raise AcquisitionError(f"Cannot complete Windows acquisition preflight: {exc}") from exc
    case_dir = _validate_case(Path(case_dir), [windows, *discovery.roots])
    try:
        case_dir.mkdir(parents=True, exist_ok=False)
        for subdirectory in ("evidence/evtx", "evidence/registry", "evidence/users", "reports"):
            (case_dir / subdirectory).mkdir(parents=True, exist_ok=False)
    except OSError as exc:
        raise AcquisitionError(f"Cannot create fresh case '{case_dir}': {exc}") from exc
    collector = _Collector(case_dir, command_timeout, discovery.records)
    for channel in _CHANNELS:
        collector.channel(tools / "wevtutil.exe", channel)
    for hive in ("SYSTEM", "SOFTWARE"):
        collector.export(
            "registry",
            f"HKLM\\{hive}",
            "reg save",
            Path("registry") / hive,
            tools / "reg.exe",
            ["save", f"HKLM\\{hive}"],
        )
    for sid in sorted(discovery.loaded_sids or ()):
        collector.export(
            "registry",
            f"HKU\\{sid}",
            "reg save",
            Path("users") / sid / "NTUSER.DAT",
            tools / "reg.exe",
            ["save", f"HKU\\{sid}"],
        )
    for sid, profile in sorted(discovery.profiles.items()):
        relative = Path("users") / sid
        if discovery.loaded_sids is None:
            record = _record("registry", f"HKU\\{sid}", "loaded hive check")
            record.update(
                status="unavailable",
                message="Loaded hive state is unknown; no direct hive copy attempted.",
            )
            collector.records.append(record)
        elif sid not in discovery.loaded_sids:
            collector.copy(profile / "NTUSER.DAT", relative / "NTUSER.DAT", "registry")
        recent = profile / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent"
        collector.directory(recent, relative / "Recent", "lnk", ".lnk")
        for folder, suffix in (
            ("AutomaticDestinations", ".automaticdestinations-ms"),
            ("CustomDestinations", ".customdestinations-ms"),
        ):
            collector.directory(recent / folder, relative / "Recent" / folder, "jump_list", suffix)
    manifest = {
        "schema_version": "1.0",
        "case_id": case_id,
        "examiner": examiner,
        "computer_name": platform.node(),
        "start_time": started,
        "end_time": utc_now().isoformat(),
        "coverage": "partial" if _has_gaps(collector.records) else "complete",
        "records": collector.records,
        "limitations": list(_LIMITATIONS),
    }
    manifest_path = case_dir / "acquisition_manifest.json"
    try:
        with manifest_path.open("x", encoding="utf-8") as output:
            json.dump(manifest, output, indent=2, ensure_ascii=True)
            output.write("\n")
    except OSError as exc:
        raise AcquisitionError(
            f"Cannot write acquisition manifest '{manifest_path}': {exc}"
        ) from exc
    if collector.cleanup_failed:
        raise AcquisitionError(
            f"Partial evidence cleanup failed; inspect manifest: {manifest_path}"
        )
    if not any(record["status"] == "collected" for record in collector.records):
        raise AcquisitionError(f"No usable evidence acquired; diagnostic manifest: {manifest_path}")
    return AcquisitionResult(
        case_dir, collector.evidence_dir, case_dir / "reports", manifest_path, manifest
    )
