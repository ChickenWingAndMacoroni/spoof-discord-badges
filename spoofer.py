#!/usr/bin/env python3
"""
discord badge spoofer — vanta rebuild.

per-badge custom targets: game hours, games played, streaming hours.
posts launch_game / running_game_heartbeat / stream events to /api/v9/science,
the same endpoint the real client uses.

stdlib only. python 3.10+.

breaks discord tos. your account, your problem.
"""

from __future__ import annotations

import base64
import json
import os
import random
import subprocess
import sys
import tempfile
import time
import uuid
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Iterator, Sequence

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

ROOT = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
GAMES_FILE = DATA_DIR / "games.json"
STATE_FILE = ROOT / "science_state.json"
CUSTOM_HOURS_FILE = ROOT / "custom_hours.json"

ME_URL = "https://discord.com/api/v9/users/@me?with_analytics_token=true"
SCIENCE_URL = "https://discord.com/api/v9/science"
PROPERTIES_URL = "https://cordapi.dolfi.es/api/v2/properties/windows"
GAMES_CDN_URL = "https://cdn.discordapp.com/detectables/games.json"

BATCH_SIZE = 50
BATCH_DELAY = 1.0
AUTH_MAX_AGE = 12 * 3600
PROPS_CACHE_TTL = 3600
RETRY_429_WAIT = 5.0
DEBUG = False

CLIENT_VERSION = "1.0.9253"
CLIENT_BUILD_NUMBER = 594031
NATIVE_BUILD_NUMBER = 88414
OS_VERSION = "10.0.26200"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) discord/1.0.9253 Chrome/148.0.7778.280 "
    "Electron/42.7.1 Safari/537.36"
)


def _user_id_from_token(token: str) -> str:
    try:
        first = token.split(".", 1)[0]
        pad = "=" * (-len(first) % 4)
        return base64.b64decode(first + pad).decode("utf-8")
    except Exception:
        return ""


_FINGERPRINT_PS1 = r'''
param(
  [int]$ProcessId = 0,
  [string]$Path,
  [Parameter(Mandatory = $true)][string]$UserId
)

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class CertPubKeyHash {
  const uint X509_ASN_ENCODING = 0x00000001;
  const uint PKCS_7_ASN_ENCODING = 0x00010000;
  const uint CALG_SHA_256 = 0x0000800C;

  [StructLayout(LayoutKind.Sequential)] struct Blob { public uint cbData; public IntPtr pbData; }
  [StructLayout(LayoutKind.Sequential)] struct AlgId { public IntPtr pszObjId; public Blob Parameters; }
  [StructLayout(LayoutKind.Sequential)] struct BitBlob { public uint cbData; public IntPtr pbData; public uint cUnusedBits; }
  [StructLayout(LayoutKind.Sequential)] struct PubKeyInfo { public AlgId Algorithm; public BitBlob PublicKey; }
  [StructLayout(LayoutKind.Sequential)] struct FileTime { public uint Low; public uint High; }
  [StructLayout(LayoutKind.Sequential)]
  struct CertInfo {
    public uint Version; public Blob SerialNumber; public AlgId SignatureAlgorithm; public Blob Issuer;
    public FileTime NotBefore; public FileTime NotAfter; public Blob Subject;
    public PubKeyInfo SubjectPublicKeyInfo; public BitBlob IssuerUniqueId; public BitBlob SubjectUniqueId;
    public uint ExtensionCount; public IntPtr Extensions;
  }
  [StructLayout(LayoutKind.Sequential)]
  struct CertContext {
    public uint EncodingType; public IntPtr Encoded; public uint EncodedSize;
    public IntPtr CertInfo; public IntPtr Store;
  }

  [DllImport("crypt32.dll", SetLastError = true)]
  static extern bool CryptHashPublicKeyInfo(
    IntPtr provider, uint algid, uint flags, uint encoding, ref PubKeyInfo info, byte[] hash, ref uint hashSize);

  public static byte[] Hash(IntPtr certContext) {
    var ctx = Marshal.PtrToStructure<CertContext>(certContext);
    var info = Marshal.PtrToStructure<CertInfo>(ctx.CertInfo);
    var hash = new byte[32];
    uint hashSize = 32;
    if (!CryptHashPublicKeyInfo(IntPtr.Zero, CALG_SHA_256, 0, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, ref info.SubjectPublicKeyInfo, hash, ref hashSize) || hashSize != 32)
      throw new InvalidOperationException("CryptHashPublicKeyInfo failed");
    return hash;
  }
}
"@

if (!$Path) {
  if (!$ProcessId) { throw "Pass -Path <exe> or -ProcessId <pid>." }
  $Path = (Get-Process -Id $ProcessId).Path
}
if (!$Path) { throw "Could not resolve executable path." }

$fs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
try {
  $fileSize = [UInt64]$fs.Length
  $readSize = [int][Math]::Min($fs.Length, 0x10000)
  $buf = [byte[]]::new($readSize)
  $read = $fs.Read($buf, 0, $readSize)
  if ($read -lt 0x40) { throw "File prefix is too small." }
  if ($read -ne $readSize) { [Array]::Resize([ref]$buf, $read) }
} finally {
  $fs.Dispose()
}

if ([BitConverter]::ToUInt16($buf, 0) -ne 0x5A4D) { throw "Not an MZ executable." }
$pe = [BitConverter]::ToInt32($buf, 0x3C)
if ($pe -lt 0 -or [BitConverter]::ToUInt32($buf, $pe) -ne 0x4550) { throw "Not a PE executable." }

$fh = $pe + 4
$sections = [BitConverter]::ToUInt16($buf, $fh + 2)
$timestamp = [BitConverter]::ToUInt32($buf, $fh + 4)
$optSize = [BitConverter]::ToUInt16($buf, $fh + 16)
$opt = $fh + 20
$isPe32Plus = [BitConverter]::ToUInt16($buf, $opt) -eq 0x20B
if (!$isPe32Plus) { throw "Discord only fingerprints PE32+." }
$sizeOfImage = [BitConverter]::ToUInt32($buf, $opt + 56)

$sectionTable = $opt + $optSize
$sha256 = [Security.Cryptography.SHA256]::Create()
$headerHash = $sha256.ComputeHash([byte[]]$buf[0..($sectionTable - 1)])
$sectionHash = $sha256.ComputeHash([byte[]]$buf[$sectionTable..($sectionTable + $sections * 40 - 1)])

$machineGuid = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography" -Name MachineGuid).MachineGuid
$machineUserHash = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($machineGuid + $UserId))

$sig = Get-AuthenticodeSignature -LiteralPath $Path
$signed = $sig.Status -eq "Valid" -and $sig.SignerCertificate
if ($signed) {
  $name = $sig.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
  $certHash = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($name) + [CertPubKeyHash]::Hash($sig.SignerCertificate.Handle))
} else {
  $certHash = [byte[]]::new(32)
}

$flags = 0
if ($signed) { $flags += 1 }
if ($isPe32Plus) { $flags += 2 }

$out = [byte[]](@(1, [byte]$flags) +
  [BitConverter]::GetBytes($fileSize) +
  [BitConverter]::GetBytes($timestamp) +
  [BitConverter]::GetBytes($sizeOfImage) +
  $headerHash + $machineUserHash + $sectionHash + $certHash)

$key = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($UserId + "https://discord.com/careers"))
for ($i = 1; $i -lt $out.Length; $i++) {
  $out[$i] = $out[$i] -bxor $key[($i - 1) -band 31]
}

[Convert]::ToBase64String($out)
'''


def generate_fingerprint(user_id: str, path: str = "", pid: int = 0) -> str:
    if os.name != "nt":
        raise RuntimeError("fingerprint generation is windows-only")
    script = Path(tempfile.gettempdir()) / f"disc_fp_{uuid.uuid4().hex}.ps1"
    script.write_text(_FINGERPRINT_PS1, encoding="utf-8")
    try:
        args = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", str(script), "-UserId", user_id]
        args += (["-ProcessId", str(pid)] if pid else ["-Path", path])
        result = subprocess.run(args, capture_output=True, text=True, timeout=60)
    finally:
        try:
            script.unlink()
        except OSError:
            pass
    if result.returncode != 0:
        lines = (result.stderr or result.stdout or "").strip().splitlines()
        raise RuntimeError(lines[-1] if lines else "powershell failed")
    out = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not out:
        raise RuntimeError("generator produced no output")
    return out[-1]


class Console:
    RED = "\x1b[91m"
    ORANGE = "\x1b[38;5;208m"
    GREEN = "\x1b[92m"
    YELLOW = "\x1b[93m"
    WHITE = "\x1b[97m"
    GREY = "\x1b[90m"
    RESET = "\x1b[0m"
    RULE = "─" * 44

    def __init__(self) -> None:
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
        if sys.platform == "win32":
            self._enable_ansi()

    @staticmethod
    def _enable_ansi() -> None:
        import ctypes
        k = ctypes.windll.kernel32
        h = k.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if k.GetConsoleMode(h, ctypes.byref(mode)):
            k.SetConsoleMode(h, mode.value | 0x0004)

    def _stamp(self) -> str:
        return f"{self.GREY}{time.strftime('%H:%M:%S')}{self.RESET}"

    def _line(self, glyph: str, target: str, detail: str, color: str) -> None:
        print(f"  {self._stamp()} {glyph} {self.WHITE}{target}{self.RESET} "
              f"{self.GREY}·{self.RESET} {color}{detail}{self.RESET}")

    def ok(self, target: str, detail: str) -> None:
        self._line(f"{self.GREEN}✓{self.RESET}", target, detail, self.GREEN)

    def sent(self, target: str, detail: str) -> None:
        self._line(f"{self.GREY}·{self.RESET} {self.GREEN}sent{self.RESET}", target, detail, self.GREEN)

    def warn(self, target: str, detail: str) -> None:
        self._line(f"{self.YELLOW}!{self.RESET}", target, detail, self.YELLOW)

    def err(self, target: str, detail: str) -> None:
        self._line(f"{self.RED}✗{self.RESET}", target, detail, self.RED)

    def info(self, detail: str) -> None:
        print(f"  {self._stamp()} {self.GREY}·{self.RESET} {self.WHITE}{detail}{self.RESET}")

    def rule(self) -> None:
        print(f"  {self.GREY}{self.RULE}{self.RESET}")

    def clear(self) -> None:
        print("\x1b[2J\x1b[3J\x1b[H", end="")

    def banner(self) -> None:
        self.clear()
        print()
        print(f"  {self.ORANGE}spoofer{self.RESET} {self.GREY}·{self.RESET} {self.WHITE}discord badges{self.RESET}")
        print(f"    {self.GREY}vanta rebuild{self.RESET}")
        print()
@dataclass
class State:
    token: str = ""
    cookie: str = ""
    fingerprint: str = ""
    analytics_token: str = ""
    fetched_at: int = 0
    used_games: list[str] = field(default_factory=list)
    total_games_claimed: int = 0
    total_hours_claimed: float = 0.0
    total_stream_hours_claimed: float = 0.0
    event_log: list[dict] = field(default_factory=list)
    props_cache: dict = field(default_factory=dict)
    props_cached_at: int = 0

    @classmethod
    def load(cls) -> "State":
        if STATE_FILE.exists():
            try:
                data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
                return cls(**{k: data.get(k, v) for k, v in cls().__dict__.items()})
            except (json.JSONDecodeError, TypeError):
                pass
        return cls()

    def save(self) -> None:
        STATE_FILE.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")

    @property
    def is_stale(self) -> bool:
        return not self.analytics_token or (time.time() - self.fetched_at) > AUTH_MAX_AGE

    @property
    def has_cookie(self) -> bool:
        return bool(self.cookie.strip())

    @property
    def has_token(self) -> bool:
        return bool(self.token.strip())


def _local_props() -> dict:
    return {
        "os": "Windows", "browser": "Discord Client", "release_channel": "stable",
        "client_version": CLIENT_VERSION, "os_version": OS_VERSION,
        "os_arch": "x64", "app_arch": "x64", "system_locale": "en-GB",
        "has_client_mods": False, "browser_user_agent": USER_AGENT,
        "browser_version": "42.7.1", "os_sdk_version": "26200",
        "client_build_number": CLIENT_BUILD_NUMBER,
        "native_build_number": NATIVE_BUILD_NUMBER,
        "client_event_source": None, "client_app_state": "focused",
    }


def _fetch_props() -> dict:
    try:
        req = urllib.request.Request(PROPERTIES_URL, method="POST", data=b"{}",
                                     headers={"content-type": "application/json", "user-agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read().decode("utf-8"))["properties"]
    except Exception:
        return _local_props()


def _cached_props(state: State) -> dict:
    if state.props_cache and (time.time() - state.props_cached_at) < PROPS_CACHE_TTL:
        return state.props_cache
    props = _fetch_props()
    state.props_cache = props
    state.props_cached_at = int(time.time())
    state.save()
    return props


def build_super_props(state: State, launch_signature: str, heartbeat_session: str) -> str:
    props = dict(_cached_props(state))
    props["client_launch_id"] = str(uuid.uuid4())
    props["launch_signature"] = launch_signature
    props["client_heartbeat_session_id"] = heartbeat_session
    raw = json.dumps(props, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def _read_analytics_token(auth_token: str, super_props: str) -> str:
    req = urllib.request.Request(ME_URL, headers={
        "authorization": auth_token, "user-agent": USER_AGENT,
        "x-super-properties": super_props,
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"token rejected ({exc.code})") from exc
    tok = data.get("analytics_token")
    if not tok:
        raise RuntimeError("no analytics_token in response")
    return tok


def ensure_token(state: State, super_props: str) -> None:
    if not state.is_stale:
        return
    state.analytics_token = _read_analytics_token(state.token, super_props)
    state.fetched_at = int(time.time())
    state.save()


@dataclass(frozen=True)
class Session:
    heartbeat_session: str
    launch_signature: str
    super_props: str

    @classmethod
    def new(cls, state: State) -> "Session":
        hb = str(uuid.uuid4())
        sig = str(uuid.uuid4())
        return cls(hb, sig, build_super_props(state, sig, hb))


@dataclass(frozen=True)
class Game:
    id: str
    name: str
    exe: str


def _win_exe(game: dict) -> str:
    for e in game.get("executables", []):
        if e.get("os") == "win32" and e.get("name"):
            return e["name"]
    return "game.exe"


def _download_games() -> str:
    req = urllib.request.Request(GAMES_CDN_URL, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        raw = r.read().decode("utf-8")
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        GAMES_FILE.write_text(raw, encoding="utf-8")
    except OSError:
        pass
    return raw


def _parse_games(raw: str) -> list[Game]:
    data = json.loads(raw)
    games, seen = [], set()
    for entry in data:
        gid = str(entry.get("id", ""))
        if not gid.isdigit() or gid in seen:
            continue
        if not any(e.get("os") == "win32" and e.get("name") for e in entry.get("executables", [])):
            continue
        seen.add(gid)
        games.append(Game(gid, entry.get("name", "Unknown"), _win_exe(entry)))
    return games


def load_games() -> list[Game]:
    raw = ""
    if GAMES_FILE.exists():
        raw = GAMES_FILE.read_text(encoding="utf-8").strip()
    if raw:
        try:
            g = _parse_games(raw)
            if g:
                return g
        except (json.JSONDecodeError, ValueError):
            pass
    try:
        return _parse_games(_download_games())
    except Exception:
        return []


class ScienceClient:
    def __init__(self, state: State, session: Session) -> None:
        self.state = state
        self.session = session
        self._seq = 0

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def build_launch(self, game: Game, ts: int | None = None) -> dict:
        now = int(time.time() * 1000) if ts is None else ts
        props = {
            "client_track_timestamp": now,
            "client_heartbeat_session_id": self.session.heartbeat_session,
            "event_sequence_number": self._next_seq(),
            "game": game.name, "game_id": game.id,
            "verified": True, "elevated": False, "is_launcher": False,
            "game_platform": "desktop", "detection_method": "verified_game",
            "is_overlay_enabled": False, "is_overlay_game_enabled": True,
            "is_overlay_game_source": "OOP_DEFAULT_DATABASE",
            "fullscreen_type": "UNKNOWN", "hardware_display_count": 1,
            "overlay_method": "Disabled",
            "activity_status_enabled": True, "activity_status_shared_guilds": [],
            "current_user_status": "online", "game_detection_enabled": True,
            "executable_path": game.exe,
            "voice_channel_id": None, "voice_channel_type": None,
            "voice_channel_bitrate": None, "voice_channel_guild_id": None,
            "hidden_by_distributor": False, "game_metadata": None,
            "client_performance_cpu": None, "client_performance_memory": None,
            "cpu_core_count": None, "accessibility_features": 0,
            "rendered_locale": "en-GB",
            "launch_signature": self.session.launch_signature,
            "client_rtc_state": None, "client_app_state": "focused",
            "client_send_timestamp": now,
        }
        if self.state.fingerprint:
            props["executable_fingerprint"] = self.state.fingerprint
        return {"type": "launch_game", "properties": props}

    def build_heartbeat(self, game: Game, duration_ms: int, session_id: str,
                        initial: bool, final: bool, ts: int) -> dict:
        return {
            "type": "running_game_heartbeat",
            "properties": {
                "client_track_timestamp": ts,
                "client_heartbeat_session_id": self.session.heartbeat_session,
                "event_sequence_number": self._next_seq(),
                "game_id": game.id, "game_name": game.name, "game_metadata": None,
                "game_executable": game.exe, "game_detection_enabled": True,
                "initial_heartbeat": initial, "final_heartbeat": final,
                "game_session_id": session_id, "duration_tracked_ms": duration_ms,
                "rtc_connection_id": None, "media_session_id": None,
                "launch_signature": self.session.launch_signature,
                "client_app_state": "focused",
                "client_send_timestamp": ts,
            },
        }

    def build_session(self, game: Game, duration_ms: int, end_ts: int) -> list[dict]:
        sid = str(uuid.uuid4())
        start = max(0, end_ts - duration_ms)
        return [
            self.build_heartbeat(game, 0, sid, initial=True, final=False, ts=start),
            self.build_launch(game, ts=start + 200),
            self.build_heartbeat(game, duration_ms, sid, initial=False, final=True, ts=end_ts),
        ]

    def build_stream_session(self, duration_ms: int, end_ts: int) -> list[dict]:
        sid = str(uuid.uuid4())
        start = max(0, end_ts - duration_ms)
        base = {
            "client_track_timestamp": start,
            "client_heartbeat_session_id": self.session.heartbeat_session,
            "launch_signature": self.session.launch_signature,
            "client_app_state": "focused",
        }
        started = {
            "type": "stream_started",
            "properties": {**base, "event_sequence_number": self._next_seq(),
                           "stream_session_id": sid, "client_send_timestamp": start},
        }
        ended = {
            "type": "stream_ended",
            "properties": {**base, "event_sequence_number": self._next_seq(),
                           "stream_session_id": sid, "duration_tracked_ms": duration_ms,
                           "client_track_timestamp": end_ts, "client_send_timestamp": end_ts},
        }
        return [started, ended]

    def post(self, events: Sequence[dict]) -> int:
        payload = {"token": self.state.analytics_token, "events": list(events)}
        body = json.dumps(payload).encode("utf-8")
        headers = {
            "accept": "*/*", "accept-language": "en-GB",
            "authorization": self.state.token, "content-type": "application/json",
            "cookie": self.state.cookie, "origin": "https://discord.com",
            "referer": "https://discord.com/channels/@me",
            "user-agent": USER_AGENT, "x-debug-options": "bugReporterEnabled",
            "x-discord-locale": "en-GB", "x-discord-timezone": "Europe/Oslo",
            "x-super-properties": self.session.super_props,
        }
        if DEBUG:
            print(f"\nPOST {SCIENCE_URL} ({len(events)} events)")
            print(json.dumps(payload, indent=2))
        req = urllib.request.Request(SCIENCE_URL, data=body, method="POST", headers=headers)
        for attempt in range(3):
            try:
                with urllib.request.urlopen(req, timeout=15) as r:
                    return r.status
            except urllib.error.HTTPError as exc:
                if exc.code == 429 and attempt < 2:
                    time.sleep(RETRY_429_WAIT * (attempt + 1))
                    continue
                return exc.code
            except Exception:
                if attempt < 2:
                    time.sleep(1.0)
                    continue
                return 0
        return 0


def _chunked(items: Sequence, size: int) -> Iterator[Sequence]:
    for s in range(0, len(items), size):
        yield items[s:s + size]


class Spoofer:
    def __init__(self, client: ScienceClient, console: Console) -> None:
        self.client = client
        self.console = console

    def run(self, games: Sequence[Game], build_events, label: str) -> int:
        total = len(games)
        sent = 0
        for req_no, chunk in enumerate(_chunked(games, BATCH_SIZE), start=1):
            events = []
            for game in chunk:
                events.extend(build_events(game))
            if not events:
                continue
            status = self.client.post(events)
            log = {"ts": int(time.time()), "label": label, "status": status,
                   "games": [g.id for g in chunk], "event_count": len(events)}
            self.client.state.event_log.append(log)
            self.client.state.event_log = self.client.state.event_log[-500:]
            if status == 204:
                sent += len(chunk)
                self.console.sent(f"batch {req_no}", f"{sent}/{total} games")
            elif status in (401, 403):
                self.console.err(f"batch {req_no}", f"[{status}] auth rejected")
                return sent
            else:
                self.console.warn(f"batch {req_no}", f"[{status}]")
            time.sleep(BATCH_DELAY)
        return sent


def _distribute_hours(total_hours: float, n: int) -> list[float]:
    if n <= 0:
        return []
    raw = [random.lognormvariate(1.0, 0.9) for _ in range(n)]
    s = sum(raw)
    return [h / s * total_hours for h in raw]


def _split_sessions(hours: float, max_session_h: float = 3.0) -> list[float]:
    if hours <= 0:
        return []
    sessions = []
    remaining = hours
    while remaining > 0:
        s = min(remaining, random.uniform(max_session_h * 0.4, max_session_h))
        sessions.append(s)
        remaining -= s
    return sessions


def _schedule_sessions(sessions_h: list[float]) -> list[tuple[int, int]]:
    now = int(time.time() * 1000)
    day = 86_400_000
    latest_end = now - int(random.uniform(0, 14) * day)
    slots = []
    cursor = latest_end
    for h in sessions_h:
        dur = max(60_000, int(h * 3_600_000))
        start = cursor - dur
        slots.append((start, cursor))
        cursor = start - int(random.uniform(1, 8) * 3_600_000)
    return slots
class App:
    def __init__(self) -> None:
        self.console = Console()
        self.state = State.load()
        self.session: Session | None = None
        self.client: ScienceClient | None = None
        self.games: list[Game] = []

    def start(self) -> None:
        C = self.console
        C.banner()
        time.sleep(0.5)

        if not self.state.has_token:
            self._prompt_token()
        if not self.state.has_token:
            C.err("token", "required to run")
            return

        if not self.state.has_cookie:
            C.banner()
            self._prompt_cookie()
        if not self.state.has_cookie:
            C.err("cookie", "required to run")
            return

        self.console.banner()
        C.info("loading games...")
        self.games = load_games()
        if not self.games:
            C.err("games", "couldn't load game list")
            return
        C.ok("games", f"{len(self.games)} loaded")

        C.info("validating auth...")
        self._new_session()
        try:
            ensure_token(self.state, self.session.super_props)
        except Exception as exc:
            C.err("token", str(exc))
            return
        C.ok("auth", "ready")
        time.sleep(0.4)
        self.menu()

    def _new_session(self) -> None:
        self.session = Session.new(self.state)
        self.client = ScienceClient(self.state, self.session)

    def _prompt_token(self) -> None:
        self.console.info("paste your discord account token")
        t = input(f"  {self.console.GREY}token:{self.console.RESET} ").strip()
        if t:
            self.state.token = t
            self.state.save()
            self.console.ok("token", "saved")

    def _prompt_cookie(self) -> None:
        self.console.info("paste your cf_clearance cookie header")
        c = input(f"  {self.console.GREY}cookie:{self.console.RESET} ").strip()
        if c:
            self.state.cookie = c
            self.state.save()
            self.console.ok("cookie", "saved")

    def _require_ready(self) -> bool:
        if not self.state.has_cookie:
            self.console.err("cookie", "not set")
            return False
        if self.state.is_stale:
            try:
                ensure_token(self.state, self.session.super_props)
            except Exception as exc:
                self.console.err("auth", str(exc))
                return False
            self._new_session()
        return bool(self.state.analytics_token)

    def _refresh(self) -> None:
        C = self.console
        C.info("update cookie? [y/n]")
        if input(f"  {C.GREY}›{C.RESET} ").strip().lower() in ("y", "yes"):
            C.info("paste fresh cookie header")
            c = input(f"  {C.GREY}cookie:{C.RESET} ").strip()
            if c:
                self.state.cookie = c
                C.ok("cookie", "updated")
        C.info("refreshing analytics token...")
        try:
            self.state.fetched_at = 0
            ensure_token(self.state, self.session.super_props)
        except Exception as exc:
            C.err("auth", str(exc))
            return
        self._new_session()
        self.state.save()
        C.ok("auth", "refreshed")

    def game_hours(self) -> None:
        if not self._require_ready():
            return
        C = self.console

        custom = None
        if CUSTOM_HOURS_FILE.exists():
            try:
                custom = json.loads(CUSTOM_HOURS_FILE.read_text(encoding="utf-8"))
                C.info(f"using custom_hours.json ({len(custom)} entries)")
            except json.JSONDecodeError:
                C.warn("custom_hours.json", "invalid, ignoring")

        if custom:
            id_map = {g.id: g for g in self.games}
            selected = [id_map[gid] for gid in custom if gid in id_map]
            hours_map = {gid: float(h) for gid, h in custom.items() if gid in id_map}
            if not selected:
                C.err("custom_hours", "no matching game ids")
                return
            for g in selected:
                if g.id not in self.state.used_games:
                    self.state.used_games.append(g.id)
        else:
            raw_n = input(f"  {C.GREY}how many games? [20]:{C.RESET} ").strip()
            n = int(raw_n) if raw_n.isdigit() else 20
            n = min(n, len(self.games))
            raw_h = input(f"  {C.GREY}total hours across all? [40]:{C.RESET} ").strip()
            try:
                total_h = float(raw_h) if raw_h else 40.0
            except ValueError:
                C.err("input", "invalid hours")
                return
            selected = self._select_games(n)
            hours_list = _distribute_hours(total_h, len(selected))
            hours_map = {g.id: h for g, h in zip(selected, hours_list)}

        C.info(f"claiming on {len(selected)} games · {sum(hours_map.values()):,.1f}h total")

        def build(g: Game):
            h = hours_map[g.id]
            if h <= 0:
                return []
            events = []
            for start, end in _schedule_sessions(_split_sessions(h)):
                events.extend(self.client.build_session(g, end - start, end))
            return events

        ok = Spoofer(self.client, self.console).run(selected, build, "game_hours")
        self.state.total_games_claimed += ok
        self.state.total_hours_claimed += sum(hours_map[g.id] for g in selected[:ok])
        self.state.save()
        C.ok("complete", f"{ok}/{len(selected)} games")
        input(f"  {C.ORANGE}›{C.RESET} enter to continue")

    def games_played(self) -> None:
        if not self._require_ready():
            return
        C = self.console
        raw_n = input(f"  {C.GREY}how many games? [50]:{C.RESET} ").strip()
        n = int(raw_n) if raw_n.isdigit() else 50
        n = min(n, len(self.games))
        selected = self._select_games(n)
        C.info(f"marking {len(selected)} games played (1 min each)")
        if not self.state.fingerprint:
            C.warn("fingerprint", "not set · games-played may not credit")

        def build(g: Game):
            days_ago = random.uniform(0, 30)
            end_ts = int(time.time() * 1000) - int(days_ago * 86_400_000)
            return self.client.build_session(g, 60_000, end_ts)

        ok = Spoofer(self.client, self.console).run(selected, build, "games_played")
        self.state.total_games_claimed += ok
        self.state.save()
        C.ok("complete", f"{ok}/{len(selected)} games")

    def streaming_hours(self) -> None:
        if not self._require_ready():
            return
        C = self.console
        C.warn("streaming", "speculative path — event shape invented, likely won't move the badge")
        raw_h = input(f"  {C.GREY}total stream hours? [20]:{C.RESET} ").strip()
        try:
            total_h = float(raw_h) if raw_h else 20.0
        except ValueError:
            C.err("input", "invalid hours")
            return

        sessions = _split_sessions(total_h, max_session_h=4.0)
        slots = _schedule_sessions(sessions)
        all_events = []
        for start, end in slots:
            all_events.extend(self.client.build_stream_session(end - start, end))

        C.info(f"posting {len(slots)} stream sessions · {total_h:g}h")
        posted_h = 0.0
        total_events = max(1, len(all_events))
        for req_no, chunk in enumerate(_chunked(all_events, 50), start=1):
            status = self.client.post(chunk)
            self.state.event_log.append({
                "ts": int(time.time()), "label": "streaming_hours",
                "status": status, "event_count": len(chunk),
            })
            if status == 204:
                C.sent(f"batch {req_no}", f"{len(chunk)} events")
                posted_h += total_h * (len(chunk) / total_events)
            else:
                C.warn(f"batch {req_no}", f"[{status}]")
            time.sleep(BATCH_DELAY)
        self.state.total_stream_hours_claimed += posted_h
        self.state.event_log = self.state.event_log[-500:]
        self.state.save()
        C.ok("complete", f"~{posted_h:g}h posted")

    def set_fingerprint(self) -> None:
        C = self.console
        uid = _user_id_from_token(self.state.token)
        if not uid:
            C.err("fingerprint", "no valid token")
            return
        if os.name != "nt":
            C.err("fingerprint", "windows-only")
            return
        C.info(f"account: {uid}")
        C.info("point at a game's .exe or a running game's pid")
        entered = input(f"  {C.GREY}exe path or pid:{C.RESET} ").strip().strip('"')
        if not entered:
            return
        pid = int(entered) if entered.isdigit() else 0
        path = "" if pid else entered
        if path and not Path(path).exists():
            C.err("fingerprint", f"not found: {path}")
            return
        C.info("generating...")
        try:
            fp = generate_fingerprint(uid, path=path, pid=pid)
        except Exception as exc:
            C.err("fingerprint", str(exc))
            return
        self.state.fingerprint = fp
        self.state.save()
        C.ok("fingerprint", f"set ({len(fp)} chars)")

    def _select_games(self, count: int) -> list[Game]:
        available = {g.id for g in self.games}
        unused = [g.id for g in self.games if g.id not in self.state.used_games]
        used = [gid for gid in self.state.used_games if gid in available]
        if len(unused) >= count:
            sel = unused[:count]
        else:
            sel = list(unused)
            if used:
                rem = count - len(sel)
                sel.extend(used[:rem])
        self.state.used_games = [gid for gid in self.state.used_games if gid not in sel] + sel
        id_map = {g.id: g for g in self.games}
        return [id_map[gid] for gid in sel if gid in id_map]

    def menu(self) -> None:
        C = self.console
        while True:
            C.clear()
            C.banner()
            print()
            C.info(f"{len(self.games)} games loaded")
            C.info(f"claimed {self.state.total_games_claimed} games · "
                   f"{self.state.total_hours_claimed:,.0f}h · "
                   f"{self.state.total_stream_hours_claimed:,.0f}h stream")
            C.rule()
            C.info(f"{C.ORANGE}1{C.RESET} · game hours")
            C.info(f"{C.ORANGE}2{C.RESET} · games played")
            C.info(f"{C.ORANGE}3{C.RESET} · streaming hours {C.YELLOW}(speculative){C.RESET}")
            C.info(f"{C.ORANGE}4{C.RESET} · set fingerprint")
            C.info(f"{C.ORANGE}5{C.RESET} · refresh auth")
            C.info(f"{C.ORANGE}6{C.RESET} · exit")
            C.rule()
            choice = input(f"  {C.ORANGE}›{C.RESET} ").strip()
            print()
            if choice == "1":
                self.game_hours()
            elif choice == "2":
                self.games_played()
            elif choice == "3":
                self.streaming_hours()
            elif choice == "4":
                self.set_fingerprint()
            elif choice == "5":
                self._refresh()
            elif choice in ("6", ""):
                break
            else:
                C.warn("input", "invalid")


def main() -> None:
    try:
        App().start()
    except KeyboardInterrupt:
        print()
        Console().warn("exit", "interrupted")


if __name__ == "__main__":
    main()