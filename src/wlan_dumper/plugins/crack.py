"""Crack plugin — offline passphrase recovery (risk=passive, no RF).

Takes a captured handshake artifact (``.22000`` for hashcat, ``.pcap`` for
aircrack-ng) and runs the selected backend to recover the Wi-Fi passphrase.
Streams ``CrackProgress`` while it runs and publishes ``CrackComplete`` at the
end (with the password on a hit, ``None`` on exhaust/cancel). A hit is also
written to ``captures/cracked/<essid>_<bssid>.txt``.

Cracking transmits nothing, so the authorization risk is PASSIVE — but it can
burn hours of CPU/GPU, which is why the keyspace+ETA estimate is shown before
the operator commits (see ``core/crack.py``).
"""

from __future__ import annotations

import subprocess
import threading
import time
from typing import TYPE_CHECKING

import click

from wlan_dumper.core.auth import AuthorizationGate, PluginRisk
from wlan_dumper.core.crack import CrackError, CrackJob, detect_backend
from wlan_dumper.core.events import (
    CrackComplete,
    CrackProgress,
    CrackStarted,
    EventBus,
)
from wlan_dumper.plugins.base import Plugin, PluginContext
from wlan_dumper.utils import aircrack, hashcat
from wlan_dumper.utils.paths import cracked_path

if TYPE_CHECKING:
    from collections.abc import Callable

_PROGRESS_INTERVAL = 2.0  # seconds between CrackProgress emissions


class CrackPlugin(Plugin):
    name = "crack"
    risk = PluginRisk.PASSIVE  # offline; transmits no frames
    requires_injection = False

    def __init__(self) -> None:
        self._cancel = threading.Event()

    # ---- CLI surface -------------------------------------------------------
    def register_cli(self, group: click.Group) -> None:
        @group.command(name=self.name, help="Crack a captured handshake")
        @click.option("--hash", "hash_path", required=True, help=".22000 or .pcap path")
        @click.option("--bssid", "-b", required=True, help="AP BSSID")
        @click.option("--essid", "-e", default=None, help="AP ESSID (for output naming)")
        @click.option(
            "--mode",
            type=click.Choice(["wordlist", "mask", "smart"]),
            default="wordlist",
            show_default=True,
        )
        @click.option("--wordlist", "-w", default=None, help="Wordlist path (wordlist mode)")
        @click.option("--mask", default=None, help="hashcat mask (mask mode)")
        @click.option("--rules", "-r", default=None, help="hashcat rule file")
        @click.option("--backend", default=None, help="Force backend: hashcat|aircrack-ng")
        @click.pass_context
        def crack_cmd(
            ctx: click.Context,
            hash_path: str,
            bssid: str,
            essid: str | None,
            mode: str,
            wordlist: str | None,
            mask: str | None,
            rules: str | None,
            backend: str | None,
        ) -> None:
            from wlan_dumper.cli import build_runtime_for

            runtime = build_runtime_for(ctx)
            rc = self.execute(
                bus=runtime.bus,
                gate=runtime.gate,
                hash_path=hash_path,
                bssid=bssid,
                essid=essid,
                mode=mode,
                wordlist=wordlist,
                mask=mask,
                rules=rules,
                backend=backend,
            )
            ctx.exit(rc)

    # ---- main entry --------------------------------------------------------
    def execute(
        self,
        *,
        bus: EventBus,
        gate: AuthorizationGate,
        hash_path: str,
        bssid: str,
        essid: str | None,
        mode: str = "wordlist",
        wordlist: str | None = None,
        mask: str | None = None,
        rules: str | None = None,
        backend: str | None = None,
    ) -> int:
        gate.check(plugin=self.name, risk=self.risk, target=bssid, reason=None)
        self._cancel.clear()

        resolved_backend = detect_backend(backend)
        job = CrackJob(
            bssid=bssid.lower(),
            essid=essid,
            hash_path=hash_path,
            mode=mode,
            backend=resolved_backend,
            wordlist=wordlist,
            mask=mask,
            rules=rules,
        )

        bus.publish(
            CrackStarted(
                timestamp=time.time(),
                bssid=job.bssid,
                essid=essid,
                backend=resolved_backend,
                mode=mode,
                keyspace=job.keyspace(),
                eta_seconds=job.estimated_eta(),
            )
        )

        started = time.time()

        def on_progress(tried: int, total: int | None, rate: float | None) -> None:
            eta = (total - tried) / rate if (total and rate and rate > 0) else None
            bus.publish(
                CrackProgress(
                    timestamp=time.time(),
                    bssid=job.bssid,
                    tried=tried,
                    total=total,
                    rate=rate or 0.0,
                    eta_seconds=eta,
                )
            )

        try:
            if resolved_backend == "hashcat":
                password = self._run_hashcat(job, on_progress)
            else:
                password = self._run_aircrack(job, on_progress)
        except CrackError as exc:
            raise click.ClickException(str(exc)) from exc

        if password is not None:
            self._write_cracked(job, password)

        bus.publish(
            CrackComplete(
                timestamp=time.time(),
                bssid=job.bssid,
                essid=essid,
                password=password,
                elapsed_seconds=time.time() - started,
            )
        )
        return 0 if password is not None else 1

    def cancel(self) -> None:
        self._cancel.set()

    # ---- output ------------------------------------------------------------
    def _write_cracked(self, job: CrackJob, password: str) -> None:
        path = cracked_path(job.essid, job.bssid)
        path.write_text(
            f"essid={job.essid or '<hidden>'}\nbssid={job.bssid}\npassword={password}\n",
            encoding="utf-8",
        )

    # ---- backend runners (subprocess; lightly covered) ---------------------
    def _run_hashcat(  # pragma: no cover - exercised via integration/manual
        self,
        job: CrackJob,
        on_progress: Callable[[int, int | None, float | None], None],
    ) -> str | None:
        argv = hashcat.build_argv(job)
        proc = subprocess.Popen(
            argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
        self._pump(proc, on_progress, hashcat.parse_progress)
        # hashcat exits 0 on a crack, 1 on exhaustion. Read the key back with
        # --show regardless, since the potfile holds it after a successful run.
        show = subprocess.run(
            hashcat.build_show_argv(job.hash_path),
            capture_output=True,
            text=True,
            check=False,
        )
        return hashcat.parse_show_output(show.stdout)

    def _run_aircrack(  # pragma: no cover - exercised via integration/manual
        self,
        job: CrackJob,
        on_progress: Callable[[int, int | None, float | None], None],
    ) -> str | None:
        if job.mode == "mask":
            producer_argv, consumer_argv = aircrack.build_stream_cmd(job)
            producer = subprocess.Popen(producer_argv, stdout=subprocess.PIPE)
            proc = subprocess.Popen(
                consumer_argv,
                stdin=producer.stdout,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
        else:
            proc = subprocess.Popen(
                aircrack.build_argv(job),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
        captured: list[str] = []

        def adapt(text: str) -> tuple[int, int | None, float | None]:
            captured.append(text)
            tried, rate = aircrack.parse_progress(text)
            return tried, None, rate

        self._pump(proc, on_progress, adapt)
        return aircrack.parse_key_found("".join(captured))

    def _pump(  # pragma: no cover - subprocess I/O loop
        self,
        proc: subprocess.Popen[str],
        on_progress: Callable[[int, int | None, float | None], None],
        parse: Callable[[str], tuple[int, int | None, float | None]],
    ) -> None:
        """Read backend stdout, emit throttled progress, honour cancellation."""
        buffer: list[str] = []
        last_emit = 0.0
        assert proc.stdout is not None
        for line in proc.stdout:
            if self._cancel.is_set():
                proc.terminate()
                break
            buffer.append(line)
            now = time.time()
            if now - last_emit >= _PROGRESS_INTERVAL:
                tried, total, rate = parse("".join(buffer))
                on_progress(tried, total, rate)
                last_emit = now
        proc.wait()

    def run(self, ctx: PluginContext) -> int:  # pragma: no cover — CLI uses execute()
        raise NotImplementedError("call CrackPlugin.execute(...) directly")
