"""CLI entry point.

Top-level group ``cyberm4fia``. Plugins register their own subcommands via
``REGISTRY[*].register_cli(main)``. The root callback wires the authorization
gate (``ensure_acknowledged``) and exposes global flags through the Click
context so plugins can read them.

``build_runtime_for(ctx)`` is the bridge between the CLI and the plugin
context: it owns adapter detection and picks the right one based on the
``--iface`` flag, then returns a small dataclass with the live engine wires.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

import click

from cyberm4fia_wifi.core.adapter import DetectedAdapter, detect_adapters
from cyberm4fia_wifi.core.auth import AuthorizationGate, AuthzError, Mode
from cyberm4fia_wifi.core.events import EventBus
from cyberm4fia_wifi.core.session import Session


@dataclass
class Runtime:
    session: Session
    bus: EventBus
    adapter: DetectedAdapter
    gate: AuthorizationGate


def _ctx_obj(ctx: click.Context) -> dict[str, object]:
    if ctx.obj is None:
        ctx.obj = {}
    return ctx.obj


@click.group(
    name="cyberm4fia",
    help=(
        "cyberm4fia-wifi: 802.11 audit suite. Use only against networks you "
        "own or have explicit, written permission to audit."
    ),
)
@click.option("--iface", default=None, help="Wireless interface to use (e.g. wlan0).")
@click.option(
    "--mode",
    type=click.Choice([m.value for m in Mode], case_sensitive=False),
    default=None,
    help="Override the persisted mode for this invocation.",
)
@click.option("--verbose", "-v", is_flag=True, help="Verbose logging.")
@click.pass_context
def main(ctx: click.Context, iface: str | None, mode: str | None, verbose: bool) -> None:
    obj = _ctx_obj(ctx)
    obj["iface"] = iface
    obj["mode"] = mode
    obj["verbose"] = verbose

    gate = AuthorizationGate.from_xdg()
    try:
        gate.ensure_acknowledged(stdin=sys.stdin, stdout=sys.stdout)
    except AuthzError as exc:
        raise click.ClickException(str(exc)) from exc
    obj["gate"] = gate


@main.command(name="adapters", help="List detected wireless adapters and exit.")
def adapters_cmd() -> None:
    found = detect_adapters()
    if not found:
        click.echo("no wireless adapters detected.")
        return
    for a in found:
        flags = []
        if a.profile.injection:
            flags.append("inject")
        if a.profile.injection_unverified:
            flags.append("inject?")
        flags_str = ",".join(flags) or "-"
        bands = "+".join(a.profile.bands)
        click.echo(
            f"{a.iface:8s}  {a.profile.name:12s}  driver={a.profile.driver:10s}  "
            f"bands={bands:5s}  flags={flags_str}"
        )


def build_runtime_for(ctx: click.Context) -> Runtime:
    """Construct the shared per-invocation runtime for a plugin.

    Detection happens here, after the auth gate has acknowledged. If more
    than one adapter is detected and the operator didn't pin ``--iface``,
    an interactive picker prompts them — entering monitor mode is a real
    side effect (radio flips away from normal use), so we want explicit
    consent on which device gets touched.
    """
    obj = _ctx_obj(ctx)
    gate = obj.get("gate")
    if gate is None:
        raise click.ClickException("authorization gate not initialised")

    preferred = obj.get("iface")
    adapters = detect_adapters()
    from cyberm4fia_wifi.plugins.scan import interactive_pick_adapter  # avoid cycle

    adapter = interactive_pick_adapter(
        adapters,
        preferred_iface=preferred if isinstance(preferred, str) else None,
    )
    return Runtime(
        session=Session(),
        bus=EventBus(),
        adapter=adapter,
        gate=gate,  # type: ignore[arg-type]
    )


# Register every plugin's subcommand(s).
def _wire_plugins() -> None:
    from cyberm4fia_wifi.plugins import REGISTRY

    for plugin in REGISTRY:
        plugin.register_cli(main)


_wire_plugins()


if __name__ == "__main__":  # pragma: no cover
    main()
