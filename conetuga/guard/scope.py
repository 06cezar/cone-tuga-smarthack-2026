"""The scope guardrail (FR-02): decides whether a live scan may touch a target, before nmap ever starts.

The brief's rule: refuse any range outside an explicit allowlist (by default the subnet we are connected to), refuse
public IP ranges, and require a confirmation flag. Scanning outside our own hotspot is a criminal offence (Criminal
Code, Art. 360) and gets the team disqualified, so every doubt ends in a refusal.

`check_scope` only decides: it reads no network, looks up no name and starts nothing, so every rule has a test."""
import ipaddress
from dataclasses import dataclass

# Our lab hotspot's name (organizer update, Nov 7: `RSH-<team_name>`). On any other Wi-Fi, such as the venue's, the
# "connected subnet" belongs to someone else, so a live scan is refused whatever the target.
HOTSPOT_SSID = "RSH-ConeTuga"

# The mobile carrier's shared address space (RFC 6598). Python's `ipaddress` calls it neither private nor global,
# so the public-IP check alone would let it through; the rules of engagement forbid the operator's network.
CARRIER_SHARED_RANGE = ipaddress.ip_network("100.64.0.0/10")

# IPv4 addresses written as IPv6: "::ffff:8.8.8.8" reaches 8.8.8.8. Python calls this block reserved but each address
# in it public or not by its IPv4 self, so the public check can't see inside it: such targets are refused as written.
IPV4_MAPPED_RANGE = ipaddress.ip_network("::ffff:0:0/96")

Target = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class ScopeDecision:
    """The guardrail's answer. `reason` is one Romanian sentence, a newline, then the same sentence in English."""

    allowed: bool
    reason: str


def check_scope(target: str, allowlist: list[str], confirmed: bool, ssid: str) -> ScopeDecision:
    """May a live scan touch `target`? The checks run in this order, and the first one that fails gives the reason:
    written as numbers, holds no public address, not the carrier's range, not IPv4 written as IPv6, not multicast, on
    our hotspot, inside the allowlist, `--confirm` given. Reserved addresses (0.0.0.0, 240.0.0.0/4...) aren't public:
    the allowlist refuses them.

    `allowlist` holds IP ranges such as "172.20.10.0/28" (the default is the connected subnet, see network.py); an
    entry that isn't a range can't allow anything. `ssid` is the Wi-Fi network of the interface we would scan
    through, "" when it isn't on Wi-Fi."""
    network = _parse_target(target)
    if network is None:
        return _refuse(
            f"{target!r} nu este o adresă IP sau un interval scris cu cifre (de ex. 172.20.10.0/28); "
            "nu căutăm nume de domeniu.",
            f"{target!r} is not an IP address or a range written as numbers (e.g. 172.20.10.0/28); "
            "domain names are never looked up.",
        )
    shown = _display(network)
    if _contains_public(network):
        if network.num_addresses == 1:
            return _refuse(
                f"{shown} este o adresă publică de pe internet: scanăm doar rețeaua noastră de laborator.",
                f"{shown} is a public internet address: we only scan our own lab network.",
            )
        return _refuse(
            f"{shown} conține adrese publice de pe internet: scanăm doar rețeaua noastră de laborator.",
            f"{shown} contains public internet addresses: we only scan our own lab network.",
        )
    # A range that overlaps the carrier's and passed the check above lies inside it: any larger range holds public
    # addresses, such as 100.0.0.0/10 next to it.
    if network.version == CARRIER_SHARED_RANGE.version and network.overlaps(CARRIER_SHARED_RANGE):
        return _refuse(
            f"{shown} aparține rețelei operatorului mobil ({CARRIER_SHARED_RANGE}), nu nouă.",
            f"{shown} belongs to the mobile carrier's network ({CARRIER_SHARED_RANGE}), not to us.",
        )
    if network.version == IPV4_MAPPED_RANGE.version and network.overlaps(IPV4_MAPPED_RANGE):
        return _refuse(
            f"{shown} este o adresă IPv4 scrisă în formă IPv6: scrie-o ca IPv4 (de ex. 172.20.10.5).",
            f"{shown} is an IPv4 address written as IPv6: write it as IPv4 (e.g. 172.20.10.5).",
        )
    # A multicast address reaches every device that listens, not one of ours, whatever the allowlist says. A range
    # that holds some and passed the checks above starts or ends inside the multicast block, so its ends tell.
    if network.network_address.is_multicast or network.broadcast_address.is_multicast:
        if network.num_addresses == 1:
            return _refuse(
                f"{shown} este o adresă de grup (multicast), nu un dispozitiv: scanăm doar dispozitivele noastre.",
                f"{shown} is a group (multicast) address, not a device: we only scan our own devices.",
            )
        return _refuse(
            f"{shown} conține adrese de grup (multicast), nu dispozitive: scanăm doar dispozitivele noastre.",
            f"{shown} contains group (multicast) addresses, not devices: we only scan our own devices.",
        )
    if ssid != HOTSPOT_SSID:
        current = repr(ssid) if ssid else "niciuna"
        current_en = repr(ssid) if ssid else "none"
        return _refuse(
            f"Laptopul nu este conectat la hotspotul nostru {HOTSPOT_SSID!r} (rețeaua Wi-Fi de acum: {current}), "
            "deci nu scanăm nimic.",
            f"The laptop is not on our hotspot {HOTSPOT_SSID!r} (current Wi-Fi network: {current_en}), "
            "so nothing is scanned.",
        )
    allowed_networks = [allowed for entry in allowlist if (allowed := _parse_target(entry)) is not None]
    if not any(network.version == allowed.version and network.subnet_of(allowed) for allowed in allowed_networks):
        fence = ", ".join(str(allowed) for allowed in allowed_networks)
        return _refuse(
            f"{shown} este în afara rețelei permise ({fence or 'nimic'}): scanăm doar subrețeaua hotspotului.",
            f"{shown} is outside the allowed network ({fence or 'nothing'}): we only scan the hotspot's subnet.",
        )
    if not confirmed:
        return _refuse(
            "Scanarea live are nevoie de --confirm: rulează din nou comanda cu --confirm dacă ești sigur.",
            "A live scan needs --confirm: run the command again with --confirm if you are sure.",
        )
    return ScopeDecision(
        allowed=True,
        reason=f"{shown} este în rețeaua noastră de laborator: scanarea poate porni.\n"
        f"{shown} is inside our lab network: the scan may start.",
    )


def _parse_target(text: str) -> Target | None:
    """An address or a CIDR range written as numbers, or None. Host bits are allowed ("172.20.10.5/28" means the
    /28, as in nmap). Names are refused without a DNS lookup, so a name can never lead the scan somewhere else."""
    try:
        return ipaddress.ip_network(text.strip(), strict=False)
    except ValueError:
        return None


def _display(network: Target) -> str:
    """How the target is shown to a person: "8.8.8.8" for one address, "172.20.10.0/28" for a range."""
    if network.prefixlen == network.max_prefixlen:
        return str(network.network_address)
    return str(network)


def _contains_public(network: Target) -> bool:
    """True when at least one address of the range is a public internet address, so 0.0.0.0/0 is refused as public
    even though its first and last addresses are reserved. Python's `ipaddress` tells whether a whole range lies
    inside one non-public block (private, loopback, link-local, reserved...); multicast addresses and the carrier's
    range aren't internet hosts either. A range inside none of them is split in two halves until each part is, or is
    one address: at most 32 levels for IPv4 and 128 for IPv6, and only along the edges of those blocks.

    The allowlist alone would refuse such ranges too; this check gives the reason the jury expects, and still holds
    if the allowlist were ever wrong."""
    inside_carrier = network.version == CARRIER_SHARED_RANGE.version and network.subnet_of(CARRIER_SHARED_RANGE)
    if network.is_private or network.is_multicast or inside_carrier:
        return False
    if network.num_addresses == 1:
        return True
    return any(_contains_public(half) for half in network.subnets(prefixlen_diff=1))


def _refuse(romanian: str, english: str) -> ScopeDecision:
    return ScopeDecision(allowed=False, reason=f"{romanian}\n{english}")
