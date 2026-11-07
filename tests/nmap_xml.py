"""Build small nmap XML files for tests, in the same shape as `nmap -sS -sU -sV --script http-title -oX`.

Each test states only what matters to it (one host, one port); everything else gets a plain default, so a test
never depends on the Validation Set's particular devices."""
from pathlib import Path
from xml.sax.saxutils import escape, quoteattr

NMAP_HEADER = (
    '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE nmaprun>\n'
    '<nmaprun scanner="nmap" args="nmap -sS -sU -sV --script http-title -oX test.xml 10.0.0.0/24" version="7.94">\n'
)
NMAP_FOOTER = '<runstats><finished summary="Nmap done" exit="success"/></runstats>\n</nmaprun>\n'


def port(number: int, service: str = "", *, proto: str = "tcp", state: str = "open", product: str = "",
         version: str = "", tunnel: str = "", title: str | None = None, title_output: str | None = None) -> str:
    """One <port>. `title` adds an http-title script with <elem key="title">; `title_output` sets only its output
    text (what nmap writes when there is no title, e.g. on a redirect)."""
    attributes = {"name": service, "product": product, "version": version, "tunnel": tunnel}
    service_xml = "<service " + " ".join(f"{k}={quoteattr(v)}" for k, v in attributes.items() if v) + "/>"
    script = ""
    if title is not None:
        script = f'<script id="http-title" output={quoteattr(title)}><elem key="title">{escape(title)}</elem></script>'
    elif title_output is not None:
        script = f'<script id="http-title" output={quoteattr(title_output)}></script>'
    return (f'<port protocol="{proto}" portid="{number}"><state state="{state}"/>'
            f'{service_xml if service else ""}{script}</port>')


def host(ip: str, *ports: str, mac: str | None = "AA:BB:CC:11:22:33", vendor: str = "Acme",
         hostname: str = "device", state: str = "up") -> str:
    """One <host>. mac=None leaves out the MAC address; vendor="" or hostname="" leave out that part."""
    mac_xml = ""
    if mac is not None:
        vendor_attr = f" vendor={quoteattr(vendor)}" if vendor else ""
        mac_xml = f'<address addr="{mac}" addrtype="mac"{vendor_attr}/>'
    names = f'<hostname name={quoteattr(hostname)} type="PTR"/>' if hostname else ""
    return (f'<host><status state="{state}"/><address addr="{ip}" addrtype="ipv4"/>{mac_xml}'
            f'<hostnames>{names}</hostnames><ports>{"".join(ports)}</ports></host>\n')


def write_scan(folder: Path, *hosts: str, name: str = "scan.xml") -> Path:
    """A complete nmap XML file with these hosts, written into `folder`."""
    path = folder / name
    path.write_text(NMAP_HEADER + "".join(hosts) + NMAP_FOOTER, encoding="utf-8")
    return path
