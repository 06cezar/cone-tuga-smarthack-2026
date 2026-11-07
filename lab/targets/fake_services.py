"""Fake lab services for setup C of the brief (page 6): each one only answers with a banner.

They give nmap something to recognise (a telnet server, an old vsftpd, a printer port) with no real login, shell or
data behind them, so they stay safe even if someone else connects ("simulate, do not expose"). Run them on the targets
laptop only while it is on our hotspot RSH-ConeTuga, and stop them with Ctrl+C.

Usage: python lab/targets/fake_services.py [telnet] [ftp] [printer]   (no names: all three)
"""
import argparse
import socketserver
import sys
import threading
import time
from dataclasses import dataclass

LISTEN_ON = "0.0.0.0"  # every interface of the targets laptop, so the scanner on the hotspot can reach the services
READ_CHUNK = 4096  # bytes per read; whatever a client sends is thrown away, never stored
MAX_READS = 64  # a client gets at most this many reads before we hang up
IDLE_TIMEOUT_SECONDS = 20  # a silent client is disconnected
WAIT_TICK_SECONDS = 1  # the main thread sleeps in short ticks so that Ctrl+C also works on Windows

# BusyBox telnetd opens every connection with these option requests (DO ECHO, DO NAWS, WILL ECHO, WILL SGA), and nmap's
# version detection recognises a telnet server from them. No login prompt follows: there is nothing to log in to.
TELNET_GREETING = b"\xff\xfd\x01\xff\xfd\x1f\xff\xfb\x01\xff\xfb\x03"
# nmap reads product "vsftpd" and version "2.3.4" from this greeting: a version on the catalog's outdated list.
FTP_BANNER = b"220 (vsFTPd 2.3.4)\r\n"
FTP_REFUSED = b"530 Login incorrect.\r\n"  # the answer to every command: nobody ever logs in
FTP_GOODBYE = b"221 Goodbye.\r\n"
FTP_QUIT = b"QUIT"


class TelnetHandler(socketserver.BaseRequestHandler):
    """Sends the telnet greeting, then ignores the client until it leaves."""

    def handle(self) -> None:
        self.request.settimeout(IDLE_TIMEOUT_SECONDS)
        try:
            self.request.sendall(TELNET_GREETING)
        except OSError:
            return
        _discard_input(self.request)


class FtpHandler(socketserver.StreamRequestHandler):
    """Greets like vsftpd 2.3.4 and refuses every command; QUIT ends the session."""

    timeout = IDLE_TIMEOUT_SECONDS

    def handle(self) -> None:
        try:
            self.wfile.write(FTP_BANNER)
            for _ in range(MAX_READS):
                line = self.rfile.readline(READ_CHUNK)
                if not line:
                    return
                if line.strip().upper().startswith(FTP_QUIT):
                    self.wfile.write(FTP_GOODBYE)
                    return
                self.wfile.write(FTP_REFUSED)
        except OSError:  # a timeout or a client that hung up
            return


class PrinterHandler(socketserver.BaseRequestHandler):
    """A raw printer port: accepts whatever is sent and throws it away, printing nothing and answering nothing."""

    def handle(self) -> None:
        self.request.settimeout(IDLE_TIMEOUT_SECONDS)
        _discard_input(self.request)


def _discard_input(connection) -> None:
    """Read and drop what the client sends, until it hangs up, goes quiet, or reaches MAX_READS."""
    for _ in range(MAX_READS):
        try:
            if not connection.recv(READ_CHUNK):
                return
        except OSError:  # a timeout or a client that hung up
            return


@dataclass(frozen=True)
class FakeService:
    port: int
    handler: type[socketserver.BaseRequestHandler]
    expected_findings: str  # what the analyser should report for it, printed so the person running it knows


SERVICES = {
    "telnet": FakeService(2323, TelnetHandler, "TELNET_OPEN"),
    "ftp": FakeService(21, FtpHandler, "FTP_CLEARTEXT + OUTDATED_SERVICE"),
    "printer": FakeService(9100, PrinterHandler, "PRINTER_RAW_EXPOSED"),
}


class LabServer(socketserver.ThreadingTCPServer):
    daemon_threads = True  # Ctrl+C ends the script even while a client is still connected


def start(name: str, host: str = LISTEN_ON, port: int | None = None) -> LabServer:
    """Start one fake service in a background thread and return its server. Port 0 picks a free port (for tests)."""
    service = SERVICES[name]
    server = LabServer((host, service.port if port is None else port), service.handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def stop(servers: list[LabServer]) -> None:
    for server in servers:
        server.shutdown()
        server.server_close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fake telnet, FTP and printer services for the ConeTuga lab.")
    parser.add_argument("services", nargs="*", metavar="SERVICE", help=f"any of {', '.join(SERVICES)} (default: all)")
    names = parser.parse_args(argv).services or list(SERVICES)
    unknown = sorted(set(names) - set(SERVICES))
    if unknown:
        parser.error(f"unknown service(s): {', '.join(unknown)}; choose from {', '.join(SERVICES)}")

    servers: list[LabServer] = []
    for name in names:
        service = SERVICES[name]
        try:
            servers.append(start(name))
        except OSError as exc:
            print(f"{name}: can't open port {service.port} ({exc}). Is another program using it?", file=sys.stderr)
            stop(servers)
            return 1
        print(f"{name}: listening on port {service.port}, expected finding: {service.expected_findings}")
    print("Stop with Ctrl+C.")
    try:
        while True:
            time.sleep(WAIT_TICK_SECONDS)
    except KeyboardInterrupt:
        print("Stopping.")
    finally:
        stop(servers)
    return 0


if __name__ == "__main__":
    sys.exit(main())
