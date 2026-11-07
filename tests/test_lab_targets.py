"""The fake lab services send exactly what nmap needs to recognise them, and nothing more (no login, no data).

They run here on 127.0.0.1 with a free port, so nothing leaves this computer."""
import importlib.util
import socket
from contextlib import contextmanager
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "lab" / "targets" / "fake_services.py"
_spec = importlib.util.spec_from_file_location("fake_services", SCRIPT)
fake_services = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fake_services)

LOOPBACK = "127.0.0.1"
CLIENT_TIMEOUT_SECONDS = 5


@contextmanager
def connected_to(name: str):
    server = fake_services.start(name, host=LOOPBACK, port=0)
    try:
        with socket.create_connection(server.server_address, timeout=CLIENT_TIMEOUT_SECONDS) as client:
            yield client
    finally:
        fake_services.stop([server])


def read_line(client: socket.socket) -> bytes:
    line = b""
    while not line.endswith(b"\r\n"):
        chunk = client.recv(1)
        if not chunk:
            break
        line += chunk
    return line


def read_until_closed(client: socket.socket) -> bytes:
    data = b""
    while chunk := client.recv(fake_services.READ_CHUNK):
        data += chunk
    return data


def test_fake_ftp_greets_as_vsftpd_2_3_4():
    with connected_to("ftp") as client:
        assert read_line(client) == b"220 (vsFTPd 2.3.4)\r\n"


def test_fake_ftp_refuses_every_login_and_says_goodbye_on_quit():
    with connected_to("ftp") as client:
        read_line(client)
        for command in (b"USER anonymous\r\n", b"PASS secret\r\n"):
            client.sendall(command)
            assert read_line(client) == fake_services.FTP_REFUSED
        client.sendall(b"QUIT\r\n")
        assert read_line(client) == fake_services.FTP_GOODBYE


def test_fake_telnet_sends_only_the_busybox_greeting():
    with connected_to("telnet") as client:
        client.shutdown(socket.SHUT_WR)
        assert read_until_closed(client) == b"\xff\xfd\x01\xff\xfd\x1f\xff\xfb\x01\xff\xfb\x03"


def test_fake_printer_accepts_a_job_and_answers_nothing():
    with connected_to("printer") as client:
        client.sendall(b"%!PS-Adobe-3.0 print this\n")
        client.shutdown(socket.SHUT_WR)
        assert read_until_closed(client) == b""


def test_every_fake_service_names_the_finding_it_should_give():
    assert {name: s.expected_findings for name, s in fake_services.SERVICES.items()} == {
        "telnet": "TELNET_OPEN",
        "ftp": "FTP_CLEARTEXT + OUTDATED_SERVICE",
        "printer": "PRINTER_RAW_EXPOSED",
    }
