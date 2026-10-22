#!/usr/bin/env python3
"""Exercise both real binaries over local DNS transports, without external DNS."""

import base64
import ipaddress
import os
from pathlib import Path
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
BIN = Path(os.environ.get("NAMESERVER_BIN_DIR", ROOT / "target" / "debug")).resolve()


def query(name, kind=1, dnssec=False, checking_disabled=False):
    labels = b"".join(bytes([len(part)]) + part.encode("ascii") for part in name.rstrip(".").split(".")) + b"\0"
    packet = struct.pack("!6H", 0x1234, 0x0100 | (0x0010 if checking_disabled else 0), 1, 0, 0, int(dnssec)) + labels + struct.pack("!HH", kind, 1)
    if dnssec:
        packet += b"\0" + struct.pack("!HHIH", 41, 1232, 0x8000, 0)
    return packet


def skip_name(packet, offset):
    for _ in range(128):
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1
        if length == 0:
            return offset
        if length > 63:
            raise ValueError("invalid DNS label")
        offset += length
    raise ValueError("DNS name is too long")


def decode(packet):
    ident, flags, qd, an, ns, ar = struct.unpack_from("!6H", packet)
    if ident != 0x1234 or not flags & 0x8000:
        raise ValueError("unexpected DNS response")
    offset = 12
    for _ in range(qd):
        offset = skip_name(packet, offset) + 4
    sections = []
    for count in (an, ns, ar):
        records = []
        for _ in range(count):
            offset = skip_name(packet, offset)
            kind, dnsclass, ttl, size = struct.unpack_from("!HHIH", packet, offset)
            offset += 10
            data = packet[offset:offset + size]
            if len(data) != size:
                raise ValueError("truncated DNS response")
            records.append({"type": kind, "class": dnsclass, "ttl": ttl, "data": data})
            offset += size
        sections.append(records)
    return {"flags": flags, "rcode": flags & 15, "answers": sections[0], "authority": sections[1], "additional": sections[2]}


def receive_exact(stream, length):
    result = bytearray()
    while len(result) < length:
        part = stream.recv(length - len(result))
        if not part:
            raise ConnectionError("DNS stream closed early")
        result.extend(part)
    return bytes(result)


def exchange(port, packet, transport="udp", context=None):
    if transport == "udp":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
            stream.settimeout(2)
            stream.sendto(packet, ("127.0.0.1", port))
            return decode(stream.recv(65535))
    with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
        stream = context.wrap_socket(raw, server_hostname="localhost") if context else raw
        with stream:
            stream.sendall(struct.pack("!H", len(packet)) + packet)
            size = struct.unpack("!H", receive_exact(stream, 2))[0]
            return decode(receive_exact(stream, size))


def free_port():
    with socket.socket() as stream:
        stream.bind(("127.0.0.1", 0))
        return stream.getsockname()[1]


class Integration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="nameserver-test-")
        cls.root = Path(cls.temp.name)
        cls.processes = []
        cls.logs = []
        cls.addClassCleanup(cls.cleanup)
        ports = set()
        while len(ports) < 4:
            ports.add(free_port())
        cls.authority_port, cls.resolver_port, cls.dot_port, cls.doh_port = sorted(ports)
        shutil.copy(ROOT / "examples/zones/example.test.zone", cls.root / "example.zone")
        (cls.root / "blocked.txt").write_text("blocked.example.test\n")
        (cls.root / "allowed.txt").write_text("safe.blocked.example.test\n")
        subprocess.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-pkeyopt", "ec_param_enc:named_curve", "-out", str(cls.root / "dnssec.pem")], check=True, capture_output=True)
        (cls.root / "certificate.cnf").write_text("[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=extensions\n[dn]\nCN=localhost\n[extensions]\nsubjectAltName=DNS:localhost\nbasicConstraints=critical,CA:TRUE\n")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-config", str(cls.root / "certificate.cnf"), "-keyout", str(cls.root / "tls-key.pem"), "-out", str(cls.root / "tls-cert.pem")], check=True, capture_output=True)
        cls.authority_config = cls.root / "authority.toml"
        cls.authority_config.write_text(f"""[server]
listen = ["127.0.0.1:{cls.authority_port}"]
allow_networks = ["127.0.0.0/8"]
[[zones]]
origin = "example.test"
file = "example.zone"
[zones.dnssec]
private_key = "dnssec.pem"
""")
        cls.authority = cls.launch("nameserver-authority", cls.authority_config, cls.authority_port)
        keys = exchange(cls.authority_port, query("example.test", 48, True))["answers"]
        key = next(record["data"] for record in keys if record["type"] == 48)
        flags, protocol, algorithm = struct.unpack_from("!HBB", key)
        anchor = f"example.test. 300 IN DNSKEY {flags} {protocol} {algorithm} {base64.b64encode(key[4:]).decode()}\n"
        (cls.root / "trusted.key").write_text(anchor)
        cls.resolver_config = cls.root / "resolver.toml"
        cls.resolver_config.write_text(f"""[server]
listen = ["127.0.0.1:{cls.resolver_port}"]
listen_dot = ["127.0.0.1:{cls.dot_port}"]
listen_doh = ["127.0.0.1:{cls.doh_port}"]
allow_networks = ["127.0.0.0/8"]
[server.tls]
certificate = "tls-cert.pem"
private_key = "tls-key.pem"
dns_name = "localhost"
[resolver]
mode = "forward"
upstreams = ["127.0.0.1:{cls.authority_port}"]
dnssec_validation = true
trust_anchor = "trusted.key"
[filters]
blocklists = ["blocked.txt"]
allowlists = ["allowed.txt"]
""")
        cls.resolver = cls.launch("nameserver-resolver", cls.resolver_config, cls.resolver_port)

    @classmethod
    def launch(cls, binary, config, port):
        log = tempfile.TemporaryFile(mode="w+b")
        cls.logs.append(log)
        process = subprocess.Popen([str(BIN / binary), "--config", str(config)], cwd=cls.root, stdout=log, stderr=log)
        cls.processes.append(process)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if process.poll() is not None:
                log.seek(0)
                raise RuntimeError(log.read().decode(errors="replace"))
            try:
                exchange(port, query("example.test", 6))
                return process
            except (OSError, ValueError):
                time.sleep(0.05)
        raise TimeoutError(f"{binary} did not start")

    @classmethod
    def cleanup(cls):
        for process in reversed(cls.processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=12)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        for log in cls.logs:
            log.close()
        cls.temp.cleanup()

    def test_authority_records_over_udp_and_tcp(self):
        for transport in ("udp", "tcp"):
            for name, kind in (("example.test", 1), ("example.test", 28), ("example.test", 2), ("example.test", 6), ("example.test", 15), ("example.test", 16), ("www.example.test", 5), ("anything.wild.example.test", 1)):
                with self.subTest(transport=transport, name=name, kind=kind):
                    response = exchange(self.authority_port, query(name, kind), transport)
                    self.assertEqual(response["rcode"], 0)
                    self.assertTrue(response["flags"] & 0x400)
                    self.assertFalse(response["flags"] & 0x80)
                    self.assertIn(kind, [record["type"] for record in response["answers"]])

    def test_authority_refuses_recursion_and_denies_transfers(self):
        self.assertEqual(exchange(self.authority_port, query("outside.invalid"))["rcode"], 5)
        self.assertNotEqual(exchange(self.authority_port, query("example.test", 252), "tcp")["rcode"], 0)

    def test_negative_and_nodata_answers(self):
        missing = exchange(self.authority_port, query("missing.example.test"))
        self.assertEqual(missing["rcode"], 3)
        self.assertIn(6, [record["type"] for record in missing["authority"]])
        nodata = exchange(self.authority_port, query("mail.example.test", 28))
        self.assertEqual(nodata["rcode"], 0)
        self.assertEqual(nodata["answers"], [])

    def test_filtering_and_allowlist_overrides(self):
        for name in ("blocked.example.test", "sub.blocked.example.test"):
            blocked = exchange(self.resolver_port, query(name, dnssec=True))
            self.assertEqual(blocked["rcode"], 3)
            self.assertFalse(blocked["flags"] & 0x20)
            self.assertIn(6, [record["type"] for record in blocked["authority"]])
        allowed = exchange(self.resolver_port, query("safe.blocked.example.test"))
        self.assertEqual(allowed["rcode"], 0)
        self.assertIn(ipaddress.ip_address("192.0.2.20").packed, [record["data"] for record in allowed["answers"] if record["type"] == 1])

    def test_dnssec_validation_and_authenticated_denial(self):
        for name in ("example.test", "missing.example.test"):
            response = exchange(self.resolver_port, query(name, dnssec=True))
            self.assertTrue(response["flags"] & 0x20, response)
        signed = exchange(self.authority_port, query("example.test", dnssec=True))
        self.assertIn(46, [record["type"] for record in signed["answers"]])

    def test_dnssec_rejects_stripped_signatures_and_honors_cd(self):
        # A local upstream strips signatures from A answers but serves the real signed DNSKEY.
        # A validator must not classify this signed namespace as merely unsigned.
        stop = threading.Event()
        upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        upstream.bind(("127.0.0.1", 0))
        upstream.settimeout(0.1)
        upstream_port = upstream.getsockname()[1]

        def proxy():
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as relay:
                relay.settimeout(1)
                while not stop.is_set():
                    try:
                        packet, peer = upstream.recvfrom(65535)
                    except socket.timeout:
                        continue
                    question_end = skip_name(packet, 12) + 4
                    kind = struct.unpack_from("!H", packet, question_end - 4)[0]
                    if kind == 1:
                        flags = 0x8400 | (struct.unpack_from("!H", packet, 2)[0] & 0x0110)
                        response = struct.pack("!6H", struct.unpack_from("!H", packet)[0], flags, 1, 1, 0, 0)
                        response += packet[12:question_end] + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + ipaddress.ip_address("192.0.2.10").packed
                    else:
                        relay.sendto(packet, ("127.0.0.1", self.authority_port))
                        response, _ = relay.recvfrom(65535)
                    upstream.sendto(response, peer)

        thread = threading.Thread(target=proxy, daemon=True)
        thread.start()
        try:
            port = free_port()
            config = self.root / "signature-stripping.toml"
            config.write_text(f"""[server]
listen = ["127.0.0.1:{port}"]
[resolver]
mode = "forward"
upstreams = ["127.0.0.1:{upstream_port}"]
dnssec_validation = true
trust_anchor = "trusted.key"
""")
            process = self.launch("nameserver-resolver", config, port)
            rejected = exchange(port, query("example.test", dnssec=True))
            self.assertEqual(rejected["rcode"], 2)
            unchecked = exchange(port, query("example.test", dnssec=True, checking_disabled=True))
            self.assertEqual(unchecked["rcode"], 0)
            self.assertFalse(unchecked["flags"] & 0x20)
            self.assertEqual(exchange(port, query("example.test", dnssec=True))["rcode"], 2)
            process.terminate()
            self.assertEqual(process.wait(timeout=12), 0)
        finally:
            stop.set()
            thread.join(timeout=2)
            upstream.close()

    def test_dns_over_tls(self):
        context = ssl.create_default_context(cafile=str(self.root / "tls-cert.pem"))
        context.set_alpn_protocols(["dot"])
        response = exchange(self.dot_port, query("example.test", dnssec=True), "tcp", context)
        self.assertEqual(response["rcode"], 0)
        self.assertTrue(response["flags"] & 0x20)

    def test_dns_over_https_get_and_post(self):
        packet = query("example.test", dnssec=True)
        packet_path = self.root / "query.bin"
        packet_path.write_bytes(packet)
        common = ["curl", "--silent", "--show-error", "--fail", "--max-time", "5", "--noproxy", "*", "--http2", "--cacert", str(self.root / "tls-cert.pem"), "--resolve", f"localhost:{self.doh_port}:127.0.0.1"]
        url = f"https://localhost:{self.doh_port}/dns-query"
        encoded = base64.urlsafe_b64encode(packet).decode().rstrip("=")
        for request in ([f"{url}?dns={encoded}"], ["-H", "Content-Type: application/dns-message", "--data-binary", f"@{packet_path}", url]):
            result = subprocess.run(common + request, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
            response = decode(result.stdout)
            self.assertEqual(response["rcode"], 0)
            self.assertTrue(response["flags"] & 0x20)

    def test_client_access_control(self):
        port = free_port()
        config = self.root / "denied.toml"
        config.write_text(self.resolver_config.read_text().replace(f'127.0.0.1:{self.resolver_port}', f'127.0.0.1:{port}').replace(f'listen_dot = ["127.0.0.1:{self.dot_port}"]', 'listen_dot = []').replace(f'listen_doh = ["127.0.0.1:{self.doh_port}"]', 'listen_doh = []').replace('["127.0.0.0/8"]', '["192.0.2.0/24"]'))
        process = self.launch("nameserver-resolver", config, port)
        for transport in ("udp", "tcp"):
            self.assertEqual(exchange(port, query("example.test"), transport)["rcode"], 5)
        process.terminate()
        self.assertEqual(process.wait(timeout=12), 0)

    @unittest.skipUnless(hasattr(signal, "SIGHUP"), "SIGHUP is a Unix feature")
    def test_reload_preserves_live_data_when_replacement_is_invalid(self):
        original = (self.root / "blocked.txt").read_text()
        (self.root / "blocked.txt").write_text(original + "mail.example.test\n")
        self.resolver.send_signal(signal.SIGHUP)
        deadline = time.monotonic() + 3
        while exchange(self.resolver_port, query("mail.example.test"))["rcode"] != 3:
            if time.monotonic() > deadline:
                self.fail("blocklist reload was not applied")
            time.sleep(0.05)
        (self.root / "blocked.txt").write_text("||unsupported.example^\n")
        self.resolver.send_signal(signal.SIGHUP)
        time.sleep(0.15)
        self.assertEqual(exchange(self.resolver_port, query("mail.example.test"))["rcode"], 3)
        (self.root / "blocked.txt").write_text(original)
        self.resolver.send_signal(signal.SIGHUP)


if __name__ == "__main__":
    unittest.main(verbosity=2)
