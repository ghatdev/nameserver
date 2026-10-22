#!/usr/bin/env python3
"""Exercise CLI → API → NATS → DNS and flow ingestion into PostgreSQL/ClickHouse.

Requires an isolated, migrated PostgreSQL 18 database, ClickHouse, and JetStream.
Connection URLs can be overridden through the NAMESERVER_TEST_* environment.
"""
import base64
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.request

from integration import ROOT, BIN, decode, exchange, free_port, query, receive_exact


class Management(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="nameserver-management-")
        cls.root = Path(cls.temp.name)
        cls.processes, cls.logs = [], []
        cls.addClassCleanup(cls.cleanup)
        cls.api_port, cls.authority_port, cls.resolver_port, cls.doh_port, cls.dot_port = [free_port() for _ in range(5)]
        cls.url = f"http://127.0.0.1:{cls.api_port}"
        nats = os.environ.get("NAMESERVER_TEST_NATS", "nats://127.0.0.1:24222")
        pg = os.environ.get("NAMESERVER_TEST_POSTGRES", "postgres://nameserver@127.0.0.1:25432/nameserver?sslmode=disable")
        ch = os.environ.get("NAMESERVER_TEST_CLICKHOUSE", "http://127.0.0.1:28123")
        control = cls.root / "control.toml"
        control.write_text(f'''postgres_url = "{pg}"
auto_pull = false
auto_rdap = false
[api]
listen = "127.0.0.1:{cls.api_port}"
[nats]
url = "{nats}"
[clickhouse]
url = "{ch}"
database = "nameserver"
''')
        authority = cls.root / "authority.toml"
        authority.write_text(f'''[server]
listen = ["127.0.0.1:{cls.authority_port}"]
[management.nats]
url = "{nats}"
''')
        cls.launch("nameserver-control", control, cls.api_port)
        cls.launch("nameserver-authority", authority, cls.authority_port)
        cls.wait(lambda: isinstance(cls.api("GET", "/api/zones").get("zones"), list))
        if not cls.api("GET", "/api/dnssec/status").get("ksk_present"):
            cls.cli("zone", "dnssec", "keygen")
        cls.zone = cls.root / "zone.toml"
        cls.zone.write_text('''origin = "example.test"
nameservers = ["ns1.example.test."]
[soa]
minimum = 1
[[records]]
name = "ns1"
type = "A"
value = "192.0.2.53"
ttl = 1
[[records]]
name = "www"
type = "A"
value = "192.0.2.80"
ttl = 1
[[records]]
name = "safe"
type = "A"
value = "192.0.2.81"
ttl = 1
[[records]]
name = "*.wild"
type = "A"
value = "192.0.2.82"
ttl = 1
[dnssec]
enabled = true
''')
        cls.cli("zone", "apply", str(cls.zone), "--yes")
        cls.wait(lambda: any(r["type"] == 1 for r in exchange(cls.authority_port, query("www.example.test"))["answers"]))
        keys = exchange(cls.authority_port, query("example.test", 48, True))["answers"]
        anchors, published_flags = [], []
        for record in keys:
            if record["type"] == 48:
                flags, protocol, algorithm = struct.unpack_from("!HBB", record["data"])
                published_flags.append(flags)
                anchors.append(f"example.test. 300 IN DNSKEY {flags} {protocol} {algorithm} {base64.b64encode(record['data'][4:]).decode()}\n")
        if set(published_flags) != {256, 257}:
            raise AssertionError(f"incorrect managed KSK/ZSK flags: {published_flags}")
        if not anchors:
            raise AssertionError("managed authority did not publish signing keys")
        (cls.root / "trusted.key").write_text("".join(anchors))
        cls.profile = cls.api("POST", "/api/profiles", {"display_name": "Management integration"})["id"]
        cls.cli("profile", "block", cls.profile, "www.example.test")
        cls.cli("profile", "apply", "--yes")
        (cls.root / "certificate.cnf").write_text(f"[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=extensions\n[dn]\nCN=localhost\n[extensions]\nsubjectAltName=DNS:localhost,DNS:{cls.profile}.localhost\nbasicConstraints=critical,CA:TRUE\n")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-config", str(cls.root / "certificate.cnf"), "-keyout", str(cls.root / "key.pem"), "-out", str(cls.root / "cert.pem")], check=True, capture_output=True)
        cls.context = ssl.create_default_context(cafile=str(cls.root / "cert.pem"))
        resolver = cls.root / "resolver.toml"
        resolver.write_text(f'''[server]
listen = ["127.0.0.1:{cls.resolver_port}"]
listen_doh = ["127.0.0.1:{cls.doh_port}"]
listen_dot = ["127.0.0.1:{cls.dot_port}"]
[server.tls]
certificate = "cert.pem"
private_key = "key.pem"
dns_name = "localhost"
[resolver]
mode = "forward"
upstreams = ["127.0.0.1:{cls.authority_port}"]
trust_anchor = "trusted.key"
[management]
default_profile = "{cls.profile}"
[management.nats]
url = "{nats}"
''')
        cls.launch("nameserver-resolver", resolver, cls.resolver_port)
        # Durable consumers may retry after starting before the resolver provisions its stream.
        time.sleep(5)

    @classmethod
    def cleanup(cls):
        for process in reversed(cls.processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(timeout=5)
        for log in cls.logs:
            log.close()
        cls.temp.cleanup()

    @classmethod
    def launch(cls, binary, config, port):
        log = (cls.root / f"{binary}.log").open("w+")
        process = subprocess.Popen([str(BIN / binary), "--config", str(config)], stdout=log, stderr=subprocess.STDOUT)
        cls.processes.append(process); cls.logs.append(log)
        for _ in range(100):
            if process.poll() is not None:
                log.seek(0); raise RuntimeError(log.read())
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=.1):
                    return process
            except OSError:
                time.sleep(.1)
        log.seek(0); raise TimeoutError(log.read())

    @classmethod
    def api(cls, method, path, body=None):
        request = urllib.request.Request(cls.url + path, None if body is None else json.dumps(body).encode(), {"Content-Type": "application/json"}, method=method)
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            logs = "\n".join(p.read_text()[-3000:] for p in cls.root.glob("*.log"))
            raise RuntimeError(error.read().decode() + "\n" + logs) from error

    @classmethod
    def cli(cls, *args):
        result = subprocess.run([str(BIN / "nameserver"), "--url", cls.url, *args], text=True, capture_output=True, timeout=15)
        if result.returncode:
            logs = "\n".join(p.read_text()[-3000:] for p in cls.root.glob("*.log"))
            raise RuntimeError(result.stdout + result.stderr + "\n" + logs)
        return result.stdout

    @classmethod
    def wait(cls, predicate, timeout=15):
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            try:
                if predicate():
                    return
            except (OSError, ValueError, RuntimeError) as error:
                last = error
            time.sleep(.2)
        for log in cls.logs:
            log.flush()
        logs = "\n".join(p.read_text()[-3000:] for p in cls.root.glob("*.log"))
        raise AssertionError(f"condition timed out: {last}\n{logs}")

    def test_management_path_and_ingestion(self):
        blocked = exchange(self.resolver_port, query("www.example.test"))
        self.assertEqual(blocked["rcode"], 3)
        allowed = exchange(self.resolver_port, query("safe.example.test", dnssec=True))
        self.assertEqual(allowed["rcode"], 0)
        self.assertTrue(allowed["flags"] & 0x20)
        self.assertTrue(any(record["type"] == 1 for record in allowed["answers"]))
        negative = exchange(self.resolver_port, query("missing.example.test", dnssec=True))
        self.assertEqual(negative["rcode"], 3)
        self.assertTrue(negative["flags"] & 0x20)
        nodata = exchange(self.resolver_port, query("safe.example.test", 28, True))
        self.assertEqual(nodata["rcode"], 0)
        self.assertFalse(nodata["answers"])
        self.assertTrue(nodata["flags"] & 0x20)
        wildcard = exchange(self.resolver_port, query("host.wild.example.test", dnssec=True))
        self.assertEqual(wildcard["rcode"], 0)
        self.assertTrue(wildcard["flags"] & 0x20)
        # DoH profile routing reaches the same policy.
        request = urllib.request.Request(f"https://localhost:{self.doh_port}/{self.profile}", query("www.example.test"), {"Content-Type": "application/dns-message"})
        with urllib.request.urlopen(request, context=self.context, timeout=5) as response:
            self.assertEqual(decode(response.read())["rcode"], 3)
        # DoT uses a profile prefix relative to the configured base hostname.
        with socket.create_connection(("127.0.0.1", self.dot_port), timeout=3) as raw:
            with self.context.wrap_socket(raw, server_hostname=f"{self.profile}.localhost") as stream:
                packet = query("www.example.test")
                stream.sendall(struct.pack("!H", len(packet)) + packet)
                size = struct.unpack("!H", receive_exact(stream, 2))[0]
                self.assertEqual(decode(receive_exact(stream, size))["rcode"], 3)
        # CLI changes become live through the CP and NATS, without a DNS process restart.
        self.cli("profile", "allow", self.profile, "www.example.test")
        self.cli("profile", "apply", "--yes")
        self.wait(lambda: exchange(self.resolver_port, query("www.example.test"))["rcode"] == 0)
        self.wait(lambda: "www.example.test" in json.dumps(self.api("GET", "/api/domains/www.example.test")))
        self.wait(lambda: "www.example.test" in json.dumps(self.api("GET", f"/api/flows?domain=www.example.test&action=ALLOW&profile={self.profile}")), timeout=45)
        # The authority retains the last signed zone when a malformed update arrives.
        before = exchange(self.authority_port, query("safe.example.test"))["answers"]
        current = self.api("GET", "/api/zones/example.test")
        if "origin" not in current:
            current = current.get("config", current)
        current["records"][0]["value"] = "invalid-ip"
        self.api("PUT", "/api/zones/example.test", current)
        time.sleep(.5)
        self.assertEqual(exchange(self.authority_port, query("safe.example.test"))["answers"], before)
        self.cli("zone", "apply", str(self.zone), "--yes")
        # Signing key metadata can be obtained through the same CLI.
        self.assertIn("DS", self.cli("zone", "dnssec", "ds", "example.test"))

    def test_migration_history_detects_changed_files(self):
        endpoint = os.environ.get("NAMESERVER_TEST_CLICKHOUSE", "http://127.0.0.1:28123")
        command = [__import__("sys").executable, str(ROOT / "tools/migrate_clickhouse.py"), "status", "--url", endpoint]
        good = subprocess.run(command, text=True, capture_output=True, timeout=10, check=True)
        self.assertEqual(json.loads(good.stdout)["pending_statements"], 0)
        directory = self.root / "changed-migrations"
        shutil.copytree(ROOT / "atlas/migrations/clickhouse", directory)
        first = sorted(directory.glob("*.sql"))[0]
        first.write_text(first.read_text() + "\n-- changed after application\n")
        bad = subprocess.run(command + ["--dir", str(directory)], text=True, capture_output=True, timeout=10)
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn("migration history differs", bad.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
