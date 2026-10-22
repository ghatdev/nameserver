#!/usr/bin/env python3
"""Apply versioned ClickHouse SQL with checked history and statement-level recovery."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.parse
import urllib.request


def statements(source):
    result, current = [], []
    quote, block, line = None, 0, False
    index = 0
    while index < len(source):
        char, pair = source[index], source[index:index + 2]
        if line:
            current.append(char)
            line = char != "\n"
        elif block:
            current.append(char)
            if pair == "/*":
                current.append(source[index + 1]); index += 1; block += 1
            elif pair == "*/":
                current.append(source[index + 1]); index += 1; block -= 1
        elif quote:
            current.append(char)
            if char == "\\" and index + 1 < len(source):
                current.append(source[index + 1]); index += 1
            elif char == quote:
                if index + 1 < len(source) and source[index + 1] == quote:
                    current.append(source[index + 1]); index += 1
                else:
                    quote = None
        elif pair == "--":
            current.extend(pair); index += 1; line = True
        elif pair == "/*":
            current.extend(pair); index += 1; block = 1
        elif char in "'\"`":
            quote = char; current.append(char)
        elif char == ";":
            text = "".join(current).strip()
            if text:
                result.append(text)
            current = []
        else:
            current.append(char)
        index += 1
    if quote or block:
        raise ValueError("unterminated SQL quote or comment")
    text = "".join(current).strip()
    if text:
        # Trailing comments do not constitute another statement.
        meaningful = re.sub(r"/\*.*?\*/|--[^\n]*", "", text, flags=re.S).strip()
        if meaningful:
            result.append(text)
    return result


class Client:
    def __init__(self, url, user, password):
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc or parsed.username or parsed.password:
            raise ValueError("use an HTTP(S) URL without embedded credentials")
        self.url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
        self.database = "default"
        self.authorization = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()

    def query(self, sql):
        url = self.url + "?" + urllib.parse.urlencode({"database": self.database, "wait_end_of_query": "1"})
        request = urllib.request.Request(url, sql.encode(), {"Authorization": self.authorization}, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                return response.read().decode()
        except urllib.error.HTTPError as error:
            detail = error.read().decode(errors="replace")
            raise RuntimeError(f"ClickHouse returned HTTP {error.code}: {detail}") from error


def migrate(client, directory, database, apply):
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", database):
        raise ValueError("database must be an SQL identifier")
    files = sorted(directory.glob("*.sql"))
    if not files:
        raise ValueError("no SQL migrations found")
    migrations = []
    for path in files:
        if not re.fullmatch(r"[0-9]{8,14}_[a-z0-9_]+\.sql", path.name):
            raise ValueError(f"invalid migration filename: {path.name}")
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        sql = re.sub(r"`?\bnameserver\b`?", f"`{database}`", raw.decode())
        migrations.append((path.name, digest, statements(sql)))
    table = f"`{database}`.schema_migrations"
    exists = client.query(f"EXISTS TABLE {table}").strip() == "1"
    history = {}
    if exists:
        for row in client.query(f"SELECT version, statement, checksum FROM {table} FORMAT TabSeparated").splitlines():
            version, position, digest = row.split("\t")
            key = version, int(position)
            if key in history and history[key] != digest:
                raise ValueError("conflicting migration history")
            history[key] = digest
    known = {name: (digest, len(sql)) for name, digest, sql in migrations}
    for (name, position), digest in history.items():
        if name not in known or known[name][0] != digest or not 1 <= position <= known[name][1]:
            raise ValueError(f"migration history differs from source: {name}; restore the original file and add a new migration")
    pending = [(name, digest, index, sql) for name, digest, commands in migrations for index, sql in enumerate(commands, 1) if (name, index) not in history]
    if not apply:
        print(json.dumps({"applied_statements": len(history), "pending_statements": len(pending)}))
        return
    client.query(f"CREATE DATABASE IF NOT EXISTS `{database}`")
    client.database = database
    client.query(f"CREATE TABLE IF NOT EXISTS {table} (version String, statement UInt32, checksum FixedString(64), applied_at DateTime64(3) DEFAULT now64(3)) ENGINE = MergeTree ORDER BY (version, statement)")
    for name, digest, index, sql in pending:
        client.query(sql)
        row = json.dumps({"version": name, "statement": index, "checksum": digest})
        client.query(f"INSERT INTO {table} (version, statement, checksum) FORMAT JSONEachRow\n{row}")
        print(f"Applied {name} statement {index}")
    print(f"ClickHouse schema current ({len(history) + len(pending)} statements)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["apply", "status"])
    parser.add_argument("--url", default="http://127.0.0.1:8123")
    parser.add_argument("--database", default="nameserver")
    parser.add_argument("--user", default=os.environ.get("NAMESERVER_CLICKHOUSE_USER", "default"))
    parser.add_argument("--password-env", default="NAMESERVER_CLICKHOUSE_PASSWORD")
    parser.add_argument("--dir", type=Path, default=Path(__file__).resolve().parents[1] / "atlas/migrations/clickhouse")
    args = parser.parse_args()
    migrate(Client(args.url, args.user, os.environ.get(args.password_env, "")), args.dir, args.database, args.command == "apply")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
