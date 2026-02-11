#!/usr/bin/env python3
"""Lokale Lernumgebung für SQL-Injection-Abwehr.

WICHTIG: Nur in einer legalen Testumgebung verwenden.
"""

from __future__ import annotations

import html
import sqlite3
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

DB_PATH = "demo.db"
HOST = "0.0.0.0"
PORT = 8000


def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS users")
    cur.execute(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            role TEXT NOT NULL
        )
        """
    )
    cur.executemany(
        "INSERT INTO users (username, role) VALUES (?, ?)",
        [
            ("alice", "admin"),
            ("bob", "user"),
            ("charlie", "user"),
        ],
    )
    conn.commit()
    conn.close()


def vulnerable_search(username: str) -> tuple[list[tuple[int, str, str]], str]:
    """Unsichere Suche: String-Konkatenation ermöglicht SQL-Injection."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    query = f"SELECT id, username, role FROM users WHERE username = '{username}'"
    cur.execute(query)
    rows = cur.fetchall()
    conn.close()
    return rows, query


def safe_search(username: str) -> tuple[list[tuple[int, str, str]], str]:
    """Sichere Suche mit Parameterbindung."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    query = "SELECT id, username, role FROM users WHERE username = ?"
    cur.execute(query, (username,))
    rows = cur.fetchall()
    conn.close()
    return rows, query


def render_rows(rows: list[tuple[int, str, str]]) -> str:
    if not rows:
        return "<p>Keine Treffer.</p>"
    items = "".join(
        f"<li>id={row[0]} | username={html.escape(row[1])} | role={html.escape(row[2])}</li>"
        for row in rows
    )
    return f"<ul>{items}</ul>"


class AppHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/":
            params = parse_qs(parsed.query)
            username = params.get("username", [""])[0]
            mode = params.get("mode", ["safe"])[0]

            executed_query = ""
            result_html = ""
            if username:
                if mode == "vulnerable":
                    rows, executed_query = vulnerable_search(username)
                else:
                    rows, executed_query = safe_search(username)
                result_html = render_rows(rows)

            page = f"""
<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>SQL Injection Demo (Lokal)</title>
  <style>
    body {{ font-family: sans-serif; max-width: 840px; margin: 2rem auto; line-height: 1.5; }}
    .card {{ border: 1px solid #ddd; border-radius: 8px; padding: 1rem; margin-bottom: 1rem; }}
    code, pre {{ background: #f6f8fa; padding: 0.2rem 0.4rem; border-radius: 4px; }}
    input, select, button {{ padding: 0.45rem; margin-right: 0.5rem; }}
    .warn {{ color: #9a3412; font-weight: 600; }}
  </style>
</head>
<body>
  <h1>SQL-Injection Lernseite (nur lokal & legal)</h1>
  <p class="warn">Nicht im Internet deployen. Nur für Schulung in einer isolierten Umgebung.</p>

  <div class="card">
    <form method="get" action="/">
      <label>Nutzername:</label>
      <input name="username" value="{html.escape(username)}" placeholder="alice" />
      <label>Modus:</label>
      <select name="mode">
        <option value="safe" {"selected" if mode == "safe" else ""}>Sicher (Prepared Statement)</option>
        <option value="vulnerable" {"selected" if mode == "vulnerable" else ""}>Verwundbar (String-Konkatenation)</option>
      </select>
      <button type="submit">Suchen</button>
    </form>
    <p><strong>Beispiel-Eingabe für Demo:</strong> <code>' OR '1'='1</code> (nur lokal testen)</p>
  </div>

  <div class="card">
    <h2>Ergebnis</h2>
    {result_html}
    <h3>Ausgeführtes SQL</h3>
    <pre>{html.escape(executed_query) if executed_query else 'Noch keine Abfrage ausgeführt.'}</pre>
  </div>

  <div class="card">
    <h2>Was du lernst</h2>
    <ul>
      <li>Warum String-Konkatenation bei SQL gefährlich ist.</li>
      <li>Wie Parameterbindung SQL-Injection verhindert.</li>
      <li>Wie man Eingaben serverseitig validiert und loggt.</li>
    </ul>
  </div>
</body>
</html>
"""
            body = page.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_error(HTTPStatus.NOT_FOUND)


def run() -> None:
    init_db()
    server = ThreadingHTTPServer((HOST, PORT), AppHandler)
    print(f"Server läuft auf http://{HOST}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    run()
