#!/usr/bin/env python3
# audit_browsers_redacted.py
# ---------------------------------------------------------------
# Auditoría segura de perfiles de navegador (Chrome/Edge/Firefox).
# - Abre perfiles en modo solo lectura.
# - Lista tablas y conteos.
# - Para datos sensibles (cookies/logins) muestra solo metadatos:
#     * longitud y hash HMAC no reversible (para correlación).
# - No descifra, no imprime valores, no exfiltra.
# - Exporta un reporte JSON con las métricas.
#
# Uso:
#   python audit_browsers_redacted.py
# ---------------------------------------------------------------

import hashlib
import hmac
import json
import os
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

HMAC_KEY = b"audit-lab-fixed-key"

REPORT = {
    "home": str(Path.home()),
    "generated_at": datetime.utcnow().isoformat() + "Z",
    "databases": [],
}


def human(n):
    for u in ["B", "KB", "MB", "GB", "TB", "PB"]:
        if n < 1024.0:
            return f"{n:.1f} {u}"
        n /= 1024.0
    return f"{n:.1f} EB"


def list_if_exists(paths):
    return [p for p in paths if p.exists()]


def hred(value: bytes) -> str:
    """Hash HMAC-SHA256 truncado para correlación sin revelar valor."""
    return hmac.new(HMAC_KEY, value, hashlib.sha256).hexdigest()[:16]


def safe_connect(db_path: Path):
    return sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)


def print_header(db: Path):
    print("=" * 100)
    print("FILE :", db)
    try:
        size = human(db.stat().st_size)
        mtime = datetime.fromtimestamp(db.stat().st_mtime).isoformat()
        print("SIZE :", size)
        print("MTIME:", mtime)
    except Exception as e:
        print("STAT ERROR:", e)


def list_tables(db_path: Path):
    try:
        con = safe_connect(db_path)
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        info = [r[0] for r in cur.fetchall()]
        con.close()
        return info
    except Exception:
        return []


def count_rows(con, table):
    try:
        cur = con.cursor()
        cur.execute(f"SELECT COUNT(*) FROM '{table}'")
        return cur.fetchone()[0]
    except Exception:
        return "?"


def audit_sqlite_generic(db_path: Path):
    out = {"path": str(db_path), "kind": "generic_sqlite", "tables": []}
    print("TABLES (count only):")
    try:
        con = safe_connect(db_path)
        for t in list_tables(db_path):
            c = count_rows(con, t)
            out["tables"].append({"table": t, "rows": c})
            print(f"  - {t}: {c}")
        con.close()
    except Exception as e:
        print("DB ERROR:", e)
        out["error"] = str(e)
    REPORT["databases"].append(out)


def redact_field(val):
    if val is None:
        return None
    if isinstance(val, (bytes, bytearray)):
        return {"len": len(val), "hash": hred(val)}
    if isinstance(val, str):
        bs = val.encode("utf-8", errors="ignore")
        return {"len": len(val), "hash": hred(bs)}
    return val


def audit_chromium_cookies(db_path: Path, limit=10):
    out = {
        "path": str(db_path),
        "kind": "chromium_cookies",
        "sample": [],
        "total": None,
        "schema": None,
    }
    columns_try = [
        (
            "host_key",
            "name",
            "value",
            "encrypted_value",
            "expires_utc",
            "path",
            "is_secure",
            "is_httponly",
            "samesite",
        ),
        (
            "host_key",
            "name",
            "encrypted_value",
            "expires_utc",
            "path",
            "is_secure",
            "is_httponly",
            "samesite",
        ),
        ("host_key", "name", "value", "expires_utc", "path"),
    ]
    try:
        con = safe_connect(db_path)
        cur = con.cursor()
        cols = None
        for cand in columns_try:
            try:
                cur.execute(f"SELECT {', '.join(cand)} FROM cookies LIMIT 1")
                cols = cand
                break
            except Exception:
                continue
        if not cols:
            print("cookies: esquema no reconocido.")
            con.close()
            REPORT["databases"].append(out)
            return
        out["schema"] = list(cols)

        cur.execute("SELECT COUNT(*) FROM cookies")
        total = cur.fetchone()[0]
        out["total"] = int(total)
        print(f"cookies: {total} filas (mostrando {min(limit,total)} redacted)")

        cur.execute(f"SELECT {', '.join(cols)} FROM cookies LIMIT {limit}")
        for r in cur.fetchall():
            row = {cols[i]: r[i] for i in range(len(cols))}
            for key in ("value", "encrypted_value", "host_key", "name", "path"):
                row[key] = redact_field(row[key])
            out["sample"].append(row)
            print("  •", row)
        con.close()
    except PermissionError:
        print("cookies: sin permisos (¿navegador abierto?).")
        out["error"] = "permission"
    except Exception as e:
        print("cookies: ERROR:", e)
        out["error"] = str(e)
    REPORT["databases"].append(out)


def audit_chromium_logins(db_path: Path, limit=10):
    out = {
        "path": str(db_path),
        "kind": "chromium_logins",
        "sample": [],
        "total": None,
        "schema": None,
    }
    candidates = [
        ("logins", ("origin_url", "username_value", "password_value", "date_created")),
        ("logins", ("origin_url", "username_value", "password_value", "date_last_used")),
        ("logins", ("origin_url", "username_value", "password_value")),
        (
            "logins",
            (
                "origin_url",
                "username_element",
                "username_value",
                "password_element",
                "password_value",
            ),
        ),
    ]
    try:
        con = safe_connect(db_path)
        cur = con.cursor()
        target = None
        for table, cols in candidates:
            try:
                cur.execute(f"SELECT {', '.join(cols)} FROM {table} LIMIT 1")
                target = (table, cols)
                break
            except Exception:
                continue
        if not target:
            print("logins: esquema no reconocido.")
            con.close()
            REPORT["databases"].append(out)
            return
        table, cols = target
        out["schema"] = [table] + list(cols)

        cur.execute(f"SELECT COUNT(*) FROM {table}")
        total = cur.fetchone()[0]
        out["total"] = int(total)
        print(f"{table}: {total} filas (mostrando {min(limit,total)} redacted)")

        cur.execute(f"SELECT {', '.join(cols)} FROM {table} LIMIT {limit}")
        for r in cur.fetchall():
            row = {cols[i]: r[i] for i in range(len(cols))}
            for key in ("username_value", "password_value", "origin_url"):
                if key in row:
                    row[key] = redact_field(row[key])
            out["sample"].append(row)
            print("  •", row)
        con.close()
    except PermissionError:
        print("logins: sin permisos (¿navegador abierto?).")
        out["error"] = "permission"
    except Exception as e:
        print("logins: ERROR:", e)
        out["error"] = str(e)
    REPORT["databases"].append(out)


def audit_webdata(db_path: Path):
    out = {"path": str(db_path), "kind": "chromium_webdata", "tables": []}
    try:
        con = safe_connect(db_path)
        tables = list_tables(db_path)
        print("Web Data tablas (conteo):")
        for t in tables:
            c = count_rows(con, t)
            out["tables"].append({"table": t, "rows": c})
            print(f"  - {t}: {c}")
        con.close()
    except Exception as e:
        print("Web Data: ERROR:", e)
        out["error"] = str(e)
    REPORT["databases"].append(out)


def audit_firefox_cookies(db_path: Path, limit=10):
    out = {"path": str(db_path), "kind": "firefox_cookies", "sample": [], "total": None}
    try:
        con = safe_connect(db_path)
        cur = con.cursor()
        cur.execute("SELECT COUNT(*) FROM moz_cookies")
        total = cur.fetchone()[0]
        out["total"] = int(total)
        print(f"moz_cookies: {total} filas (mostrando {min(limit,total)} redacted)")
        cur.execute(
            "SELECT host, name, value, expiry, path FROM moz_cookies LIMIT ?",
            (limit,),
        )
        for host, name, value, expiry, path in cur.fetchall():
            row = {
                "host": redact_field(host),
                "name": redact_field(name),
                "value": redact_field(value),
                "path": redact_field(path),
                "expiry": expiry,
            }
            out["sample"].append(row)
            print("  •", row)
        con.close()
    except Exception as e:
        print("moz_cookies: ERROR:", e)
        out["error"] = str(e)
    REPORT["databases"].append(out)


def audit_firefox_logins(json_path: Path):
    out = {"path": str(json_path), "kind": "firefox_logins_json"}
    try:
        text = json_path.read_text(encoding="utf-8", errors="ignore")
        out["size"] = len(text)
        out["hash"] = hred(text.encode())
        print(
            f"logins.json size={human(len(text))} hash={out['hash']} (contenido oculto)"
        )
    except Exception as e:
        print("logins.json: ERROR:", e)
        out["error"] = str(e)
    REPORT["databases"].append(out)


def main():
    home = Path.home()
    candidates = [
        home / "AppData/Local/Google/Chrome/User Data/Default",
        home / "AppData/Local/Microsoft/Edge/User Data/Default",
        home / ".config/google-chrome/Default",
        home / "Library/Application Support/Google/Chrome/Default",
        home / "Library/Application Support/Microsoft Edge/Default",
        home / "AppData/Roaming/Mozilla/Firefox/Profiles",
        home / ".mozilla/firefox",
        home / "Library/Application Support/Firefox/Profiles",
    ]
    print(f"Audit home: {home}\n")

    targets = [
        "Cookies",
        "Network/Cookies",
        "Login Data",
        "Web Data",
        "places.sqlite",
        "logins.json",
    ]
    found = []
    for base in list_if_exists(candidates):
        if base.name == "Profiles":
            for prof in base.glob("*"):
                for t in targets:
                    p = prof / t
                    if p.exists():
                        found.append(p)
        else:
            for t in targets:
                p = base / t
                if p.exists():
                    found.append(p)

    if not found:
        print("No se encontraron bases comunes.")
        return

    for db in found:
        print_header(db)
        is_sqlite = False
        try:
            with open(db, "rb") as f:
                header = f.read(16)
            is_sqlite = b"SQLite format 3" in header
        except Exception:
            pass

        name = db.name.lower()
        parent = db.parent.name.lower()

        try:
            if name == "cookies" or (parent == "network" and name == "cookies"):
                audit_chromium_cookies(db) if is_sqlite else print(
                    "Cookies: no SQLite."
                )
            elif name == "login data":
                audit_chromium_logins(db) if is_sqlite else print("Login Data: no SQLite.")
            elif name == "web data":
                audit_webdata(db) if is_sqlite else print("Web Data: no SQLite.")
            elif name == "places.sqlite":
                audit_sqlite_generic(db) if is_sqlite else print("places.sqlite: no SQLite.")
            elif name == "logins.json":
                audit_firefox_logins(db)
            else:
                audit_sqlite_generic(db) if is_sqlite else print("Formato no inspeccionado (OK).")
        except PermissionError:
            print("Permisos insuficientes (cierra el navegador e intenta de nuevo).")
        except Exception as e:
            print("ERROR:", e)

    out = Path.cwd() / "audit_report.json"
    out.write_text(json.dumps(REPORT, indent=2), encoding="utf-8")
    print("\n📄 Reporte JSON:", out)
    print("✅ Auditoría completada (redactada, sin exponer datos).")


if __name__ == "__main__":
    main()
