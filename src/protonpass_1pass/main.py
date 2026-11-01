#!/usr/bin/env python3
"""
Convert a Proton Pass CSV export into 1Password-importable CSV files.

Input : Proton Pass CSV export (Settings -> Export -> CSV).
        Works with the 12-, 11- and 9-column variants:
          type,name,url,autofillUrls,email,username,password,note,totp,createTime,modifyTime,vault
          type,name,url,email,username,password,note,totp,createTime,modifyTime,vault
          type,name,url,email,username,password,note,totp,vault

Output: up to three files next to the output stem you give:
          <stem>_logins.csv   Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes
          <stem>_cards.csv    Title,Card Number,Expiry Date,Cardholder Name,PIN,Bank Name,CVV,Notes
          <stem>_notes.csv    Title,Notes
        Only non-empty files are written. Import each one separately in
        1Password (1Password.com -> Import data -> CSV, or the desktop app).

No secrets are ever printed to the terminal. Delete the input and output
files once the import is verified.

Usage:
    python proton_to_1password.py proton_export.csv
    python proton_to_1password.py proton_export.csv -o out/1password
    python proton_to_1password.py proton_export.csv --vault-as-tag --no-header
    python proton_to_1password.py proton_export.csv --exclude-1password 1PasswordExport.csv

Duplicate filtering (--exclude-1password):
    A Proton login is matched against the 1Password export on
    (site, username), where site = URL host without 'www.' (or the title
    when there is no URL) and username is case-insensitive. Every URL on
    the Proton item is checked.
      same site+username+password  -> skipped (already in 1Password)
      same site+username, other pw -> written with tag 'proton-conflict'
                                      (--conflicts skip|keep to change)
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import urllib.parse
from collections import Counter

LOGIN_HEADER = ["Title", "Url", "Username", "Password", "OTPAuth",
                "Favorite", "Archived", "Tags", "Notes"]
CARD_HEADER = ["Title", "Card Number", "Expiry Date", "Cardholder Name",
               "PIN", "Bank Name", "CVV", "Notes"]
NOTE_HEADER = ["Title", "Notes"]

PROTON_REQUIRED = {"type", "name", "password", "note"}


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _s(row: dict, key: str) -> str:
    """Safe string getter: missing column or None -> ''."""
    v = row.get(key)
    return "" if v is None else str(v).strip()


def extract_urls(row: dict) -> list[str]:
    """Return every URL on the item, primary first, deduplicated."""
    urls: list[str] = []

    raw_af = _s(row, "autofillUrls")
    if raw_af:
        try:
            parsed = json.loads(raw_af)
            for entry in parsed:
                if isinstance(entry, dict) and entry.get("url"):
                    urls.append(str(entry["url"]).strip())
                elif isinstance(entry, str):
                    urls.append(entry.strip())
        except (json.JSONDecodeError, TypeError):
            pass

    raw_url = _s(row, "url")
    if raw_url:
        for u in re.split(r",\s*", raw_url):
            u = u.strip()
            if u:
                urls.append(u)

    seen, out = set(), []
    for u in urls:
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def normalise_totp(value: str, title: str, account: str) -> str:
    """
    1Password expects an otpauth:// URI in the OTPAuth column.
    Proton usually stores a full URI, but a bare base32 secret is possible.
    """
    value = value.strip()
    if not value:
        return ""
    if value.lower().startswith("otpauth://"):
        return value
    # Looks like a bare base32 secret (possibly with spaces/dashes)?
    cleaned = re.sub(r"[\s-]", "", value).upper()
    if re.fullmatch(r"[A-Z2-7]+=*", cleaned):
        label = urllib.parse.quote(f"{title}:{account}" if account else title, safe="")
        q = {"secret": cleaned}
        if title:
            q["issuer"] = title
        return f"otpauth://totp/{label}?{urllib.parse.urlencode(q)}"
    # Unknown shape: pass through unchanged and let 1Password decide.
    return value


def yyyymm_to_mmyyyy(exp: str) -> str:
    """Proton stores card expiry as 'YYYY-MM'; 1Password wants 'MM/YYYY'."""
    exp = exp.strip()
    m = re.fullmatch(r"(\d{4})-(\d{1,2})", exp)
    if m:
        return f"{int(m.group(2)):02d}/{m.group(1)}"
    m = re.fullmatch(r"(\d{1,2})/(\d{2,4})", exp)
    if m:
        year = m.group(2)
        if len(year) == 2:
            year = "20" + year
        return f"{int(m.group(1)):02d}/{year}"
    return exp


def parse_json_note(note: str) -> dict | None:
    note = note.strip()
    if not note.startswith("{"):
        return None
    try:
        obj = json.loads(note)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        return None


def site_key(url: str, title: str) -> str:
    """
    Normalise a login's site for duplicate matching:
    host without scheme/path/port/'www.', lower-cased. Falls back to the
    lower-cased title when there is no URL.
    """
    url = url.strip()
    if url:
        if "://" not in url:
            url = "https://" + url
        host = (urllib.parse.urlsplit(url).hostname or "").lower()
        if host.startswith("www."):  # noqa: FURB188
            host = host[4:]
        if host:
            return host
    return "title:" + title.strip().lower()


def login_keys(url: str, title: str, username: str) -> set[tuple[str, str]]:
    """(site, username) keys for one login. Username is case-insensitive."""
    return {(site_key(url, title), username.strip().lower())}


def load_1password_export(path: str) -> dict[tuple[str, str], set[str]]:
    """
    Read a 1Password CSV export and return {(site, username): {passwords}}.
    The export header is Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes
    (header names matched case-insensitively; only Title/Url/Username/Password are needed).
    """
    index: dict[tuple[str, str], set[str]] = {}
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            sys.exit(f"{path} is empty.")
        cols = {fn.strip().lower(): fn for fn in reader.fieldnames}

        def pick(*names: str) -> str | None:
            for n in names:
                if n in cols:
                    return cols[n]
            return None

        c_title = pick("title", "name")
        c_url = pick("url", "website", "urls")
        c_user = pick("username", "user", "login")
        c_pass = pick("password")
        if not (c_user and c_pass):
            sys.exit(f"{path} does not look like a 1Password CSV export "
                     f"(need Username and Password columns; found {reader.fieldnames}).")
        for row in reader:
            title = _s(row, c_title) if c_title else ""
            url = _s(row, c_url) if c_url else ""
            user = _s(row, c_user)
            pw = _s(row, c_pass)
            # 1Password's Url column can hold several URLs separated by commas/newlines.
            urls = [u for u in re.split(r"[,\n]\s*", url) if u.strip()] or [""]
            for u in urls:
                for key in login_keys(u, title, user):
                    index.setdefault(key, set()).add(pw)
    return index


def join_notes(*parts: str) -> str:
    return "\n".join(p for p in (x.strip() for x in parts) if p)


def pretty_fields(obj: dict, skip: set[str] = frozenset()) -> str: # type: ignore
    """Flatten a JSON object into 'Key: value' lines for a secure note."""
    lines = []
    for k, v in obj.items():
        if k in skip or v in ("", None, [], {}):
            continue
        if isinstance(v, (dict, list)):
            v = json.dumps(v, ensure_ascii=False)
        lines.append(f"{k}: {v}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# per-type converters
# --------------------------------------------------------------------------- #
def convert_login(row: dict, tag: str) -> list[str]:
    title = _s(row, "name")
    email = _s(row, "email")
    username = _s(row, "username")
    urls = extract_urls(row)

    primary_url = urls[0] if urls else ""
    extra_notes = []

    if len(urls) > 1:
        extra_notes.append("Additional URLs:\n" + "\n".join(urls[1:]))

    if username and email and username != email:
        login_name = username
        extra_notes.append(f"Email: {email}")
    else:
        login_name = username or email

    totp = normalise_totp(_s(row, "totp"), title, login_name)
    notes = join_notes(_s(row, "note"), *extra_notes)

    return [title, primary_url, login_name, _s(row, "password"), totp,
            "", "", tag, notes]


def convert_alias(row: dict, tag: str, mode: str) -> tuple[str, list[str]] | None:
    """Return ('login' | 'note', row) or None to skip."""
    title = _s(row, "name")
    address = _s(row, "email") or _s(row, "username")
    note = join_notes(f"Proton Pass hide-my-email alias: {address}", _s(row, "note"))
    if mode == "skip":
        return None
    if mode == "logins":
        return "login", [title, "", address, "", "", "", "", tag, note]
    return "note", [title, note]


def convert_card(row: dict, tag: str) -> list[str]:
    title = _s(row, "name")
    data = parse_json_note(_s(row, "note")) or {}
    inner_note = str(data.get("note", "") or "")
    pin = str(data.get("pin", "") or "")
    notes = join_notes(inner_note)
    return [title,
            str(data.get("number", "") or ""),
            yyyymm_to_mmyyyy(str(data.get("expirationDate", "") or "")),
            str(data.get("cardholderName", "") or ""),
            pin,
            "",  # Proton has no bank-name field
            str(data.get("verificationNumber", "") or ""),
            notes]


def convert_note(row: dict) -> list[str]:
    return [_s(row, "name"), _s(row, "note")]


def convert_identity(row: dict) -> list[str]:
    title = _s(row, "name")
    data = parse_json_note(_s(row, "note"))
    if data is None:
        return [title, _s(row, "note")]
    inner_note = str(data.get("note", "") or "")
    body = pretty_fields(data, skip={"note"})
    return [title, join_notes(body, inner_note)]


def convert_other(row: dict, item_type: str) -> list[str]:
    """sshKey, wifi, custom and anything unknown -> secure note with what is left."""
    title = _s(row, "name")
    parts = [f"Proton Pass item type: {item_type}"]
    for key in ("url", "email", "username", "password", "totp"):
        v = _s(row, key)
        if v:
            parts.append(f"{key}: {v}")
    parts.append(_s(row, "note"))
    parts.append("NOTE: Proton Pass CSV exports drop custom fields/sections for "
                 "this item type. Check the original item before deleting it.")
    return [title, join_notes(*parts)]


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def read_proton_csv(path: str) -> tuple[list[str], list[dict]]:
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            sys.exit("Input file is empty.")
        fieldnames = [fn.strip() for fn in reader.fieldnames]
        rows = []
        for raw in reader:
            rows.append({(k.strip() if k else k): v for k, v in raw.items()})
    missing = PROTON_REQUIRED - set(fieldnames)
    if missing:
        sys.exit(f"This does not look like a Proton Pass CSV export. "
                 f"Missing columns: {sorted(missing)}. Found: {fieldnames}")
    return fieldnames, rows


def write_csv(path: str, header: list[str], rows: list[list[str]], with_header: bool) -> None:
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, quoting=csv.QUOTE_ALL, lineterminator="\n")
        if with_header:
            w.writerow(header)
        w.writerows(rows)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", help="Proton Pass CSV export")
    ap.add_argument("-o", "--output", default="1password",
                    help="output stem; files become <stem>_logins.csv etc. (default: 1password)")
    ap.add_argument("--vault-as-tag", action="store_true",
                    help="put the Proton vault name into the 1Password Tags column")
    ap.add_argument("--aliases", choices=["notes", "logins", "skip"], default="notes",
                    help="what to do with hide-my-email alias items (default: notes)")
    ap.add_argument("--no-header", action="store_true",
                    help="omit the header row (use if 1Password imports the header as an item)")
    ap.add_argument("--keep-empty-logins", action="store_true",
                    help="keep login rows that have no password (default: move them to notes)")
    ap.add_argument("--exclude-1password", metavar="EXPORT.csv",
                    help="CSV exported from 1Password; Proton logins already present there "
                         "(same site + username + password) are not written")
    ap.add_argument("--conflicts", choices=["tag", "skip", "keep"], default="tag",
                    help="Proton login whose site+username exists in 1Password but with a "
                         "different password: tag it 'proton-conflict' (default), skip it, "
                         "or keep it untouched")
    args = ap.parse_args()

    fieldnames, rows = read_proton_csv(args.input)

    existing: dict[tuple[str, str], set[str]] = {}
    if args.exclude_1password:
        existing = load_1password_export(args.exclude_1password)
        print(f"Loaded {len(existing)} site+username keys from {args.exclude_1password}")

    logins: list[list[str]] = []
    cards: list[list[str]] = []
    notes: list[list[str]] = []
    counts: Counter = Counter()
    vaults: set[str] = set()

    for row in rows:
        item_type = _s(row, "type").lower() or "login"
        vault = _s(row, "vault")
        if vault:
            vaults.add(vault)
        tag = vault if args.vault_as_tag else ""
        counts[item_type] += 1

        if item_type == "login":
            r = convert_login(row, tag)

            if existing and r[3]:
                # Compare against every URL on the Proton item, not just the primary one.
                keys: set[tuple[str, str]] = set()
                for u in extract_urls(row) or [""]:
                    keys |= login_keys(u, r[0], r[2])
                matched_pw = {pw for k in keys for pw in existing.get(k, ())}
                if matched_pw:
                    if r[3] in matched_pw:
                        counts["login skipped (already in 1Password)"] += 1
                        continue
                    if args.conflicts == "skip":
                        counts["login skipped (conflict, different password)"] += 1
                        continue
                    if args.conflicts == "tag":
                        r[7] = ";".join(t for t in (r[7], "proton-conflict") if t)
                    counts["login conflict (different password)"] += 1

            if not r[3] and not args.keep_empty_logins:
                # No password -> 1Password would reject it as a login; keep the data as a note.
                body = join_notes(f"Url: {r[1]}" if r[1] else "",
                                  f"Username: {r[2]}" if r[2] else "",
                                  f"OTPAuth: {r[4]}" if r[4] else "",
                                  r[8])
                notes.append([r[0], body])
                counts["login->note (no password)"] += 1
            else:
                logins.append(r)
        elif item_type == "alias":
            res = convert_alias(row, tag, args.aliases)
            if res is None:
                counts["alias skipped"] += 1
            elif res[0] == "login":
                logins.append(res[1])
            else:
                notes.append(res[1])
        elif item_type == "creditcard":
            cards.append(convert_card(row, tag))
        elif item_type == "note":
            notes.append(convert_note(row))
        elif item_type == "identity":
            notes.append(convert_identity(row))
        else:
            notes.append(convert_other(row, item_type))

    stem = args.output
    out_dir = os.path.dirname(stem)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    written = []
    for suffix, header, data in (("logins", LOGIN_HEADER, logins),
                                 ("cards", CARD_HEADER, cards),
                                 ("notes", NOTE_HEADER, notes)):
        if data:
            path = f"{stem}_{suffix}.csv"
            write_csv(path, header, data, with_header=not args.no_header)
            written.append((path, len(data)))

    print(f"Read {len(rows)} rows ({len(fieldnames)} columns) from {args.input}")
    print("Item types found: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    if len(vaults) > 1 and not args.vault_as_tag:
        print(f"Note: {len(vaults)} vaults in export; use --vault-as-tag to keep them as tags.")
    for path, n in written:
        print(f"Wrote {n:5d} items -> {path}")
    if not written:
        print("Nothing to write.")
    print("Reminder: import each file separately, verify in 1Password, then delete "
          "both the Proton export and these files.")


if __name__ == "__main__":
    main()
