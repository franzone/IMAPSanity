"""Header and snippet parsing for maildir files."""

import email
import email.header
import email.parser
import email.policy
import email.utils
import re

HEADER_LIMIT = 256 * 1024
BODY_LIMIT = 2 * 1024 * 1024


def norm_msgid(value):
    return "".join((value or "").split())


def _decode(value):
    if value is None:
        return ""
    try:
        return str(email.header.make_header(email.header.decode_header(str(value))))
    except Exception:
        return str(value)


def read_header_bytes(path):
    with open(path, "rb") as f:
        data = f.read(HEADER_LIMIT)
    for sep in (b"\r\n\r\n", b"\n\n"):
        i = data.find(sep)
        if i != -1:
            return data[: i + len(sep)]
    return data


def parse_headers(raw):
    msg = email.parser.BytesHeaderParser(policy=email.policy.compat32).parsebytes(raw)
    from_raw = " ".join(_decode(msg.get("From")).split())
    addr = email.utils.parseaddr(from_raw)[1].lower()
    date_ts = None
    try:
        dt = email.utils.parsedate_to_datetime(msg.get("Date"))
        date_ts = int(dt.timestamp()) if dt else None
    except Exception:
        pass
    return {
        "msgid": norm_msgid(msg.get("Message-ID")),
        "from_raw": from_raw,
        "from_addr": addr,
        "subject": " ".join(_decode(msg.get("Subject")).split()),
        "date_ts": date_ts,
        "list_id": " ".join(_decode(msg.get("List-Id")).split()),
    }


def read_headers(path):
    return parse_headers(read_header_bytes(path))


_TAG_RE = re.compile(r"<(script|style)\b.*?</\1>|<[^>]+>", re.S | re.I)


def read_snippet(path, length=500):
    try:
        with open(path, "rb") as f:
            msg = email.message_from_bytes(f.read(BODY_LIMIT), policy=email.policy.default)
        part = msg.get_body(preferencelist=("plain", "html"))
        if part is None:
            return ""
        text = part.get_content()
        if part.get_content_subtype() == "html":
            text = _TAG_RE.sub(" ", text)
        return " ".join(text.split())[:length]
    except Exception:
        return ""
