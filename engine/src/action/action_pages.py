"""HTML pages of the Action Lambda (design §10.4, CONTRACT §4.6).

Small self-contained pages: no scripts, no external resources, inline style only (the CSP allows nothing else).
Every untrusted value (resource IDs, Name tags, regions, error text) goes through html.escape.
The raw token appears only in the hidden form field of the confirmation page.
"""

from html import escape

SECURITY_HEADERS = {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": ("default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
                                "frame-ancestors 'none'; base-uri 'none'"),
}

STYLE = (
    "body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem;"
    "color:#1f2328;line-height:1.5}"
    "h1{font-size:1.4rem}"
    "dl{display:grid;grid-template-columns:max-content 1fr;gap:.25rem 1rem}"
    "dt{font-weight:600}dd{margin:0;word-break:break-all}"
    "button{font-size:1rem;padding:.5rem 1.5rem;border-radius:6px;border:1px solid #1f6feb;background:#1f6feb;"
    "color:#fff;cursor:pointer}"
    ".note{color:#59636e;font-size:.9rem}"
    ".err{border-left:4px solid #cf222e;padding-left:.75rem}"
    ".ok{border-left:4px solid #1a7f37;padding-left:.75rem}"
)

TITLES = {
    "protect": "Protect this resource",
    "postpone": "Postpone the action",
    "restore": "Restore the volume from its snapshot",
}

WHAT_HAPPENS = {
    "protect": ("The tag guardian:protect=true is added to the resource and its warning timeline is stopped. "
                "Cost Guardian will only report on it from now on; it will never stop or delete it."),
    "postpone": ("The current warning timeline is stopped and a new one starts with a later deadline. "
                 "You will get a new final warning before anything happens."),
    "restore": ("A new gp3 volume is created from the Guardian's snapshot, in the original volume's "
                "Availability Zone and with its original tags. The snapshot is kept. "
                "The new volume is not attached to anything."),
}


def _page(title, body, css_class=""):
    cls = f' class="{css_class}"' if css_class else ""
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta name="robots" content="noindex, nofollow">'
        f"<title>{escape(title)} - Cloud Cost Guardian</title><style>{STYLE}</style></head>"
        f"<body><h1>{escape(title)}</h1><div{cls}>{body}</div>"
        '<p class="note">Cloud Cost Guardian</p></body></html>\n'
    )


def _details(rows):
    """<dl> of (label, value) pairs; rows with a None value are skipped. Values are escaped here."""
    items = "".join(f"<dt>{escape(label)}</dt><dd>{escape(str(value))}</dd>"
                    for label, value in rows if value is not None and value != "")
    return f"<dl>{items}</dl>"


def response(status, html, extra_headers=None):
    headers = dict(SECURITY_HEADERS)
    headers.update(extra_headers or {})
    return {"statusCode": status, "headers": headers, "body": html, "isBase64Encoded": False}


def confirmation(action, info, raw_token):
    """GET page: what will happen + one Confirm button posting t back to the same path."""
    rows = [("Resource", info["resourceId"]), ("Name", info.get("name")), ("Region", info.get("region"))]
    if action in ("protect", "postpone"):
        rows.append(("Current deadline", info.get("deadlineAt")))
    if action == "postpone":
        rows.append(("New deadline (approx.)", info.get("newDeadlineAt")))
        rows.append(("Postpones left after this one", info.get("postponesLeftAfter")))
    if action == "restore":
        rows += [("Snapshot", info.get("snapshotId")), ("Availability Zone", info.get("availabilityZone"))]
    body = (
        f"<p>{escape(WHAT_HAPPENS[action])}</p>"
        f"{_details(rows)}"
        # Relative action: posts to the same /action path (form-action 'self').
        '<form method="post" action="action">'
        f'<input type="hidden" name="t" value="{escape(raw_token, quote=True)}">'
        "<button type=\"submit\">Confirm</button></form>"
        '<p class="note">Nothing has changed yet. The action runs only when you press Confirm; '
        "the link works once.</p>"
    )
    return _page(TITLES[action], body)


def done(action, info):
    """POST success page."""
    if action == "protect":
        text = ("The resource is now tagged guardian:protect=true and its timeline is stopped. "
                "Cost Guardian will not stop or delete it.")
        rows = [("Resource", info["resourceId"]), ("Name", info.get("name")), ("Region", info.get("region"))]
    elif action == "postpone":
        text = "The action is postponed. A new timeline started; you will get a new final warning before the deadline."
        rows = [("Resource", info["resourceId"]), ("Name", info.get("name")), ("Region", info.get("region")),
                ("New deadline (approx.)", info.get("newDeadlineAt"))]
    else:
        text = "The new volume was created from the snapshot. It is not attached to any instance."
        rows = [("New volume", info.get("newVolumeId")), ("Restored from", info.get("snapshotId")),
                ("Original volume", info["resourceId"]), ("Availability Zone", info.get("availabilityZone")),
                ("Region", info.get("region"))]
    return _page("Done", f"<p>{escape(text)}</p>{_details(rows)}", "ok")


def refusal(title, message):
    return _page(title, f"<p>{escape(message)}</p>", "err")


def error(message, rows=()):
    return _page("Something went wrong", f"<p>{escape(message)}</p>{_details(rows)}", "err")
