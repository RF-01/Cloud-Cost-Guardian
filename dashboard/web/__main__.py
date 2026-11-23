"""Entry point: `python -m dashboard.web` (from the repo root).

Environment:
    NAME_PREFIX   table names = <prefix><name>, e.g. cg-dev- (each TABLE_* variable overrides one table)
    PORT          default 8080
    HOST          default 127.0.0.1 (the EC2 service in #38 sets 0.0.0.0)
    AWS_REGION    default us-west-2
    THREADS       waitress worker threads, default 8
    ORIGIN_SECRET           if set, every request needs X-Origin-Verify = this value (else 403)
    REQUIRE_ORIGIN_SECRET   1 = refuse to start without ORIGIN_SECRET (set on EC2)
    WARM_CACHE              1 = load the page's data once in a background thread at startup (set on EC2)
"""

import os
import threading

from waitress import serve

from .app import create_app
from .store import log


def main():
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8080"))
    threads = int(os.environ.get("THREADS", "8"))
    app = create_app()  # raises if REQUIRE_ORIGIN_SECRET=1 and ORIGIN_SECRET is empty
    log("dashboard_start", "ok", host=host, port=port, threads=threads,
        tables=app.extensions["guardian_store"].table_names,
        originCheck=bool(os.environ.get("ORIGIN_SECRET")))  # whether it is on, never the value
    if os.environ.get("WARM_CACHE") == "1":
        threading.Thread(target=app.extensions["guardian_warm_cache"], name="warm-cache", daemon=True).start()
    serve(app, host=host, port=port, threads=threads, ident="guardian-dashboard")


if __name__ == "__main__":
    main()
