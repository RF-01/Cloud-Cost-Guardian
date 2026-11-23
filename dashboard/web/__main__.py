"""Entry point: `python -m dashboard.web` (from the repo root).

Environment:
    NAME_PREFIX   table names = <prefix><name>, e.g. cg-dev- (each TABLE_* variable overrides one table)
    PORT          default 8080
    HOST          default 127.0.0.1 (the EC2 service in #38 sets 0.0.0.0)
    AWS_REGION    default us-west-2
    THREADS       waitress worker threads, default 8
"""

import os

from waitress import serve

from .app import create_app
from .store import log


def main():
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8080"))
    threads = int(os.environ.get("THREADS", "8"))
    app = create_app()
    log("dashboard_start", "ok", host=host, port=port, threads=threads,
        tables=app.extensions["guardian_store"].table_names)
    serve(app, host=host, port=port, threads=threads, ident="guardian-dashboard")


if __name__ == "__main__":
    main()
