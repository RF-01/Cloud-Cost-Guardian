"""Per-thread boto3 clients for the scanner (task #22: regions are scanned in parallel threads).

boto3's default session and resource objects are not thread-safe, so every thread gets its own
boto3.session.Session() and builds its clients from it. All clients are bounded (connect 5 s, read 20 s,
standard retries, 4 attempts) so one slow region can't eat the 5-minute Lambda timeout (design §17).

Memory: every session normally parses the service models (JSON) again; EC2's alone is ~20 MB, so 8 sessions
were ~220 MB of a 256 MB Lambda. All sessions therefore share one botocore data loader (read-only parsed JSON);
sessions, clients and their credentials stay per thread. `preload()` loads the models in the main thread before
the workers start, so workers only read the loader's cache.
"""

import threading

import boto3
import botocore.loaders
import botocore.session
from botocore.config import Config

CONFIG = Config(connect_timeout=5, read_timeout=20, retries={"mode": "standard", "max_attempts": 4})

SERVICES = ("ec2", "cloudwatch", "dynamodb")  # what a region worker uses (preloaded)

_local = threading.local()
_loader = botocore.loaders.create_loader()


def session():
    """This thread's boto3 session (sharing the process-wide data loader)."""
    local = _local
    if not hasattr(local, "session"):
        core = botocore.session.get_session()
        core.register_component("data_loader", _loader)
        local.session = boto3.session.Session(botocore_session=core)
    return local.session


def preload(region):
    """Main thread, before the workers: load the service models into the shared loader."""
    for service in SERVICES:
        session().client(service, region_name=region, config=CONFIG)


def client(service, region):
    return session().client(service, region_name=region, config=CONFIG)


def resource(service, region):
    return session().resource(service, region_name=region, config=CONFIG)


def reset():
    """Forget every thread's session (tests, or after changing env)."""
    global _local
    _local = threading.local()
