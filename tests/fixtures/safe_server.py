"""Fixture MCP-style server that performs the same operations as
vulnerable_server.py but safely, used to prove the scanner doesn't
false-positive on correct code."""
import os
import subprocess
from urllib.parse import urlparse

import requests
import yaml

ALLOWED_ROOT = os.path.realpath("/srv/mcp-data")
ALLOWED_HOSTS = {"api.example.com"}


def run_command(args: list[str]) -> str:
    result = subprocess.run(args, shell=False, capture_output=True)
    return result.stdout.decode()


def read_file(filepath: str) -> str:
    real = os.path.realpath(os.path.join(ALLOWED_ROOT, filepath))
    if os.path.commonpath([real, ALLOWED_ROOT]) != ALLOWED_ROOT:
        raise ValueError("path escapes allowed root")
    with open(real) as fh:
        return fh.read()


def fetch(url: str) -> str:
    if urlparse(url).netloc not in ALLOWED_HOSTS:
        raise ValueError("host not allow-listed")
    return requests.get(url).text


def load_config(text: str):
    return yaml.load(text, Loader=yaml.SafeLoader)
