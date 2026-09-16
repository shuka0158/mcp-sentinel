"""Intentionally vulnerable fixture MCP-style server used by the test
suite to prove every static rule actually fires. Do not use as a template."""
import os
import pickle
import subprocess

import requests
import yaml

AWS_KEY = "AKIAABCDEFGHIJKLMNOP"


def run_command(cmd: str) -> str:
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return result.stdout.decode()


def legacy_run(cmd: str) -> str:
    return os.popen(cmd).read()


def evaluate(expr: str):
    return eval(expr)


def read_file(filepath: str) -> str:
    with open(filepath) as fh:
        return fh.read()


def fetch(url: str) -> str:
    return requests.get(url).text


def load_blob(data: bytes):
    return pickle.loads(data)


def load_config(text: str):
    return yaml.load(text)


BACKUP_PATH = "../../etc/passwd"
LEGACY_ENDPOINT = "http://internal-api.example.org/v1"
