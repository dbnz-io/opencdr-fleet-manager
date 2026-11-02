#!/usr/bin/env python3
"""Signed operator client for the fleet API, plus local SSM credential setup."""

from __future__ import annotations

import argparse
import getpass
import json
import re
import sys
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--region", default="us-east-1")
    commands = parser.add_subparsers(dest="command", required=True)
    secret = commands.add_parser(
        "credential", help="create/rotate an agent key in the security account"
    )
    secret.add_argument("--security-account-id", required=True)
    secret.add_argument("--stage", default="prod")
    secret.add_argument("--agent", required=True)
    secret.add_argument("--kind", choices=["read", "write"], default="read")
    request = commands.add_parser(
        "request", help="make an IAM/SigV4 request to this organization’s fleet manager"
    )
    request.add_argument(
        "--url", required=True, help="FleetManagerApiUrl from CloudFormation outputs"
    )
    request.add_argument("method", choices=["GET", "POST", "PUT"])
    request.add_argument("path", help="relative /v1/... path, including optional query")
    request.add_argument("--file", help="JSON body file; use - to read stdin")
    args = parser.parse_args()
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    if args.command == "credential":
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", args.agent) or not re.fullmatch(
            r"[a-z0-9][a-z0-9-]{0,31}", args.stage
        ):
            parser.error("invalid agent or stage name")
        if session.client("sts").get_caller_identity()["Account"] != args.security_account_id:
            parser.error("profile does not match the expected security account")
        value = getpass.getpass("Paste the scoped Core API key (input hidden): ")
        if not value or any(ord(char) < 32 for char in value):
            parser.error("invalid API key")
        name = f"/opencdr-fleet-manager/{args.stage}/agents/{args.agent}/{args.kind}-key"
        session.client("ssm").put_parameter(
            Name=name, Value=value, Type="SecureString", Overwrite=True
        )
        print(f"Stored {name}; the key was not written to the repository or fleet tables.")
        return 0
    url = urlsplit(args.url)
    path = urlsplit(args.path)
    if (
        url.scheme != "https"
        or not url.hostname
        or url.username
        or url.password
        or url.query
        or url.fragment
        or not args.path.startswith("/v1/")
        or path.scheme
        or path.netloc
        or path.fragment
    ):
        parser.error("use an HTTPS fleet URL and a relative /v1/ path")
    raw = None
    if args.file:
        if args.method == "GET":
            parser.error("GET does not accept a body")
        with sys.stdin if args.file == "-" else open(args.file) as source:
            raw = json.dumps(json.load(source), separators=(",", ":")).encode()
    credentials = session.get_credentials()
    if credentials is None:
        parser.error("AWS credentials unavailable; sign in to the selected profile")
    full_url = args.url.rstrip("/") + args.path
    request = AWSRequest(
        method=args.method, url=full_url, data=raw, headers={"Content-Type": "application/json"}
    )
    SigV4Auth(credentials.get_frozen_credentials(), "execute-api", args.region).add_auth(request)
    prepared = request.prepare()
    req = Request(prepared.url, data=raw, method=args.method, headers=dict(prepared.headers))
    try:
        with build_opener(NoRedirect()).open(req, timeout=28) as response:
            value = json.loads(response.read())
            print(json.dumps(value, indent=2))
            if isinstance(value, dict) and any(
                row.get("error_code") or not 200 <= row.get("status_code", 500) < 300
                for row in value.get("results", [])
            ):
                return 1
        return 0
    except HTTPError as error:
        print(f"HTTP {error.code}: {error.read().decode(errors='replace')}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
