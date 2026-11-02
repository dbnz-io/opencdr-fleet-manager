#!/usr/bin/env python3
"""Account-checked deployment entry point; CloudFormation is managed by Serverless."""

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

import boto3

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, help="AWS profile for the security account")
    parser.add_argument("--security-account-id", required=True)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--stage", default="prod")
    parser.add_argument("--security-profile", choices=["standard", "hardened"], default="standard")
    parser.add_argument("--allowed-agent-hosts", default="")
    parser.add_argument("--snapshot-retention-hours", type=int, default=24)
    parser.add_argument("--pause-polling", action="store_true")
    parser.add_argument("--package-only", action="store_true")
    args = parser.parse_args()
    if not re.fullmatch(r"\d{12}", args.security_account_id):
        parser.error("--security-account-id must contain 12 digits")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", args.stage):
        parser.error("--stage must be a lowercase name, up to 32 characters")
    if not 2 <= args.snapshot_retention_hours <= 168:
        parser.error("snapshot retention must be 2–168 hours")
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    actual = session.client("sts").get_caller_identity()["Account"]
    if actual != args.security_account_id:
        parser.error("AWS profile is not authenticated to the expected security account")
    subprocess.run([sys.executable, str(ROOT / "scripts/package.py")], cwd=ROOT, check=True)
    env = {**os.environ, "AWS_PROFILE": args.profile, "SECURITY_ACCOUNT_ID": actual}
    common = [
        "--stage",
        args.stage,
        "--region",
        args.region,
        f"--param=securityProfile={args.security_profile}",
        f"--param=snapshotRetentionHours={args.snapshot_retention_hours}",
        f"--param=allowedAgentHosts={args.allowed_agent_hosts}",
        f"--param=pollingEnabled={str(not args.pause_polling).lower()}",
    ]
    executable = str(ROOT / "node_modules/.bin/serverless")
    subprocess.run([executable, "package", *common], cwd=ROOT, env=env, check=True)
    if not args.package_only:
        # Deploy the exact package just compiled, not a rebuild.
        subprocess.run(
            [
                executable,
                "deploy",
                "--package",
                ".serverless",
                *common,
            ],
            cwd=ROOT,
            env=env,
            check=True,
        )


if __name__ == "__main__":
    main()
