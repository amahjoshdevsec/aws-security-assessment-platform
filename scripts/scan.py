#!/usr/bin/env python3
"""Run one approved account/region scan and publish private evidence to S3."""

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys

from governance import ROOT, exceptions, inventory, read_json, require
from findings import normalize, reconcile


LAB_ACCOUNT = "214745599312"
LAB_REGION = "us-east-1"

EXCLUDED_KMS_ID = "f4f68753-13a6-4d04-8143-6d32fb0480b8"
EXCLUDED_KMS_ARN = (
    f"arn:aws:kms:{LAB_REGION}:{LAB_ACCOUNT}:key/{EXCLUDED_KMS_ID}"
)


def scope_exclusions(account, region):
    if (account, region) != (LAB_ACCOUNT, LAB_REGION):
        return []

    return [
        {
            "service": "glue",
            "reason": "Glue is outside this lab's assessment scope.",
        },
        {
            "service": "kms",
            "resource": EXCLUDED_KMS_ARN,
            "reason": "Legacy EKS key; metadata access unavailable.",
        },
    ]


def expected_kms_error(entry, account, region):
    if (account, region) != (LAB_ACCOUNT, LAB_REGION):
        return False

    if not isinstance(entry, dict):
        return False

    message = entry.get("message")
    if (
        entry.get("level") != "ERROR"
        or entry.get("module") != "kms_service"
        or not isinstance(message, str)
    ):
        return False

    pattern = (
        re.escape(f"{LAB_REGION} -- ClientError:")
        + r"\d+"
        + re.escape(
            " -- An error occurred (AccessDeniedException) when calling "
            "the DescribeKey operation: User: "
            f"arn:aws:sts::{LAB_ACCOUNT}:assumed-role/ProwlerAudit/"
        )
        + r"[A-Za-z0-9_+=,.@-]{1,64}"
        + re.escape(
            " is not authorized to perform: kms:DescribeKey on resource: "
            f"{EXCLUDED_KMS_ARN} because no resource-based policy allows "
            "the kms:DescribeKey action"
        )
    )
    return re.fullmatch(pattern, message) is not None


def run(command, **kwargs):
    return subprocess.run(
        command,
        check=True,
        text=True,
        capture_output=True,
        **kwargs,
    )


def json_file(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def scan_command(account, region, image, output, mutelist, run_id):
    command = [
        "docker",
        "run",
        "--rm",
        "--name",
        f"prowler-{run_id}",
        "--user",
        "1000:1000",
        "--group-add",
        str(os.getgid()),
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "-e",
        "HOME=/tmp",
        "-e",
        "AWS_EC2_METADATA_DISABLED=true",
    ]

    # Values come exclusively from the member session environment supplied to
    # this subprocess; Docker arguments contain variable names, never secrets.
    for name in (
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
    ):
        command.extend(["-e", name])

    command.extend(
        [
            "-v",
            f"{output.resolve()}:/reports",
            "-v",
            f"{mutelist.resolve()}:/config/mutelist.yaml:ro",
            image,
            "aws",
            "--filter-region",
            region,
            "--scan-unused-services",
            "--mutelist-file",
            "/config/mutelist.yaml",
            "--output-formats",
            "csv",
            "json-ocsf",
            "html",
            "--output-directory",
            "/reports",
            "--output-filename",
            "prowler",
            "--log-level",
            "ERROR",
            "--log-file",
            "/reports/errors.log",
            "--only-logs",
            "--no-color",
        ]
    )

    command.extend(["--excluded-checks", "ec2_elastic_ip_shodan"])

    if (account["id"], region) == (LAB_ACCOUNT, LAB_REGION):
        command.extend(["--excluded-services", "glue"])

    return command


def member_environment(account, region, run_id):
    """Assume the audit role on the host; never give tooling credentials to Docker."""
    role = (
        f"arn:aws:iam::{account['id']}:role/security/{account['role_name']}"
    )
    session_name = f"prowler-{run_id}"[:64]

    response = json.loads(
        run(
            [
                "aws",
                "sts",
                "assume-role",
                "--role-arn",
                role,
                "--external-id",
                account["external_id"],
                "--role-session-name",
                session_name,
                "--duration-seconds",
                "3600",
                "--output",
                "json",
            ]
        ).stdout
    )

    credentials = response["Credentials"]
    expected_arn = (
        f"arn:aws:sts::{account['id']}:assumed-role/"
        f"{account['role_name']}/{session_name}"
    )

    require(
        response["AssumedRoleUser"]["Arn"] == expected_arn,
        "Unexpected assumed member role",
    )

    expiry = dt.datetime.fromisoformat(
        credentials["Expiration"].replace("Z", "+00:00")
    )
    require(
        expiry >= dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=45),
        "Member credentials expire too soon for the bounded scan",
    )

    # Do not inherit tooling AWS, GitHub tokens, OIDC URLs, or arbitrary host secrets.
    environment = {
        key: os.environ[key]
        for key in (
            "PATH",
            "HOME",
            "TMPDIR",
            "DOCKER_HOST",
            "DOCKER_CONTEXT",
            "DOCKER_CONFIG",
        )
        if key in os.environ
    }

    for key, source in [
        ("AWS_ACCESS_KEY_ID", "AccessKeyId"),
        ("AWS_SECRET_ACCESS_KEY", "SecretAccessKey"),
        ("AWS_SESSION_TOKEN", "SessionToken"),
    ]:
        require(
            isinstance(credentials[source], str) and credentials[source],
            "Invalid member credentials",
        )
        environment[key] = credentials[source]

    environment.update(
        AWS_REGION=region,
        AWS_DEFAULT_REGION=region,
        AWS_EC2_METADATA_DISABLED="true",
        AWS_CONFIG_FILE=os.devnull,
        AWS_SHARED_CREDENTIALS_FILE=os.devnull,
    )

    identity = json.loads(
        run(
            ["aws", "sts", "get-caller-identity", "--output", "json"],
            env=environment,
        ).stdout
    )
    require(
        identity["Account"] == account["id"]
        and identity["Arn"] == expected_arn,
        "Member session identity does not match approved inventory",
    )

    return environment


def previous_state(bucket, key, path, scope):
    # Prefix-scoped ListBucket permits discovery without needing unrestricted
    # ListBucket just to distinguish GetObject's 403 from a missing first-run key.
    listing = run(
        [
            "aws",
            "s3api",
            "list-objects-v2",
            "--bucket",
            bucket,
            "--prefix",
            key,
            "--max-keys",
            "1",
            "--output",
            "json",
        ]
    )

    objects = json.loads(listing.stdout).get("Contents", [])
    if not any(obj["Key"] == key for obj in objects):
        return {
            "schema_version": 1,
            "scope": scope,
            "findings": {},
        }

    run(
        [
            "aws",
            "s3api",
            "get-object",
            "--bucket",
            bucket,
            "--key",
            key,
            str(path),
        ]
    )
    return read_json(path)


def healthy_output(output, returncode, account=None, region=None):
    require(
        returncode in (0, 3),
        f"Prowler operational failure: exit {returncode}",
    )

    errors = output / "errors.log"
    require(errors.exists(), "Prowler did not create its error log")

    accepted_errors = []

    for line in errors.read_text().splitlines():
        if not line.strip():
            continue

        entry = json.loads(line)
        require(
            expected_kms_error(entry, account, region),
            "Unexpected Prowler error: coverage is incomplete",
        )
        accepted_errors.append(entry)

    for filename in ("prowler.csv", "prowler.ocsf.json", "prowler.html"):
        require(
            (output / filename).is_file()
            and (output / filename).stat().st_size > 0,
            f"Missing or empty expected report: {filename}",
        )

    ocsf = read_json(output / "prowler.ocsf.json")
    require(
        isinstance(ocsf, list) and ocsf,
        "Empty or invalid OCSF findings",
    )

    return accepted_errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()

    require(
        re.fullmatch(r"[A-Za-z0-9_-]{1,48}", args.run_id),
        "Invalid run ID",
    )

    accounts = inventory()
    matches = [
        account
        for account in accounts
        if account["id"] == args.account and account["enabled"]
    ]
    require(
        len(matches) == 1 and args.region in matches[0]["regions"],
        "Account/region is not enabled in inventory",
    )
    account = matches[0]

    compiled = exceptions(ROOT / "config/exceptions.json", accounts)
    image = (ROOT / ".prowler-image").read_text().strip()
    require(
        re.fullmatch(r"prowlercloud/prowler@sha256:[0-9a-f]{64}", image),
        ".prowler-image must contain an approved official image digest",
    )

    bucket = os.environ["REPORT_BUCKET"]
    kms = os.environ["REPORT_KMS_KEY_ARN"]

    require(
        re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket),
        "Invalid report bucket",
    )
    require(
        re.fullmatch(
            r"arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[a-zA-Z0-9-]+",
            kms,
        ),
        "Use the full report KMS key ARN",
    )

    for name in (
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
    ):
        require(
            os.environ.get(name),
            f"Temporary tooling credentials required: {name}",
        )

    scope = f"{args.account}/{args.region}"
    output = ROOT / "reports" / scope / args.run_id
    output.mkdir(parents=True, exist_ok=False)

    # The pinned image keeps /home/prowler private to UID 1000. Grant its
    # supplementary host group access to this directory without world writes.
    output.chmod(0o770)

    mutelist = output / "mutelist.yaml"
    json_file(mutelist, compiled)

    # Preserve the reviewed inputs and provenance with every run.
    for filename in ("accounts.json", "exceptions.json"):
        (output / filename).write_bytes(
            (ROOT / "config" / filename).read_bytes()
        )

    timestamp = dt.datetime.now(dt.timezone.utc).isoformat()
    manifest = {
        "schema_version": 1,
        "scope": scope,
        "run_id": args.run_id,
        "started_at": timestamp,
        "commit": os.environ.get("GITHUB_SHA", "local"),
        "image": image,
        "prowler_version": (ROOT / ".prowler-version").read_text().strip(),
        "workflow_url": os.environ.get("WORKFLOW_URL", ""),
        "status": "failed",
    }

    exclusions = scope_exclusions(args.account, args.region)
    manifest["coverage_exclusions"] = exclusions
    manifest["excluded_checks"] = ["ec2_elastic_ip_shodan"]

    state_key = f"state/{scope}/latest.json"
    evidence_prefix = f"reports/{scope}/{args.run_id}"
    audit_environment = {}

    try:
        previous = previous_state(
            bucket,
            state_key,
            output / "previous-state.json",
            scope,
        )

        # Download outside the credentialed scan's time limit and verify
        # release metadata.
        run(["docker", "pull", image], timeout=300)
        version = run(
            ["docker", "run", "--rm", image, "--version"],
            timeout=60,
        ).stdout

        require(
            re.search(
                r"(?<![\d.])"
                + re.escape(manifest["prowler_version"])
                + r"(?![\d.])",
                version,
            ),
            "Image version does not match .prowler-version",
        )

        audit_environment = member_environment(
            account,
            args.region,
            args.run_id,
        )

        with (output / "scan.log").open("w") as log:
            result = subprocess.run(
                scan_command(
                    account,
                    args.region,
                    image,
                    output,
                    mutelist,
                    args.run_id,
                ),
                stdout=log,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
                timeout=2400,
                env=audit_environment,
            )

        audit_environment.clear()
        manifest["prowler_exit_code"] = result.returncode

        manifest["accepted_collection_errors"] = healthy_output(
            output,
            result.returncode,
            args.account,
            args.region,
        )

        findings = normalize(
            output / "prowler.csv",
            args.account,
            args.region,
            excluded_services=("glue",) if exclusions else (),
            excluded_kms_resources=(
                EXCLUDED_KMS_ARN,
                EXCLUDED_KMS_ID,
            ) if exclusions else (),
        )

        json_file(output / "normalized.json", findings)

        state = reconcile(
            previous,
            findings,
            args.run_id,
            timestamp,
            scope,
        )
        state["coverage_exclusions"] = exclusions
        json_file(output / "state.json", state)

        manifest.update(
            status="complete_with_exclusions" if exclusions else "complete",
            finding_count=len(findings),
            active_failures=sum(
                finding["status"] == "FAIL" and not finding["muted"]
                for finding in findings
            ),
            muted_count=sum(finding["muted"] for finding in findings),
        )

    except (ValueError, OSError, subprocess.SubprocessError) as error:
        # Operational logs remain in encrypted S3; avoid report contents in
        # public Actions logs.
        manifest["error_type"] = type(error).__name__
        manifest["error"] = str(error)
        print(
            f"Scan failed for {scope}: {type(error).__name__}; "
            "inspect private evidence.",
            file=sys.stderr,
        )

    finally:
        audit_environment.clear()

        subprocess.run(
            ["docker", "rm", "-f", f"prowler-{args.run_id}"],
            capture_output=True,
            check=False,
            timeout=30,
        )

        manifest["finished_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
        manifest["sha256"] = {
            str(path.relative_to(output)): hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
            for path in sorted(output.rglob("*"))
            if path.is_file()
        }

        json_file(output / "manifest.json", manifest)

        # No public Actions artifacts. Publish manifest last as evidence
        # completion marker.
        for path in sorted(output.rglob("*")):
            if path.is_file() and path.name != "manifest.json":
                run(
                    [
                        "aws",
                        "s3",
                        "cp",
                        str(path),
                        (
                            f"s3://{bucket}/{evidence_prefix}/"
                            f"{path.relative_to(output)}"
                        ),
                        "--sse",
                        "aws:kms",
                        "--sse-kms-key-id",
                        kms,
                        "--only-show-errors",
                    ]
                )

        run(
            [
                "aws",
                "s3",
                "cp",
                str(output / "manifest.json"),
                f"s3://{bucket}/{evidence_prefix}/manifest.json",
                "--sse",
                "aws:kms",
                "--sse-kms-key-id",
                kms,
                "--only-show-errors",
            ]
        )

    require(
        manifest["status"] in ("complete", "complete_with_exclusions"),
        "Scan incomplete; last successful lifecycle state preserved",
    )

    # Publish state only after all scan evidence is safely uploaded.
    run(
        [
            "aws",
            "s3",
            "cp",
            str(output / "state.json"),
            f"s3://{bucket}/{state_key}",
            "--sse",
            "aws:kms",
            "--sse-kms-key-id",
            kms,
            "--only-show-errors",
        ]
    )

    print(
        f"Assessment {manifest['status']} for {scope}; "
        f"evidence published privately. "
        f"Security failures: {manifest['active_failures']}"
    )


if __name__ == "__main__":
    main()