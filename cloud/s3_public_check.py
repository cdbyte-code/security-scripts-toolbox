#!/usr/bin/env python3
"""List S3 buckets and flag ones that may be publicly exposed.
Read-only: uses list/get calls only."""
import sys

import boto3
from botocore.exceptions import ClientError

ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"
AUTH_USERS = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"


def block_public_access_fully_on(s3, bucket):
    try:
        cfg = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            return False
        raise
    keys = ("BlockPublicAcls", "IgnorePublicAcls",
            "BlockPublicPolicy", "RestrictPublicBuckets")
    return all(cfg.get(k, False) for k in keys)


def policy_is_public(s3, bucket):
    try:
        return s3.get_bucket_policy_status(Bucket=bucket)["PolicyStatus"]["IsPublic"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
            return False
        raise


def acl_is_public(s3, bucket):
    grants = s3.get_bucket_acl(Bucket=bucket)["Grants"]
    return any(g.get("Grantee", {}).get("URI") in (ALL_USERS, AUTH_USERS)
               for g in grants)


def main():
    s3 = boto3.client("s3")
    try:
        buckets = [b["Name"] for b in s3.list_buckets()["Buckets"]]
    except ClientError as e:
        sys.exit(f"Cannot list buckets: {e}")

    print(f"{'Bucket':<40} {'Status':<8} Reason")
    found_public = False
    for name in buckets:
        try:
            reasons = []
            if policy_is_public(s3, name):
                reasons.append("bucket policy is public")
            if acl_is_public(s3, name):
                reasons.append("ACL grants public access")
            if reasons:
                status = "PUBLIC"
                found_public = True
            elif not block_public_access_fully_on(s3, name):
                status, reasons = "WARN", ["Block Public Access not fully enabled"]
            else:
                status, reasons = "OK", ["Block Public Access fully on"]
        except ClientError as e:
            status, reasons = "ERROR", [e.response["Error"]["Code"]]
        print(f"{name:<40} {status:<8} {'; '.join(reasons)}")

    print(f"\nChecked {len(buckets)} bucket(s).")
    sys.exit(1 if found_public else 0)


if __name__ == "__main__":
    main()