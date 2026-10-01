import json
import logging
import os
import sys

import boto3
from botocore.exceptions import ClientError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("customer-export-app")


def load_config():
    """Bucket and key are plain, non-secret configuration - they name where
    the ciphertext lives, they aren't the sensitive data itself. They're
    set directly in the task definition's `environment` field (not
    `secrets`), unlike the actual export content."""
    bucket = os.environ.get("EXPORT_BUCKET_NAME")
    key = os.environ.get("EXPORT_OBJECT_KEY")

    missing = [name for name, val in [("EXPORT_BUCKET_NAME", bucket), ("EXPORT_OBJECT_KEY", key)] if not val]
    if missing:
        log.error("[FAIL] Missing required environment variable(s): %s", ", ".join(missing))
        sys.exit(1)

    return bucket, key


def fetch_ciphertext(bucket, key):
    """Download the encrypted export object from S3. The task role needs
    s3:GetObject on this bucket/key for this call to succeed."""
    s3 = boto3.client("s3")
    try:
        response = s3.get_object(Bucket=bucket, Key=key)
        return response["Body"].read()
    except ClientError as exc:
        log.error("[FAIL] Could not fetch s3://%s/%s - %s", bucket, key, exc)
        log.error("[FAIL] Check the task role has s3:GetObject on this bucket/key.")
        sys.exit(1)


def decrypt_export(ciphertext_blob):
    """Decrypt the raw ciphertext bytes via KMS. The task role needs
    kms:Decrypt on the CMK that encrypted this object for this call to
    succeed - no key ID is passed here, since KMS derives which CMK to
    use from metadata embedded in the ciphertext blob itself."""
    kms = boto3.client("kms")
    try:
        response = kms.decrypt(CiphertextBlob=ciphertext_blob)
        return response["Plaintext"]
    except ClientError as exc:
        log.error("[FAIL] KMS decrypt failed - %s", exc)
        log.error("[FAIL] Check the task role has kms:Decrypt on the CMK that encrypted this object.")
        sys.exit(1)


def main():
    log.info("=" * 64)
    log.info("  Customer Data Export - Batch Job Starting")
    log.info("=" * 64)

    bucket, key = load_config()
    log.info("[OK] Config loaded. Source: s3://%s/%s", bucket, key)

    ciphertext_blob = fetch_ciphertext(bucket, key)
    log.info("[OK] Fetched %d bytes of ciphertext from S3.", len(ciphertext_blob))

    plaintext_bytes = decrypt_export(ciphertext_blob)
    log.info("[OK] Successfully decrypted customer export data via KMS!")

    try:
        export_data = json.loads(plaintext_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        log.error("[FAIL] Decrypted data isn't valid JSON - %s", exc)
        sys.exit(1)

    customers = export_data.get("customers", [])
    log.info("[OK] Export contains %d customer record(s).", len(customers))
    if customers:
        log.info("[OK] First record: %s (%s)", customers[0].get("name"), customers[0].get("customer_id"))

    log.info("=" * 64)
    log.info("  Batch job complete. Exiting.")
    log.info("=" * 64)


if __name__ == "__main__":
    main()
