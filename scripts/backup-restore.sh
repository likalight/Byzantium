#!/usr/bin/env bash
# Restore a PostgreSQL backup from S3 or local file.
# Usage: BACKUP_FILE=byzantium_20260701_020000.sql.gz bash scripts/backup-restore.sh

set -euo pipefail

BACKUP_FILE="${BACKUP_FILE:?Set BACKUP_FILE=byzantium_YYYYMMDD_HHMMSS.sql.gz}"
DB_URL="${DATABASE_URL:?Set DATABASE_URL}"
S3_BUCKET="${BACKUP_S3_BUCKET:-}"

echo "WARNING: This will overwrite the current database. Ctrl+C to cancel."
sleep 5

# Download from S3 if not local
if [ ! -f "$BACKUP_FILE" ] && [ -n "$S3_BUCKET" ]; then
    echo "Downloading from s3://${S3_BUCKET}/postgres/${BACKUP_FILE}..."
    aws s3 cp "s3://${S3_BUCKET}/postgres/${BACKUP_FILE}" "/tmp/${BACKUP_FILE}"
    BACKUP_FILE="/tmp/${BACKUP_FILE}"
fi

echo "Restoring from $BACKUP_FILE..."
gunzip -c "$BACKUP_FILE" | psql "$DB_URL"
echo "Restore complete."
