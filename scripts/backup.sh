#!/bin/sh
# Automated PostgreSQL backup script for ThreatDock
# Runs from docker-compose db-backup service
# Backups are stored in /backups (host: ./data/backups)

BACKUP_DIR="/backups"
RETENTION_DAYS=30
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
FILENAME="threatdock_${TIMESTAMP}.sql"

# Ensure backup directory exists
mkdir -p "$BACKUP_DIR"

# Run pg_dump
echo "[Backup] Starting PostgreSQL dump..."
pg_dump "postgresql://${PGUSER}:${PGPASSWORD}@postgres:5432/${PGDATABASE}" > "${BACKUP_DIR}/${FILENAME}"

if [ $? -eq 0 ]; then
  gzip -f "${BACKUP_DIR}/${FILENAME}"
  echo "[Backup] Saved: ${FILENAME}.gz ($(du -h "${BACKUP_DIR}/${FILENAME}.gz" | cut -f1))"
else
  echo "[Backup] FAILED!"
  rm -f "${BACKUP_DIR}/${FILENAME}"
  exit 1
fi

# Cleanup old backups
echo "[Backup] Cleaning backups older than ${RETENTION_DAYS} days..."
find "$BACKUP_DIR" -name "threatdock_*.sql.gz" -mtime +${RETENTION_DAYS} -delete
find "$BACKUP_DIR" -name "threatdock_*.sql" -mtime +${RETENTION_DAYS} -delete

echo "[Backup] Complete. Active backups: $(ls ${BACKUP_DIR}/*.gz 2>/dev/null | wc -l)"
