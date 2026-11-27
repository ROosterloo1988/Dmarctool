#!/bin/sh
# Daily pg_dump of the dmarc database into /backups, keeping BACKUP_KEEP_DAYS days.
set -eu
: "${BACKUP_HOUR_UTC:=2}"
: "${BACKUP_KEEP_DAYS:=14}"
export PGPASSWORD="$POSTGRES_PASSWORD"

backup() {
  ts=$(date -u +%Y%m%dT%H%M%SZ)
  tmp="/backups/.dmarc-$ts.dump.partial"
  if pg_dump -h "${PGHOST:-db}" -U dmarc -d "${PGDATABASE:-dmarc}" -Fc -f "$tmp"; then
    mv "$tmp" "/backups/dmarc-$ts.dump"
    echo "$(date -u) backup written: dmarc-$ts.dump"
    find /backups -name 'dmarc-*.dump' -mtime +"$BACKUP_KEEP_DAYS" -print -delete
  else
    rm -f "$tmp"
    echo "$(date -u) BACKUP FAILED" >&2
  fi
}

[ "${1:-}" = "now" ] && { backup; exit 0; }

last=""
while true; do
  today=$(date -u +%Y-%m-%d)
  hour=$(date -u +%H)
  if [ "$last" != "$today" ] && [ "${hour#0}" -ge "$BACKUP_HOUR_UTC" ] 2>/dev/null; then
    backup && last="$today"
  fi
  sleep 300
done
