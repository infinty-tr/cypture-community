#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
DB="data/cypture.db"

pkill -x cypture 2>/dev/null || true
sleep 1

echo "=== before ==="
sqlite3 "$DB" "select 'users',count(*) from users union all select 'scans',count(*) from scan_sessions union all select 'findings',count(*) from findings;"

sqlite3 "$DB" <<'SQL'
DELETE FROM findings;
DELETE FROM log_events;
DELETE FROM questions;
DELETE FROM scan_sessions;
DELETE FROM engagements;
DELETE FROM auth_sessions;
DELETE FROM audit_logs;
DELETE FROM users WHERE role <> 'admin';
VACUUM;
SQL

echo "=== after (admin only) ==="
sqlite3 -header -column "$DB" "select email,role from users;"
sqlite3 "$DB" "select 'engagements',count(*) from engagements union all select 'scans',count(*) from scan_sessions union all select 'findings',count(*) from findings;"
echo "RESET DONE"
