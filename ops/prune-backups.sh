#!/usr/bin/env bash
#
# Retention for LOCAL backups (grandfather-father-son), by the timestamp in the
# file name, not by file dates that a copy or restore can change:
#
#   keep the newest backup of each of the last  BACKUP_KEEP_DAILY   (14) days that have one
#   keep the newest backup of each of the last  BACKUP_KEEP_WEEKLY  (8)  ISO weeks
#   keep the newest backup of each of the last  BACKUP_KEEP_MONTHLY (12) months
#   and ALWAYS the newest BACKUP_MIN_KEEP (3) files, whatever the rules say.
#
#   ops/prune-backups.sh <dir> [--dry-run]
#
# Off-server retention belongs to the storage (S3 lifecycle rules, RECOVERY.md).
set -euo pipefail
DIR="${1:?usage: prune-backups.sh <dir> [--dry-run]}"
[[ -d "$DIR" ]] || { echo "not a directory: $DIR" >&2; exit 2; }
DRY=0; [[ "${2:-}" == "--dry-run" ]] && DRY=1
KD="${BACKUP_KEEP_DAILY:-14}"; KW="${BACKUP_KEEP_WEEKLY:-8}"; KM="${BACKUP_KEEP_MONTHLY:-12}"; MIN="${BACKUP_MIN_KEEP:-3}"
for v in "$KD" "$KW" "$KM" "$MIN"; do [[ "$v" =~ ^[0-9]+$ ]] || { echo "retention settings must be whole numbers" >&2; exit 2; }; done

# Newest first: legion-YYYYMMDDTHHMMSSZ.dump[.age]
mapfile -t FILES < <(find "$DIR" -maxdepth 1 -type f \( -name 'legion-*.dump' -o -name 'legion-*.dump.age' \) -printf '%f\n' | { grep -E '^legion-[0-9]{8}T[0-9]{6}Z\.dump(\.age)?$' || true; } | sort -r)
declare -A KEEP=() SEEN_D=() SEEN_W=() SEEN_M=()
nd=0; nw=0; nm=0; i=0
for f in "${FILES[@]}"; do
  stamp="${f#legion-}"; stamp="${stamp%%.*}"; day="${stamp:0:8}"
  iso="${day:0:4}-${day:4:2}-${day:6:2}"
  week="$(date -u -d "$iso" +%G-W%V)"; month="${day:0:6}"
  (( i < MIN )) && KEEP[$f]="newest"
  if [[ -z "${SEEN_D[$day]:-}" ]] && (( nd < KD )); then SEEN_D[$day]=1; nd=$((nd+1)); KEEP[$f]="daily"; fi
  if [[ -z "${SEEN_W[$week]:-}" ]] && (( nw < KW )); then SEEN_W[$week]=1; nw=$((nw+1)); KEEP[$f]="${KEEP[$f]:-weekly}"; fi
  if [[ -z "${SEEN_M[$month]:-}" ]] && (( nm < KM )); then SEEN_M[$month]=1; nm=$((nm+1)); KEEP[$f]="${KEEP[$f]:-monthly}"; fi
  i=$((i+1))
done
removed=0
for f in "${FILES[@]}"; do
  [[ -n "${KEEP[$f]:-}" ]] && continue
  if (( DRY )); then
    echo "would remove $f"
  else
    rm -f "${DIR:?}/${f:?}" "${DIR:?}/${f:?}.sha256"
    echo "removed old backup: $f"
  fi
  removed=$((removed+1))
done
# Interrupted runs leave scratch behind; it holds a plaintext dump, so do not let it linger.
find "$DIR" -maxdepth 1 \( -name '.work.*' -o -name '*.partial' \) -mmin +240 -exec rm -rf {} + 2>/dev/null || true
echo "kept $(( ${#FILES[@]} - removed )) of ${#FILES[@]} backups"
