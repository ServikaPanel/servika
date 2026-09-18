#!/usr/bin/env bash
# config-check — static configuration gate. It needs no database and no server.
#
# It answers three questions that every other gate takes for granted:
#
#   (a) Does every workflow and every checked-in JSON file still parse? A broken
#       workflow does not fail a job, it silently stops scheduling one, and a
#       broken package.json or tsconfig.json fails much later with a message
#       about something else.
#   (b) Are the migration file names unambiguous? dbmigrate applies them in name
#       order, so two files sharing a number have no defined order between them
#       and a file with no NNNN_ prefix sorts wherever its first character puts
#       it. Both are refused here. A GAP in the numbering is reported and does
#       not fail: a number withdrawn before release leaves one for ever.
#   (c) Do go.mod and go.sum still agree with the module cache?
#
# Exit codes: 0 clean (warnings allowed), 1 a real defect, 2 the check itself
# could not run.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2

FAIL=0
WARN=0
GO="${GO:-go}"

PY=python3
command -v "$PY" >/dev/null 2>&1 || PY=python
command -v "$PY" >/dev/null 2>&1 || {
  echo "config-check: no python interpreter, and one is needed to parse YAML"
  exit 2
}

# parse_file <yaml|json|jsonc> <path> — prints the parser error on failure.
parse_file() {
  "$PY" - "$1" "$2" <<'PY'
import json, re, sys

mode, path = sys.argv[1], sys.argv[2]
raw = open(path, 'rb').read().decode('utf-8', 'replace')

if mode == 'yaml':
    import yaml
    yaml.safe_load(raw)
elif mode == 'json':
    json.loads(raw)
elif mode == 'jsonc':
    # tsconfig.json is JSON with comments. Try strict JSON first so a real
    # syntax error is still reported, then strip comments and trailing commas.
    try:
        json.loads(raw)
    except ValueError:
        out, i, n, quote, escaped = [], 0, len(raw), '', False
        while i < n:
            c = raw[i]
            if quote:
                out.append(c)
                if escaped:
                    escaped = False
                elif c == '\\':
                    escaped = True
                elif c == quote:
                    quote = ''
                i += 1
                continue
            if c in '"\'':
                quote = c
                out.append(c)
                i += 1
                continue
            if c == '/' and i + 1 < n and raw[i + 1] == '/':
                i += 2
                while i < n and raw[i] not in '\r\n':
                    i += 1
                continue
            if c == '/' and i + 1 < n and raw[i + 1] == '*':
                i += 2
                while i + 1 < n and not (raw[i] == '*' and raw[i + 1] == '/'):
                    i += 1
                i += 2
                continue
            out.append(c)
            i += 1
        json.loads(re.sub(r',(\s*[}\]])', r'\1', ''.join(out)))
else:
    print('unknown mode: %s' % mode)
    sys.exit(2)
PY
}

# check_file <mode> <label> <path> <required 0|1>
check_file() {
  local mode="$1" label="$2" path="$3" required="$4" err
  if [ ! -f "$path" ]; then
    if [ "$required" = 1 ]; then
      echo "  FAIL $label: the file is missing ($path)"
      FAIL=1
    else
      echo "  skip $label: not present"
    fi
    return
  fi
  if err="$(parse_file "$mode" "$path" 2>&1)"; then
    echo "  ok   $label"
  else
    echo "  FAIL $label: does not parse"
    printf '%s\n' "$err" | head -3 | sed 's/^/         /'
    FAIL=1
  fi
}

echo "[config-check] (a) workflows and checked-in configuration parse"
"$PY" -c 'import yaml' 2>/dev/null || {
  echo "  FAIL pyyaml is not installed, so no workflow could be parsed"
  exit 2
}
for workflow in .github/workflows/*.yml; do
  [ -e "$workflow" ] || continue
  check_file yaml "$workflow" "$workflow" 1
done
check_file json  "version.json"             "version.json"             1
check_file json  "frontend/package.json"    "frontend/package.json"    1
check_file jsonc "frontend/tsconfig.json"   "frontend/tsconfig.json"   1
check_file jsonc "tsconfig.json"            "tsconfig.json"            0

echo "[config-check] (b) migration file names are unambiguous"
report="$("$PY" - <<'PY'
import glob, os, re

numbers = {}
unnamed = []
for path in sorted(glob.glob(os.path.join('migrations', '*.sql'))):
    name = os.path.basename(path)
    match = re.match(r'^(\d{4})_', name)
    if not match:
        unnamed.append(name)
        continue
    numbers.setdefault(int(match.group(1)), []).append(name)

if not numbers and not unnamed:
    print('EMPTY')
    raise SystemExit

low, high = min(numbers), max(numbers)
print('INFO %04d..%04d (%d files, %d distinct numbers)'
      % (low, high, sum(len(v) for v in numbers.values()), len(numbers)))
for name in unnamed:
    print('BADNAME %s' % name)
for number in sorted(numbers):
    if len(numbers[number]) > 1:
        print('DUPLICATE %04d -> %s' % (number, ', '.join(numbers[number])))
gaps = [n for n in range(low, high + 1) if n not in numbers]
if gaps:
    print('GAP ' + ', '.join('%04d' % n for n in gaps))
PY
)"
printf '%s\n' "$report" | while IFS= read -r line; do
  case "$line" in
    INFO*)      echo "  ok   ${line#INFO }" ;;
    DUPLICATE*) echo "  FAIL two files share a number: ${line#DUPLICATE }" ;;
    BADNAME*)   echo "  FAIL no NNNN_ prefix, so its apply order is undefined: ${line#BADNAME }" ;;
    GAP*)       echo "  warn a number is unused: ${line#GAP }" ;;
    EMPTY)      echo "  FAIL migrations/ holds no .sql file" ;;
  esac
done
if printf '%s\n' "$report" | grep -qE '^(DUPLICATE|BADNAME|EMPTY)'; then FAIL=1; fi
if printf '%s\n' "$report" | grep -q '^GAP'; then WARN=1; fi

echo "[config-check] (c) go.mod and go.sum agree with the module cache"
if command -v "$GO" >/dev/null 2>&1; then
  if out="$("$GO" mod verify 2>&1)"; then
    echo "  ok   $out"
  else
    echo "  FAIL go mod verify"
    printf '%s\n' "$out" | head -5 | sed 's/^/         /'
    FAIL=1
  fi
else
  echo "  FAIL '$GO' is not on PATH"
  FAIL=1
fi

echo
if [ "$FAIL" != 0 ]; then
  echo "[config-check] FAILED"
  exit 1
fi
if [ "$WARN" != 0 ]; then
  echo "[config-check] passed with warnings"
  exit 0
fi
echo "[config-check] clean"
exit 0
