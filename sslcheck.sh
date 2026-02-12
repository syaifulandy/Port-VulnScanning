#!/bin/bash

INPUT_FILE="domains.txt"
OUTPUT_FILE="ssl_report.csv"
PARALLEL=6
TIMEOUT=10

# Hitung total domain (skip kosong)
TOTAL=$(grep -v '^\s*$' "$INPUT_FILE" | wc -l)

# Header CSV
echo "domain;tanggal_expired;status_akhir" > "$OUTPUT_FILE"

# Temp file untuk hasil paralel
TMP_OUT=$(mktemp)

check_domain() {
  domain="$1"

  EXP_DATE=$(
    timeout "$TIMEOUT" openssl s_client \
      -servername "$domain" \
      -connect "$domain:443" </dev/null 2>/dev/null \
    | openssl x509 -noout -enddate 2>/dev/null \
    | cut -d= -f2
  )

  if [[ -z "$EXP_DATE" ]]; then
    echo "$domain;N/A;ERROR"
    return
  fi

  EXP_TS=$(date -d "$EXP_DATE" +%s 2>/dev/null)
  NOW_TS=$(date +%s)

  if [[ -z "$EXP_TS" ]]; then
    echo "$domain;$EXP_DATE;PARSE_ERROR"
    return
  fi

  if [[ "$EXP_TS" -lt "$NOW_TS" ]]; then
    STATUS="EXPIRED"
  else
    STATUS="VALID"
  fi

  echo "$domain;$EXP_DATE;$STATUS"
}

export -f check_domain
export TIMEOUT

echo "[*] Running SSL checks in parallel ($PARALLEL workers)"
echo "[*] Total domains: $TOTAL"
echo "--------------------------------------"

COUNT=0

# Loop domain satu-satu untuk progress, tapi proses tetap paralel via xargs batch
grep -v '^\s*$' "$INPUT_FILE" \
| xargs -P "$PARALLEL" -I {} bash -c 'check_domain "$@"' _ {} \
| while read line; do
    COUNT=$((COUNT+1))

    # Print progress di terminal (overwrite line)
    echo -ne "\rProgress: [$COUNT/$TOTAL] done..."

    # Simpan hasil ke temp file
    echo "$line" >> "$TMP_OUT"
done

echo -e "\n--------------------------------------"
echo "[*] Scan finished, writing output..."

# Gabung header + hasil
cat "$TMP_OUT" >> "$OUTPUT_FILE"
rm -f "$TMP_OUT"

echo "======================================"
echo "Done! Output saved to: $OUTPUT_FILE"
echo "======================================"
