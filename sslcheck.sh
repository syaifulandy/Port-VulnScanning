#!/bin/bash

INPUT_FILE="domains.txt"
OUTPUT_FILE="ssl_report.csv"
PARALLEL=2
TIMEOUT=5

# =========================
# PRECHECK
# =========================
if [[ ! -f "$INPUT_FILE" ]]; then
  echo "❌ Error: File '$INPUT_FILE' tidak ditemukan!"
  exit 1
fi

TOTAL=$(grep -v '^\s*$' "$INPUT_FILE" | wc -l)
if [[ "$TOTAL" -eq 0 ]]; then
  echo "❌ Error: File '$INPUT_FILE' kosong!"
  exit 1
fi

START_TIME=$(date +%s)

echo "[*] SSL Checker Started"
echo "[*] Total domains: $TOTAL"
echo "[*] Parallel workers: $PARALLEL"
echo "--------------------------------------"

# Header CSV
echo "domain;tanggal_expired;status_akhir" > "$OUTPUT_FILE"

TMP_OUT=$(mktemp)

# =========================
# FUNCTION CHECK DOMAIN
# =========================
check_domain() {
  domain="$1"

  # Ambil full info cert
  CERT_INFO=$(
    timeout "$TIMEOUT" openssl s_client \
      -servername "$domain" \
      -connect "$domain:443" </dev/null 2>/dev/null
  )

  if [[ -z "$CERT_INFO" ]]; then
    echo "$domain;N/A;ERROR"
    return
  fi

  # Ambil expiry
  EXP_DATE=$(echo "$CERT_INFO" \
    | openssl x509 -noout -enddate 2>/dev/null \
    | cut -d= -f2)

  if [[ -z "$EXP_DATE" ]]; then
    echo "$domain;N/A;ERROR"
    return
  fi

  # Timestamp expiry
  EXP_TS=$(date -d "$EXP_DATE" +%s 2>/dev/null)
  NOW_TS=$(date +%s)

  if [[ -z "$EXP_TS" ]]; then
    echo "$domain;$EXP_DATE;PARSE_ERROR"
    return
  fi

  # Default status
  if [[ "$EXP_TS" -lt "$NOW_TS" ]]; then
    STATUS="EXPIRED"
  else
    STATUS="VALID"
  fi

  # Detect self-signed
  if echo "$CERT_INFO" | grep -qi "self-signed"; then
    if [[ "$STATUS" == "VALID" ]]; then
      STATUS="SELF_SIGNED"
    fi
  fi

  echo "$domain;$EXP_DATE;$STATUS"
}

export -f check_domain
export TIMEOUT

# =========================
# PARALLEL + PROGRESS
# =========================
COUNT=0

grep -v '^\s*$' "$INPUT_FILE" \
| xargs -P "$PARALLEL" -I {} bash -c 'check_domain "$@"' _ {} \
| while read line; do
    COUNT=$((COUNT+1))
    echo -ne "\rProgress: [$COUNT/$TOTAL] checked..."

    echo "$line" >> "$TMP_OUT"
done

echo -e "\n--------------------------------------"

# Save output
cat "$TMP_OUT" >> "$OUTPUT_FILE"
rm -f "$TMP_OUT"

# Timer end
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo "[*] Scan Finished!"
echo "[*] Duration: ${DURATION}s"
echo "======================================"
echo "Output saved to: $OUTPUT_FILE"
echo "======================================"
