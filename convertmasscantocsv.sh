#!/bin/bash

# === Validasi argumen ===
if [[ $# -ne 1 ]]; then
  echo "Usage: $0 /path/to/ip_port.txt"
  exit 1
fi

INPUT_FILE="$1"

if [[ ! -f "$INPUT_FILE" ]]; then
  echo "File tidak ditemukan: $INPUT_FILE"
  exit 2
fi

OUTPUT_FILE="output.csv"

# === Proses konversi IP:port -> IP;port1,port2 ===
echo "IP;port" > "$OUTPUT_FILE"


INPUT_FILE="$1"
TEMP_FILE=$(mktemp)

# Sort dan ambil hanya baris unik (IP:port)
sort "$INPUT_FILE" | uniq > "$TEMP_FILE"


awk -F: '
{
  ip = $1
  port = $2
  # Bersihkan whitespace
  gsub(/^[ \t]+|[ \t]+$/, "", ip)
  gsub(/^[ \t]+|[ \t]+$/, "", port)

  # Hanya proses jika port angka saja
  if (ip != "" && port ~ /^[0-9]+$/) {
    data[ip] = (ip in data) ? data[ip] "," port : port
  }
}
END {
  for (ip in data) {
    print ip ";" data[ip]
  }
}
' "$TEMP_FILE" | sed 's/;,/;/' > "$OUTPUT_FILE"

rm -f "$TEMP_FILE"

echo "Selesai! Hasil disimpan di $OUTPUT_FILE"
