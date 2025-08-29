#!/usr/bin/env bash
set -euo pipefail

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
TEMP_FILE="$(mktemp)"
trap 'rm -f "$TEMP_FILE"' EXIT

# Ambil baris unik IP:port (abaikan whitespace)
sed 's/^[ \t]*//; s/[ \t]*$//' "$INPUT_FILE" | awk 'NF' | sort -u > "$TEMP_FILE"

declare -A map

# Kumpulkan port per IP
while IFS=: read -r ip port; do
  # Trim spasi
  ip="${ip//[$'\t\r ']/}"
  port="${port//[$'\t\r ']/}"

  # Skip baris tidak valid
  [[ -z "$ip" || -z "$port" ]] && continue
  [[ "$port" =~ ^[0-9]+$ ]] || continue

  # Kumpulkan (akan disortir nanti)
  if [[ -n "${map[$ip]:-}" ]]; then
    map["$ip"]+=",${port}"
  else
    map["$ip"]="${port}"
  fi
done < "$TEMP_FILE"

# Tulis output (header + data)
echo "IP;port" > "$OUTPUT_FILE"

for ip in "${!map[@]}"; do
  # Pecah -> sort numeric unik -> gabung lagi dengan koma
  IFS=',' read -r -a arr <<< "${map[$ip]}"
  # Buang elemen kosong
  arr=("${arr[@]/#/}")
  # Sort & uniq
  sorted_unique_ports="$(printf '%s\n' "${arr[@]}" | awk 'NF' | sort -n -u | paste -sd, -)"
  echo "${ip};${sorted_unique_ports}" >> "$OUTPUT_FILE"
done

echo "Selesai! Hasil disimpan di $OUTPUT_FILE"
