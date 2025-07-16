#!/bin/bash

# Daftar keterangan severity
declare -A SEVERITY_MAP=(
  [0]="Info"
  [1]="Low"
  [2]="Medium"
  [3]="High"
  [4]="Critical"
)

# Cek parameter
if [ "$#" -ne 2 ]; then
  echo "Usage: $0 severity_list file.nessus"
  echo "Contoh: $0 0,1 scan.nessus"
  echo ""
  echo "Severity:"
  echo "  0: Info"
  echo "  1: Low"
  echo "  2: Medium"
  echo "  3: High"
  echo "  4: Critical"
  exit 1
fi

# Ambil parameter severity dan file
IFS=',' read -ra SEVERITIES <<< "$1"
NESSUS_FILE="$2"
OUTPUT_FILE="filtered_$NESSUS_FILE"

# Cek file .nessus
if [ ! -f "$NESSUS_FILE" ]; then
  echo "File $NESSUS_FILE tidak ditemukan!"
  exit 1
fi

# Salin file awal ke output
cp "$NESSUS_FILE" "$OUTPUT_FILE"

# Loop setiap severity dan hapus blok <ReportItem> terkait
for SEV in "${SEVERITIES[@]}"; do
  if [[ ! "$SEV" =~ ^[0-4]$ ]]; then
    echo "Severity $SEV tidak valid. Hanya 0–4 yang diperbolehkan."
    exit 1
  fi

  echo "Menghapus severity $SEV: ${SEVERITY_MAP[$SEV]}"
  perl -0777 -i -pe "s|<ReportItem\b[^>]*?severity=\"$SEV\".*?</ReportItem>\s*||gs" "$OUTPUT_FILE"
done

echo "Selesai. Severity ${SEVERITIES[*]} telah dihapus."
echo "Hasil disimpan di $OUTPUT_FILE"
