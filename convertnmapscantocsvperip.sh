#!/bin/bash
# perlu install xmlstarlet: sudo apt install xmlstarlet
# Input: file XML hasil Nmap

INPUT="$1"

if [[ -z "$INPUT" ]]; then
    echo "Penggunaan: $0 <nama_file_nmap.xml>"
    exit 1
fi

if [[ ! -f "$INPUT" ]]; then
    echo "File tidak ditemukan: $INPUT"
    exit 1
fi

# Ambil nama file tanpa ekstensi
BASENAME=$(basename "$INPUT" .xml)
OUTPUT="output_parsing_${BASENAME}.csv"

# Jalankan parsing dan simpan ke file output
xmlstarlet sel -t -m '//host' \
  -i 'count(ports/port[state/@state="open"]) > 0' \
    -v 'address[@addrtype="ipv4"]/@addr' -o ';' \
    -m 'ports/port[state/@state="open"]' -v '@portid' -o ',' \
  -b -n "$INPUT" | sed 's/,\+$//' > "$OUTPUT"

echo "[+] Output disimpan ke: $OUTPUT"

