#! /bin/bash
# Check if a filename was provided
if [ -z "$1" ]; then
    echo "Usage: $0 < filename>"
    exit 1
fi

FILENAME="$1"
echo "------------------------------"
echo "File Type:" 
file "$FILENAME" | awk -F': ' '{print $2}'
echo "------------------------------"
echo "First 16 Bytes:"
xxd -1 16 "$FILENAME" | awk -F ': ' '{print $2}'
echo "------------------------------"
echo "SHA256 Hash:"
sha256sum "SFILENAME" | awk -F' ' '(print S1}'
echo "------------------------------"
echo "File Entropy:
ent "$FILENAME" | awk -F'= ' '/bits per byte/{print $2}'
echo "------------------------------"
echo "First String in File:
find -maxdepth 1 -type f -name "$(basename "$FILENAME")" -exec sh -c '
    for f; do
        printf "%s\n" "$(strings "$f" | head -n 1)"
    done sh echo
' sh {} +
echo "------------------------------"
echo "Copyright Strings:"
strings "$FILENAME" | egrep "Copyright"
echo "------------------------------"
echo "UPX Strings:"
strings "$FILENAME" | egrep "UPX"
echo "------------------------------"
