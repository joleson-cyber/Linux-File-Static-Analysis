#! /bin/bash

#Print content to terminal & Ouput to a file in current directory
LOGFILE="static-Analysis_$(date +%d%b%y_%H%M).txt" #./static-Analysis_24May25_1001.txt
exec > >(tee -i "$LOGFILE")
exec 2>&1

# Automated malware triage script
# Usage:  ./static-analysis.sh <filename>

# Check if a filename was provided
if [ -z "$1" ]; then
    echo "Usage: $0 < filename>"
    exit 1
fi

FILENAME="$1"

print_separator() {
    echo #Print a new line
    printf '%*s\n' "$(tput cols)" '' | tr ' ' '-'
}

echo "Malware - Static Analysis Report for: $FILENAME"
echo -e "\nOutput saved to:  ./$LOGFILE"

print_separator
echo "File Type:"
file "$FILENAME" | /bin/awk -F': ' '{print $2}'

print_separator
echo "First 16 Bytes:"
xxd -l 16 "$FILENAME" | /bin/awk -F ': ' '{print $2}'

print_separator
echo "File Entropy:"
ent "$FILENAME" | awk -F'= ' '/bits per byte/{print $2}'

print_separator
echo "Hash of File:"
MD5=$(md5sum "$FILENAME" | cut -d ' ' -f1)
SHA1=$(sha1sum "$FILENAME" | cut -d ' ' -f1)
SHA256=$(sha256sum "$FILENAME" | cut -d ' ' -f1)
echo -e "MD5:\t$MD5\nSHA1:\t$SHA1\nSHA256:\t$SHA256\n"
#VirusTotal Test:
#https://www.virustotal.com/gui/file/3e26204eba90ebf94001773952658942d68746d5bf54ec9dbae52ddb9087e51b
echo -e " *** See VirusTotal Results ***\nhttps://www.virustotal.com/gui/file/$SHA256"

print_separator
echo "First Printable String in File:"
find . -maxdepth 1 -type f -name "$(basename "$FILENAME")" -exec sh -c '
    for f in "$@"; do
        printf "%s\n" "$(strings "$f" | head -n 1)"
    done
' _ {} +
print_separator

extract_suspicious_strings() {
# Common strings found in malware, including indicators of compression, obfuscation,
# suspicious process calls, and known file write or persistence locations.
    printf "Strings of Interest with Line Number:\n"

    # Case-insensitive matches
    mapfile -t CI_MATCHES < <(strings "$FILENAME" 2>/dev/null \
        | grep -Enai 'copyright|upx|aspack|fsg|mew|petite|pecompact|themida|vmprotect|mpress|nspack|morphine|y0da|execryptor|enigma|obsidium|telock|wwpack32|packman|pebundle|kkrunchy|boomerang|upack|neolite|rlpack|procrypt|crunch|pklite|shrinker|dos|cmd\.exe|powershell|wget|curl|invoke-webrequest|base64|base32|vbs|\.bat|http://|https://|/tmp|/dev/shm|ld_preload|cron|crontab|systemd|init\.d|rc\.local|bash_history|\.bashrc|\.bash_profile|atd|inittab|\.ssh|rc[0-6]\.d|schtasks|reg add|runonce|runservices|hklm\\software\\microsoft\\windows\\currentversion\\run|hkcu\\software\\microsoft\\windows\\currentversion\\run|hklm\\software\\wow6432node\\microsoft\\windows\\currentversion\\run|appdata|startup')

    # Create map of CI line numbers
    declare -A CI_LINE_MAP
    for line in "${CI_MATCHES[@]}"; do
        line_num="${line%%:*}"
        CI_LINE_MAP["$line_num"]=1
    done

    # Case-sensitive matches
    mapfile -t CS_MATCHES_RAW < <(strings "$FILENAME" 2>/dev/null \
      | grep -Ena 'ELF|MZ|PE|PE32|This program cannot be run in DOS mode|CreateProcess|VirtualAlloc|WriteProcessMemory|GetProcAddress|LoadLibrary|kernel32\.dll|user32\.dll|ntdll\.dll')

    # Filter out duplicate line numbers from CS
    CS_MATCHES=()
    for line in "${CS_MATCHES_RAW[@]}"; do
        line_num="${line%%:*}"
        if [[ -z "${CI_LINE_MAP[$line_num]}" ]]; then
            CS_MATCHES+=("$line")
        fi
    done

    # Merge and sort unique by line number
    ALL_MATCHES=("${CI_MATCHES[@]}" "${CS_MATCHES[@]}")
    printf '%s\n' "${ALL_MATCHES[@]}" \
      | sort -n -t: -k1,1 \
      | awk -F: '!seen[$1]++ { printf "%s:\t%s\n", $1, substr($0, index($0, $2)) }'
}

extract_suspicious_strings
