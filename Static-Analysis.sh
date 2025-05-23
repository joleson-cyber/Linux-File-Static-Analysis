#! /bin/bash

#LOGFILE="analysis_$(date +%d%b%y_%H%M).txt"
#exec > >(tee -i "$LOGFILE")
#exec 2>&1

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

print_separator
echo "Malware - Static Analysis Report for: $FILENAME"
print_separator
echo "File Type:" 
file "$FILENAME" | /bin/awk -F': ' '{print $2}'
print_separator
echo "First 16 Bytes:"
xxd -l 16 "$FILENAME" | /bin/awk -F ': ' '{print $2}'
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
echo "File Entropy:"
ent "$FILENAME" | awk -F'= ' '/bits per byte/{print $2}'
print_separator
echo "First Printable String in File:"
find -maxdepth 1 -type f -name "$(basename "$FILENAME")" -exec sh -c '
    for f; do
        printf "%s\n" "$(strings "$f" | head -n 1)"
    done sh echo
' sh {} +
print_separator
echo "Strings of interest:"
# Common strings found in malware, including indicators of compression, obfuscation,
# suspicious process calls, and known file write or persistence locations.

extract_suspicious_strings() {
    printf "\nStrings of interest:\n"
    local result
    result=$(strings "$FILENAME" 2>/dev/null \
        | grep -Eai 'Copyright|UPX|ASPack|FSG|MEW|Petite|PECompact|Themida|VMProtect|MPRESS|NSPack|Morphine|y0da|EXEcryptor|Enigma|Obsidium|Telock|WWPack32|Packman|PEBundle|kkrunchy|Boomerang|UPack|NeoLite|RLPack|ProCrypt|Crunch|PKLite|Shrinker|DOS|cmd.exe|powershell|wget|curl|Invoke-WebRequest|Base64|Base32|vbs|.bat|MZ|PE|PE32|This program cannot be run in DOS mode|CreateProcess|VirtualAlloc|WriteProcessMemory|GetProcAddress|LoadLibrary|kernel32.dll|user32.dll|ntdll.dll|http://|https://|/tmp|/dev/shm|LD_PRELOAD|cron|crontab|systemd|init.d|rc.local|bash_history|.bashrc|.bash_profile|atd|inittab|.ssh|rc0.d|rc1.d|rc2.d|rc3.d|rc4.d|rc5.d|rc6.d|schtasks|reg add|runonce|RunServices|HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|HKLM\\Software\\Wow6432node\\Microsoft\\Windows\\CurrentVersion\\Run|AppData|Startup' \
        | sort -u \
        | grep -E '.{4,}')  # Filter short strings like 'LPeI'
    
    if [[ -z "$result" ]]; then
        printf "No suspicious strings found.\n"
    else
        printf "%s\n" "$result"
    fi
    print_separator
}
extract_suspicious_strings
#strings "$FILENAME" | egrep -ai "Copyright|UPX|ASPack|FSG|MEW|Petite|PECompact|Themida|VMProtect|MPRESS|NSPack|Morphine|y0da|EXEcryptor|Enigma|Obsidium|Telock|WWPack32|Packman|PEBundle|kkrunchy|Boomerang|UPack|NeoLite|RLPack|ProCrypt|Crunch|PKLite|Shrinker|DOS|cmd.exe|powershell|wget|curl|Invoke-WebRequest|Base64|Base32|vbs|.bat|MZ|PE|PE32|This program cannot be run in DOS mode|CreateProcess|VirtualAlloc|WriteProcessMemory|GetProcAddress|LoadLibrary|kernel32.dll|user32.dll|ntdll.dll|http://|https://|/tmp|/dev/shm|LD_PRELOAD|cron|crontab|systemd|init.d|rc.local|bash_history|.bashrc|.bash_profile|atd|inittab|.ssh|rc0.d|rc1.d|rc2.d|rc3.d|rc4.d|rc5.d|rc6.d|schtasks|reg add|runonce|RunServices|HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|HKLM\\Software\\Wow6432node\\Microsoft\\Windows\\CurrentVersion\\Run|AppData|Startup" | \
#| sort -u \
#| grep -E '.{4,}')  # Filter short strings like 'LPeI'
#print_separator
