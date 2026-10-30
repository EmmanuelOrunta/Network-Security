#!/bin/sh
# =====================================================================
#  ITEC624 Assessment 2 - Host-based Intrusion Detection System (HIDS)
#  File-integrity monitor written for the Bourne shell (sh / dash)
#
#  Authors : Emmanuel Orunta (S00403657), Utsav Bhandari (S00403656)
#  Date    : October 2026
#
#  Usage   : ./ids.sh -c NAME              create verification file NAME
#            ./ids.sh -o NAME [BASELINE]   re-scan, compare with BASELINE,
#                                          show results and save them to NAME
#            ./ids.sh                      no options: interactive C/O menu
# =====================================================================

# ---------------------------------------------------------------------
# 1. CONFIGURATION - change these values here, not further down.
#    Each can also be overridden from the environment, e.g.
#    MONITOR_DIR=/srv/data ./ids.sh -c VERI1
# ---------------------------------------------------------------------
MONITOR_DIR="${MONITOR_DIR:-$HOME/itec624/Test}"     # folder being watched
DATA_DIR="${DATA_DIR:-$HOME/itec624/ids_data}"       # IDS files live here, OUTSIDE the watched folder
HASH_CMD="${HASH_CMD:-md5sum}"                       # swap to sha256sum for a stronger hash
DEFAULT_BASELINE="${DEFAULT_BASELINE:-VERI1}"        # baseline used by -o when none is given
NEW_SCAN_NAME="${NEW_SCAN_NAME:-VERI2}"              # verification file made during -o
SEP='|'                                              # field separator (safe for names with spaces)

# ---------------------------------------------------------------------
# 2. HELPER FUNCTIONS
# ---------------------------------------------------------------------

# usage: print how to run the script, then stop with an error code
usage() {
    echo "Usage: $0 -c NAME | -o NAME [BASELINE]" >&2
    echo "       $0            (interactive menu)" >&2
    exit 2
}

# report MESSAGE: show a line on screen AND append it to the output file
report() {
    echo "$1"
    echo "$1" >> "$OUTPUT_FILE"
}

# file_type PATH: print the type as the brief requires
# (regular file / directory / symlink)
file_type() {
    case "$(stat -c %F "$1")" in
        "regular file"|"regular empty file") echo "regular file" ;;
        "directory")                         echo "directory" ;;
        "symbolic link")                     echo "symlink" ;;
        *)                                   echo "other" ;;
    esac
}

# file_hash PATH TYPE: print the hash of a regular file, or "-" for
# anything else (directories and symlinks have no contents to hash)
file_hash() {
    if [ "$2" = "regular file" ]; then
        $HASH_CMD "$1" | awk '{print $1}'
    else
        echo "-"
    fi
}



# field_name N: human-readable name of field N in a verification record
field_name() {
    case "$1" in
        2) echo "file type" ;;
        3) echo "access mode" ;;
        4) echo "owner id" ;;
        5) echo "group id" ;;
        6) echo "last modification time" ;;
        7) echo "last status change time" ;;
        8) echo "hash" ;;
    esac
}

# get_field RECORD N: print field N of a verification record
get_field() {
    echo "$1" | awk -F"$SEP" -v n="$2" '{print $n}'
}

# ---------------------------------------------------------------------
# 3. BASELINE MODULE - collect attributes into a verification file
# ---------------------------------------------------------------------

# collect FILE: scan MONITOR_DIR and write one record per path to FILE:
# path|type|mode|uid|gid|mtime|ctime|hash
# Only READS inside MONITOR_DIR, so no timestamps there are changed.
collect() {
    out="$1"
    temp="$DATA_DIR/temp"                     # temp file kept OUTSIDE the watched folder
    find "$MONITOR_DIR" | sort > "$temp"      # step 1: list every path (recursive)
    : > "$out"                                # start with an empty verification file
    while IFS= read -r path; do               # step 2: read the list line by line
        type=$(file_type "$path")
        attrs=$(stat -c "%A$SEP%u$SEP%g$SEP%Y$SEP%Z" "$path")
        hash=$(file_hash "$path" "$type")
        echo "$path$SEP$type$SEP$attrs$SEP$hash" >> "$out"
    done < "$temp"
    rm -f "$temp"
}

# create_mode NAME: option C - build the baseline verification file
create_mode() {
    rm -f "$DATA_DIR/$1"                      # remove an old read-only copy first
    collect "$DATA_DIR/$1"
    chmod 400 "$DATA_DIR/$1"                  # read-only, to discourage tampering
    echo "File created: $DATA_DIR/$1 ($(wc -l < "$DATA_DIR/$1") entries)"
}

# ---------------------------------------------------------------------
# 4. DETECTION MODULE - compare two verification files
# ---------------------------------------------------------------------

# compare OLD NEW: report modified, deleted and created entries
compare() {
    old="$1"; new="$2"
    modified=0; deleted=0; created=0

    # Pass 1 - loop 1 over the baseline, loop 2 over the new scan
    while IFS= read -r line1; do
        var1=$(get_field "$line1" 1)
        found=0                                    # reset flag for every baseline entry
        while IFS= read -r line2; do
            var2=$(get_field "$line2" 1)
            if [ "$var1" = "$var2" ]; then         # same path in both scans
                found=1
                if [ "$line1" != "$line2" ]; then  # something about it changed
                    modified=$((modified + 1))
                    report "[MODIFIED] $var1"
                    for n in 2 3 4 5 6 7 8; do     # compare field by field
                        a=$(get_field "$line1" "$n")
                        b=$(get_field "$line2" "$n")
                        if [ "$a" != "$b" ]; then
                            if [ "$n" -eq 6 ] || [ "$n" -eq 7 ]; then   # show times as dates
                                a=$(date -d "@$a" '+%Y-%m-%d %H:%M:%S')
                                b=$(date -d "@$b" '+%Y-%m-%d %H:%M:%S')
                            fi
                            report "           $(field_name "$n"): $a -> $b"
                        fi
                    done
                fi
                break                              # match found: stop loop 2
            fi
        done < "$new"
        if [ "$found" -eq 0 ]; then                # no match anywhere in the new scan
            deleted=$((deleted + 1))
            report "[DELETED]  $var1"
        fi
    done < "$old"

    # Pass 2 - anything in the new scan that is not in the baseline
    while IFS= read -r line1; do
        var1=$(get_field "$line1" 1)
        found=0
        while IFS= read -r line2; do
            if [ "$var1" = "$(get_field "$line2" 1)" ]; then
                found=1
                break
            fi
        done < "$old"
        if [ "$found" -eq 0 ]; then
            created=$((created + 1))
            report "[CREATED]  $var1"
        fi
    done < "$new"

    report "----------------------------------------------------------"
    report "Summary: $modified modified, $deleted deleted, $created created"
}

# output_mode NAME BASELINE: option O - rescan, compare, save the results
output_mode() {
    OUTPUT_FILE="$DATA_DIR/$1"
    baseline="$DATA_DIR/$2"
    if [ ! -f "$baseline" ]; then
        echo "Error: baseline '$baseline' not found. Run with -c first." >&2
        exit 1
    fi
    newscan="$DATA_DIR/$NEW_SCAN_NAME"
    rm -f "$newscan"
    collect "$newscan"
    : > "$OUTPUT_FILE"
    report "IDS scan of $MONITOR_DIR on $(date '+%Y-%m-%d %H:%M:%S')"
    report "Baseline: $baseline   New scan: $newscan"
    report "----------------------------------------------------------"
    compare "$baseline" "$newscan"
    echo "Results saved to $OUTPUT_FILE"
}

# ---------------------------------------------------------------------
# 5. MAIN PROGRAM
# ---------------------------------------------------------------------
if [ ! -d "$MONITOR_DIR" ]; then
    echo "Error: monitored folder '$MONITOR_DIR' does not exist." >&2
    exit 1
fi
mkdir -p "$DATA_DIR"

if [ $# -gt 0 ]; then                      # command-line switches
    [ -n "$2" ] || usage
    case "$1" in
        -c|-C) create_mode "$2" ;;
        -o|-O) output_mode "$2" "${3:-$DEFAULT_BASELINE}" ;;
        *)     usage ;;
    esac
else                                       # interactive menu (flowchart Step 2)
    echo "Choose an option: C to create a verification file, O to create an output file"
    read -r option
    case "$option" in
        C|c) echo "Enter a name for the verification file:"
             read -r name
             [ -n "$name" ] || usage
             create_mode "$name" ;;
        O|o) echo "Enter a name for the output file:"
             read -r name
             [ -n "$name" ] || usage
             echo "Enter the baseline verification file name [$DEFAULT_BASELINE]:"
             read -r base
             output_mode "$name" "${base:-$DEFAULT_BASELINE}" ;;
        *)   echo "Invalid option: $option" >&2
             exit 2 ;;
    esac
fi
