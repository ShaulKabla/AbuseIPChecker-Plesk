#!/bin/bash
# -----------------------------------------------------------------
# AbuseIPDB Realtime Checker & Data Collector (Optimized for Short Runs)
#
# DESCRIPTION:
# This script collects IPs from web server logs, checks them against
# the AbuseIPDB API, and maintains a persistent database of checked
# IPs to avoid redundant queries. It processes a limited number of
# NEW IPs on each run (e.g., 1000) to ensure execution is fast.
# Malicious IPs are output to a separate file in real-time.
# Designed for high-traffic servers without CSF.
# -----------------------------------------------------------------
set -euo pipefail
trap 'echo "[ERROR] Failed at line $LINENO" >&2; exit 1' ERR
shopt -s nullglob

### --- TUNEABLES --------------------------------------------------
MAX_AGE=90              # AbuseIPDB “maxAgeInDays”
THRESHOLD=25            # % score to treat as abusive
MAX_CHECKS_PER_RUN=1000 # Process this many NEW IPs per script execution for fast runs.
SLEEP_SEC=1             # Delay between API calls (stay polite)
### ---------------------------------------------------------------

# --- FILE & DIRECTORY SETUP
OUTPUT_DIR="/root/abuseipdb_checker"
MASTER_IP_LIST="$OUTPUT_DIR/master_ip_list.csv"  # Persistent DB: IP,Timestamp,Score,Status
MALICIOUS_IPS_REALTIME="$OUTPUT_DIR/malicious_ips_realtime.txt" # Bad IPs are added here immediately
LOG_FILE="$OUTPUT_DIR/script_activity.log"       # General script activity log

# --- TEMPORARY FILES
TMP_LOG_LINES="/tmp/abuseipdb.tmp"
ALL_UNIQUE_IPS="/tmp/abuseipdb.all_unique_ips"
IPS_TO_CHECK="/tmp/abuseipdb.ips_to_check"

# --- WEB SERVER LOGS
LOG_FILES=(
  "/var/log/nginx/access.log"    "/var/log/nginx/access_log"
  "/var/log/apache2/access.log"  "/var/log/apache2/access_log"
  "/var/log/httpd/access_log"
  "/usr/local/lsws/logs/access.log"
  "/var/log/lighttpd/access.log"
  "/var/log/caddy/access.log"
)

# --- API KEYS (rotate automatically on quota errors)
# !!! IMPORTANT !!! REPLACE with your full, real API keys.
API_KEYS=(
""
)
KEY_IDX=0
KEY_TOTAL=${#API_KEYS[@]}
API_KEY="${API_KEYS[$KEY_IDX]}"

### --- FUNCTIONS --------------------------------------------------

log_message() {
    echo "$(date '+%F %T') - $1" | tee -a "$LOG_FILE"
}

install_deps() {
    log_message "Dependency check…"
    if command -v curl >/dev/null && command -v jq >/dev/null; then
        log_message "  -> curl and jq are already installed."
        return
    fi
    log_message "  -> Installing curl + jq…"
    if [ -f /etc/debian_version ]; then
        apt-get -qq update && apt-get -yqq install curl jq
    elif [ -f /etc/redhat-release ]; then
        (yum -y -q install curl jq || dnf -y -q install curl jq)
    else
        log_message "[WARNING] Could not detect package manager. Please install 'curl' and 'jq' manually."
    fi
}

collect_logs() {
    log_message "Harvesting all lines from access logs…"
    : > "$TMP_LOG_LINES"
    for f in "${LOG_FILES[@]}"; do
        [ -f "$f" ] && cat "$f" >> "$TMP_LOG_LINES"
    done
    # Plesk vhosts support
    find /var/www/vhosts -type f -path "*/logs/*access*log*" ! -name '*.gz' -print0 2>/dev/null |
    while IFS= read -r -d '' f; do cat "$f" >> "$TMP_LOG_LINES"; done

    if [ ! -s "$TMP_LOG_LINES" ]; then
        log_message "[FATAL] No log lines found. Exiting." >&2
        exit 1
    fi
}

prepare_ips_to_check() {
    log_message "Extracting unique IPs from logs..."
    awk '{print $1}' "$TMP_LOG_LINES" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' |
    sort -u > "$ALL_UNIQUE_IPS"
    local total_unique_in_logs
    total_unique_in_logs=$(wc -l < "$ALL_UNIQUE_IPS")
    log_message "  -> Found ${total_unique_in_logs} total unique IPs in logs."

    log_message "Filtering out IPs that have already been checked..."
    # Extract just the IP addresses from the master list (first column of the CSV)
    local checked_ips_file="/tmp/abuseipdb.checked_ips"
    cut -d',' -f1 "$MASTER_IP_LIST" > "$checked_ips_file"

    # Use grep to find lines in ALL_UNIQUE_IPS that are NOT in checked_ips_file
    grep -vFf "$checked_ips_file" "$ALL_UNIQUE_IPS" > "$IPS_TO_CHECK"
    rm "$checked_ips_file"

    local new_ips_count
    new_ips_count=$(wc -l < "$IPS_TO_CHECK")
    log_message "  -> Found ${new_ips_count} new IPs to process."

    # If there are more new IPs than our per-run limit, truncate the list
    if (( new_ips_count > MAX_CHECKS_PER_RUN )); then
        log_message "  -> Limiting this run to the first ${MAX_CHECKS_PER_RUN} new IPs."
        head -n "$MAX_CHECKS_PER_RUN" "$IPS_TO_CHECK" > "${IPS_TO_CHECK}.tmp" && mv "${IPS_TO_CHECK}.tmp" "$IPS_TO_CHECK"
    fi
}

rotate_key() {
    log_message "[NOTICE] API quota likely reached. Rotating key."
    KEY_IDX=$(((KEY_IDX + 1) % KEY_TOTAL))
    API_KEY="${API_KEYS[$KEY_IDX]}"
    if (( KEY_IDX == 0 )); then
        log_message "[WARNING] Cycled through all API keys. Pausing for 10 seconds."
        sleep 10
    fi
}

### --- MAIN LOOP --------------------------------------------------
main() {
    mkdir -p "$OUTPUT_DIR"
    touch "$MASTER_IP_LIST" "$MALICIOUS_IPS_REALTIME" "$LOG_FILE"

    log_message "--- Starting AbuseIPDB Check (Batch limit: ${MAX_CHECKS_PER_RUN} IPs) ---"

    install_deps
    collect_logs
    prepare_ips_to_check

    local total_to_process
    total_to_process=$(wc -l < "$IPS_TO_CHECK")

    if (( total_to_process == 0 )); then
        log_message "No new IPs to check. All done."
        exit 0
    fi

    log_message "Starting API checks for ${total_to_process} IPs..."
    local processed_count=0

    while read -r ip; do
        ((processed_count++))

        # Skip private networks
        if [[ "$ip" =~ ^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.) ]]; then
            # Log private IPs so we don't re-check them in the future
            if ! grep -q "^${ip}," "$MASTER_IP_LIST"; then
                 echo "${ip},$(date '+%F %T'),0,PRIVATE" >> "$MASTER_IP_LIST"
            fi
            continue
        fi

        # Query AbuseIPDB
        local resp
        while :; do
            resp=$(curl -s -G "https://api.abuseipdb.com/api/v2/check" \
                --data-urlencode "ipAddress=${ip}" \
                --data-urlencode "maxAgeInDays=${MAX_AGE}" \
                -H "Key: ${API_KEY}" \
                -H "Accept: application/json")

            # Check for API errors (like quota exceeded)
            if jq -e '.errors' <<<"$resp" >/dev/null; then
                rotate_key
                sleep 1 # Wait a moment before retrying with the new key
            else
                break # Success, exit the retry loop
            fi
        done

        local score
        score=$(jq -r '.data.abuseConfidenceScore' <<<"$resp")

        # Progress indicator
        printf "[%6d/%d] %-15s -> Score: %3s%%\n" "$processed_count" "$total_to_process" "$ip" "$score"

        if (( score > THRESHOLD )); then
            log_message "  -> MARKED MALICIOUS: ${ip} (Score: ${score}%)"
            # Add to the master list with MALICIOUS status
            echo "${ip},$(date '+%F %T'),${score},MALICIOUS" >> "$MASTER_IP_LIST"
            # Add to the real-time malicious list
            echo "$ip" >> "$MALICIOUS_IPS_REALTIME"
        else
            # Add to the master list with CHECKED status
            echo "${ip},$(date '+%F %T'),${score},CHECKED" >> "$MASTER_IP_LIST"
        fi

        sleep "$SLEEP_SEC"
    done <"$IPS_TO_CHECK"

    log_message "--- Run complete ---"
    log_message "Checked ${processed_count} new IPs."
    log_message "Master database is at: ${MASTER_IP_LIST}"
    log_message "Real-time list of malicious IPs is at: ${MALICIOUS_IPS_REALTIME}"
}

main
