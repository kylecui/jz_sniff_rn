#!/usr/bin/env bash
# --------------------------------------------------------------------------
# test_api.sh — REST API test suite for jz_sniff_rn (31 endpoints)
#
# Usage:
#   ./test_api.sh                          # default: https://localhost:8443
#   ./test_api.sh https://10.174.254.136:8443
#   API_TOKEN=secret ./test_api.sh         # with bearer auth
#
# Requirements: curl, jq
# --------------------------------------------------------------------------
set -euo pipefail

BASE_URL="${1:-https://localhost:8443}"
API="${BASE_URL}/api/v1"
TOKEN="${API_TOKEN:-}"
CURL_OPTS=(-sk --max-time 10)

if [ -n "$TOKEN" ]; then
    CURL_OPTS+=(-H "Authorization: Bearer $TOKEN")
fi

PASS=0
FAIL=0
TOTAL=0
FAILURES=""

RED='\033[0;31m'
GRN='\033[0;32m'
CYN='\033[0;36m'
RST='\033[0m'

# assert_status <test_name> <expected_http_code> <curl_args...>
assert_status() {
    local name="$1"; shift
    local expect="$1"; shift
    TOTAL=$((TOTAL + 1))

    local tmpfile
    tmpfile=$(mktemp)

    local http_code
    http_code=$(curl "${CURL_OPTS[@]}" -o "$tmpfile" -w '%{http_code}' "$@") || true

    if [ "$http_code" = "$expect" ]; then
        PASS=$((PASS + 1))
        printf "${GRN}  PASS${RST}  %-55s  [%s]\n" "$name" "$http_code"
    else
        FAIL=$((FAIL + 1))
        local body
        body=$(head -c 200 "$tmpfile" 2>/dev/null)
        printf "${RED}  FAIL${RST}  %-55s  [got %s, want %s]  %s\n" "$name" "$http_code" "$expect" "$body"
        FAILURES="${FAILURES}\n  - ${name}: got ${http_code}, want ${expect}"
    fi
    rm -f "$tmpfile"
}

# assert_json <test_name> <jq_expression> <expected_value> <curl_args...>
assert_json() {
    local name="$1"; shift
    local jq_expr="$1"; shift
    local expect_val="$1"; shift
    TOTAL=$((TOTAL + 1))

    local body
    body=$(curl "${CURL_OPTS[@]}" "$@") || true

    local actual
    actual=$(echo "$body" | jq -r "$jq_expr" 2>/dev/null) || actual="<jq_error>"

    if [ "$actual" = "$expect_val" ]; then
        PASS=$((PASS + 1))
        printf "${GRN}  PASS${RST}  %-55s  [%s = %s]\n" "$name" "$jq_expr" "$actual"
    else
        FAIL=$((FAIL + 1))
        printf "${RED}  FAIL${RST}  %-55s  [%s: got '%s', want '%s']\n" "$name" "$jq_expr" "$actual" "$expect_val"
        FAILURES="${FAILURES}\n  - ${name}: ${jq_expr} = '${actual}', want '${expect_val}'"
    fi
}

# assert_json_type <test_name> <jq_expression> <type> <curl_args...>
assert_json_type() {
    local name="$1"; shift
    local jq_expr="$1"; shift
    local expect_type="$1"; shift
    TOTAL=$((TOTAL + 1))

    local body
    body=$(curl "${CURL_OPTS[@]}" "$@") || true

    local actual_type
    actual_type=$(echo "$body" | jq -r "$jq_expr | type" 2>/dev/null) || actual_type="<jq_error>"

    if [ "$actual_type" = "$expect_type" ]; then
        PASS=$((PASS + 1))
        printf "${GRN}  PASS${RST}  %-55s  [%s is %s]\n" "$name" "$jq_expr" "$actual_type"
    else
        FAIL=$((FAIL + 1))
        printf "${RED}  FAIL${RST}  %-55s  [%s: got '%s', want '%s']\n" "$name" "$jq_expr" "$actual_type" "$expect_type"
        FAILURES="${FAILURES}\n  - ${name}: type of ${jq_expr} = '${actual_type}', want '${expect_type}'"
    fi
}

section() {
    printf "\n${CYN}=== %s ===${RST}\n" "$1"
}

printf "\n${CYN}jz_sniff_rn REST API Test Suite${RST}\n"
printf "Target: %s\n" "$BASE_URL"
printf "Auth:   %s\n" "${TOKEN:+Bearer token set}"
printf "Date:   %s\n\n" "$(date -Iseconds)"

section "1. Health & Status"

assert_status     "GET /health returns 200"                    200  "$API/health"
assert_json       "GET /health .status=ok"                     ".status" "ok" "$API/health"
assert_json       "GET /health has version"                    '.version | length > 0' "true" "$API/health"

assert_status     "GET /status returns 200"                    200  "$API/status"
assert_json_type  "GET /status .uptime_sec is number"          ".uptime_sec" "number" "$API/status"
assert_json_type  "GET /status .modules is object"             ".modules" "object" "$API/status"
assert_json_type  "GET /status .modules.loaded_count is num"   ".modules.loaded_count" "number" "$API/status"

section "2. Modules"

assert_status     "GET /modules returns 200"                   200  "$API/modules"
assert_json_type  "GET /modules .modules is array"             ".modules" "array" "$API/modules"
assert_json       "GET /modules[0] has .name"                  '.modules[0] | has("name")' "true" "$API/modules"
assert_json       "GET /modules[0] has .loaded"                '.modules[0] | has("loaded")' "true" "$API/modules"

section "3. Guards — Read"

assert_status     "GET /guards returns 200"                    200  "$API/guards"
assert_json_type  "GET /guards .guards is array"               ".guards" "array" "$API/guards"

assert_status     "GET /guards/static returns 200"             200  "$API/guards/static"
assert_json_type  "GET /guards/static .guards is array"        ".guards" "array" "$API/guards/static"

assert_status     "GET /guards/dynamic returns 200"            200  "$API/guards/dynamic"
assert_json_type  "GET /guards/dynamic .guards is array"       ".guards" "array" "$API/guards/dynamic"

section "4. Guards — CRUD Lifecycle"

TEST_GUARD_IP="192.168.254.199"
TEST_GUARD_MAC="aa:bb:cc:dd:ee:99"

assert_status     "POST /guards/static (add test guard)"       201 \
    -X POST -H "Content-Type: application/json" \
    -d "{\"ip\":\"$TEST_GUARD_IP\",\"mac\":\"$TEST_GUARD_MAC\"}" \
    "$API/guards/static"

assert_json       "GET /guards/static contains test guard"     \
    "[.guards[] | select(.ip==\"$TEST_GUARD_IP\")] | length > 0" "true" \
    "$API/guards/static"

assert_status     "POST /guards/static (duplicate → 201 upsert)" 201 \
    -X POST -H "Content-Type: application/json" \
    -d "{\"ip\":\"$TEST_GUARD_IP\",\"mac\":\"$TEST_GUARD_MAC\"}" \
    "$API/guards/static"

assert_status     "DELETE /guards/static/{ip} (remove test)"   200 \
    -X DELETE "$API/guards/static/$TEST_GUARD_IP"

assert_json       "GET /guards/static test guard removed"      \
    "[.guards[] | select(.ip==\"$TEST_GUARD_IP\")] | length" "0" \
    "$API/guards/static"

assert_status     "DELETE /guards/static (nonexistent → 404)"  404 \
    -X DELETE "$API/guards/static/192.168.254.254"

assert_status     "DELETE /guards/dynamic (nonexistent → 404)" 404 \
    -X DELETE "$API/guards/dynamic/192.168.254.254"

assert_status     "POST /guards/static (no body → 400)"        400 \
    -X POST -H "Content-Type: application/json" \
    -d "" "$API/guards/static"

assert_status     "POST /guards/static (bad json → 400)"       400 \
    -X POST -H "Content-Type: application/json" \
    -d '{"ip":"not-an-ip"}' "$API/guards/static"

section "5. Whitelist — CRUD Lifecycle"

TEST_WL_IP="10.99.99.99"
TEST_WL_MAC="11:22:33:44:55:66"

assert_status     "GET /whitelist returns 200"                  200  "$API/whitelist"
assert_json_type  "GET /whitelist .whitelist is array"          ".whitelist" "array" "$API/whitelist"

assert_status     "POST /whitelist (add test entry)"            201 \
    -X POST -H "Content-Type: application/json" \
    -d "{\"ip\":\"$TEST_WL_IP\",\"mac\":\"$TEST_WL_MAC\"}" \
    "$API/whitelist"

assert_json       "GET /whitelist contains test entry"          \
    "[.whitelist[] | select(.ip==\"$TEST_WL_IP\")] | length > 0" "true" \
    "$API/whitelist"

assert_status     "DELETE /whitelist/{ip} (remove test)"        200 \
    -X DELETE "$API/whitelist/$TEST_WL_IP"

assert_json       "GET /whitelist test entry removed"           \
    "[.whitelist[] | select(.ip==\"$TEST_WL_IP\")] | length" "0" \
    "$API/whitelist"

assert_status     "DELETE /whitelist (nonexistent → 404)"       404 \
    -X DELETE "$API/whitelist/10.99.99.254"

section "6. Policies (501 Not Implemented)"

assert_status     "GET /policies returns 200"                   200  "$API/policies"
assert_json_type  "GET /policies .policies is array"            ".policies" "array" "$API/policies"

assert_status     "POST /policies → 501"                        501 \
    -X POST -H "Content-Type: application/json" \
    -d '{"name":"test"}' "$API/policies"

assert_status     "PUT /policies/{id} → 501"                    501 \
    -X PUT -H "Content-Type: application/json" \
    -d '{"name":"test"}' "$API/policies/1"

assert_status     "DELETE /policies/{id} → 501"                 501 \
    -X DELETE "$API/policies/1"

section "7. Logs"

assert_status     "GET /logs/attacks returns 200"               200  "$API/logs/attacks"
assert_json_type  "GET /logs/attacks .rows is array"            ".rows" "array" "$API/logs/attacks"

assert_status     "GET /logs/sniffers returns 200"              200  "$API/logs/sniffers"
assert_json_type  "GET /logs/sniffers .rows is array"           ".rows" "array" "$API/logs/sniffers"

assert_status     "GET /logs/background returns 200"            200  "$API/logs/background"
assert_json_type  "GET /logs/background .rows is array"         ".rows" "array" "$API/logs/background"

assert_status     "GET /logs/threats returns 200"               200  "$API/logs/threats"
assert_json_type  "GET /logs/threats .rows is array"            ".rows" "array" "$API/logs/threats"

assert_status     "GET /logs/audit returns 200"                 200  "$API/logs/audit"
assert_json_type  "GET /logs/audit .rows is array"              ".rows" "array" "$API/logs/audit"

assert_status     "GET /logs/attacks?limit=5 returns 200"       200  "$API/logs/attacks?limit=5"
assert_status     "GET /logs/attacks?since=2020-01-01 200"      200  "$API/logs/attacks?since=2020-01-01T00:00:00Z"
assert_status     "GET /logs/attacks?src_ip=1.2.3.4 200"        200  "$API/logs/attacks?src_ip=1.2.3.4"

section "8. Stats"

assert_status     "GET /stats returns 200"                      200  "$API/stats"
assert_json_type  "GET /stats is object"                        "." "object" "$API/stats"

assert_status     "GET /stats/guards returns 200"               200  "$API/stats/guards"
assert_json_type  "GET /stats/guards .static_count is number"   ".static_count" "number" "$API/stats/guards"
assert_json_type  "GET /stats/guards .dynamic_count is number"  ".dynamic_count" "number" "$API/stats/guards"
assert_json_type  "GET /stats/guards .total is number"          ".total" "number" "$API/stats/guards"

assert_status     "GET /stats/traffic returns 200"              200  "$API/stats/traffic"
assert_json_type  "GET /stats/traffic is object"                "." "object" "$API/stats/traffic"

assert_status     "GET /stats/threats returns 200"              200  "$API/stats/threats"
assert_json_type  "GET /stats/threats is object"                "." "object" "$API/stats/threats"

assert_status     "GET /stats/background returns 200"           200  "$API/stats/background"
assert_json_type  "GET /stats/background is object"             "." "object" "$API/stats/background"

section "9. Config"

assert_status     "GET /config returns 200"                     200  "$API/config"
assert_json_type  "GET /config is object"                       "." "object" "$API/config"

assert_status     "GET /config/history returns 200"             200  "$API/config/history"
assert_json_type  "GET /config/history .rows is array"          ".rows" "array" "$API/config/history"

assert_status     "POST /config (push config)"                  200 \
    -X POST -H "Content-Type: application/json" \
    -d '{"network":{"interface":"ens33"}}' \
    "$API/config"

LATEST_VER=$(curl "${CURL_OPTS[@]}" "$API/config/history" | jq -r '.rows[0].version // empty' 2>/dev/null) || LATEST_VER=""
if [ -n "$LATEST_VER" ]; then
    assert_status "POST /config/rollback (ver $LATEST_VER)"     200 \
        -X POST -H "Content-Type: application/json" \
        -d "{\"version\":$LATEST_VER}" \
        "$API/config/rollback"
else
    assert_status "POST /config/rollback (ver 1)"               200 \
        -X POST -H "Content-Type: application/json" \
        -d '{"version":1}' \
        "$API/config/rollback"
fi

assert_status     "POST /config (empty body → 400)"             400 \
    -X POST -H "Content-Type: application/json" \
    -d "" "$API/config"

section "10. Module Reload"

for mod in guard_classifier arp_honeypot sniffer_detect traffic_weaver; do
    assert_status "POST /modules/$mod/reload returns 200"       200 \
        -X POST -d "" "$API/modules/$mod/reload"
done

assert_status     "POST /modules/nonexistent/reload → 404"     404 \
    -X POST -d "" "$API/modules/nonexistent/reload"

section "11. Error Handling"

assert_status     "GET /nonexistent → 404"                      404  "$API/nonexistent"
assert_status     "DELETE /health → 404 or 405"                 404  -X DELETE "$API/health"
assert_status     "PUT /modules → 404 or 405"                   404  -X PUT -d "" "$API/modules"

printf "\n${CYN}============================================${RST}\n"
printf "${CYN}  Test Summary${RST}\n"
printf "${CYN}============================================${RST}\n"
printf "  Total:   %d\n" "$TOTAL"
printf "  ${GRN}Passed:  %d${RST}\n" "$PASS"
if [ "$FAIL" -gt 0 ]; then
    printf "  ${RED}Failed:  %d${RST}\n" "$FAIL"
else
    printf "  Failed:  %d\n" "$FAIL"
fi

if [ "$FAIL" -gt 0 ]; then
    printf "\n${RED}Failures:${RST}"
    printf "$FAILURES\n"
fi

printf "${CYN}============================================${RST}\n"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
