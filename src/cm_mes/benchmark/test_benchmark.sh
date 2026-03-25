#!/bin/bash

# MES Benchmark Test Script
# This script tests mes_benchmark and mes_rtt_perf functionality

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CBB_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
BIN_DIR="$CBB_ROOT/output/bin"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

TESTS_PASSED=0
TESTS_FAILED=0

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_test() {
    echo -e "${YELLOW}[TEST]${NC} $1"
}

check_result() {
    local test_name="$1"
    local expected="$2"
    local actual="$3"
    
    if [[ "$actual" == *"$expected"* ]]; then
        log_info "PASSED: $test_name"
        ((TESTS_PASSED++))
        return 0
    else
        log_error "FAILED: $test_name"
        log_error "Expected: $expected"
        log_error "Actual: $actual"
        ((TESTS_FAILED++))
        return 1
    fi
}

check_numeric_result() {
    local test_name="$1"
    local min_value="$2"
    local actual="$3"
    
    # Remove non-numeric characters
    actual=$(echo "$actual" | tr -cd '0-9')
    
    if [[ -n "$actual" && "$actual" -ge "$min_value" ]]; then
        log_info "PASSED: $test_name (value: $actual)"
        ((TESTS_PASSED++))
        return 0
    else
        log_error "FAILED: $test_name (expected >= $min_value, got '$actual')"
        ((TESTS_FAILED++))
        return 1
    fi
}

extract_value() {
    local output="$1"
    local pattern="$2"
    echo "$output" | grep "$pattern" | sed 's/.*|\s*\([0-9]*\)\s*|.*/\1/' | tr -d ' '
}

# Set LD_LIBRARY_PATH
export LD_LIBRARY_PATH=/usr1/wyc/source_code/openGauss-server/dest/lib:/usr1/wyc/openGauss-third_party_binarylibs_openEuler_arm/buildtools/gcc10.3/gcc/lib64:/usr1/wyc/openGauss-third_party_binarylibs_openEuler_arm/buildtools/gcc10.3/isl/lib:/usr1/wyc/openGauss-third_party_binarylibs_openEuler_arm/buildtools/gcc10.3/mpc/lib/:/usr1/wyc/openGauss-third_party_binarylibs_openEuler_arm/buildtools/gcc10.3/mpfr/lib/:/usr1/wyc/openGauss-third_party_binarylibs_openEuler_arm/buildtools/gcc10.3/gmp/lib/:/usr1/wyc/source_code/CBB/output/lib/:/usr1/wyc/openGauss-third_party_binarylibs_openEuler_arm/kernel/component/cbb/lib:/usr1/wyc/openGauss-third_party_binarylibs_openEuler_arm/kernel/dependency/openssl/comm/lib:/usr1/wyc/source_code/CBB/output/lib

echo "========================================"
echo "MES Benchmark Test Suite"
echo "========================================"
echo "Binary directory: $BIN_DIR"
echo ""

# Test 1: mes_benchmark help
log_test "Testing mes_benchmark --help"
HELP_OUTPUT=$("$BIN_DIR/mes_benchmark" --help 2>&1)
check_result "mes_benchmark --help shows usage" "Usage:" "$HELP_OUTPUT"
check_result "mes_benchmark --help shows -t option" "-t, --type" "$HELP_OUTPUT"
check_result "mes_benchmark --help shows -V option" "-V, --verify" "$HELP_OUTPUT"
check_result "mes_benchmark --help shows -E option" "-E, --inject-error" "$HELP_OUTPUT"

echo ""

# Test 2: mes_benchmark IPC request-response test
log_test "Testing mes_benchmark IPC request-response mode"
IPC_OUTPUT=$("$BIN_DIR/mes_benchmark" -t ipc -m reqresp -c 100 -s 64 2>&1)
check_result "mes_benchmark IPC test completes" "Benchmark completed successfully" "$IPC_OUTPUT"
check_result "mes_benchmark IPC test shows success count" "Success count" "$IPC_OUTPUT"

# Extract success count
SUCCESS_COUNT=$(extract_value "$IPC_OUTPUT" "Success count")
check_numeric_result "mes_benchmark IPC success count >= 90" 90 "$SUCCESS_COUNT"

echo ""

# Test 3: mes_benchmark with verification (no error injection)
log_test "Testing mes_benchmark with verification (no errors)"
VERIFY_OUTPUT=$("$BIN_DIR/mes_benchmark" -t ipc -V -c 100 -s 256 2>&1)
check_result "mes_benchmark verification shows ALL PASSED" "ALL PASSED" "$VERIFY_OUTPUT"

# Extract verified count
VERIFIED_OK=$(extract_value "$VERIFY_OUTPUT" "Verified OK")
check_numeric_result "mes_benchmark verified OK count >= 90" 90 "$VERIFIED_OK"

echo ""

# Test 4: mes_benchmark with verification and error injection
log_test "Testing mes_benchmark with verification and error injection"
ERROR_OUTPUT=$("$BIN_DIR/mes_benchmark" -t ipc -V -E -c 200 -s 512 2>&1)
check_result "mes_benchmark error injection shows FAILED" "FAILED" "$ERROR_OUTPUT"
check_result "mes_benchmark error injection shows checksum failures" "Checksum Failed" "$ERROR_OUTPUT"

# Verify error count (should be ~2 for 200 messages with error injection every 100)
CHECKSUM_FAILED=$(extract_value "$ERROR_OUTPUT" "Checksum Failed")
check_numeric_result "mes_benchmark checksum failed count >= 1" 1 "$CHECKSUM_FAILED"

echo ""

# Test 5: mes_benchmark with different message sizes
log_test "Testing mes_benchmark with different message sizes"
SIZE_OUTPUT=$("$BIN_DIR/mes_benchmark" -t ipc -c 50 -s 4096 2>&1)
check_result "mes_benchmark large message test completes" "Benchmark completed successfully" "$SIZE_OUTPUT"

echo ""

# Test 6: mes_benchmark send-only mode
log_test "Testing mes_benchmark send-only mode"
SENDONLY_OUTPUT=$("$BIN_DIR/mes_benchmark" -t ipc -m sendonly -c 100 -s 64 2>&1)
check_result "mes_benchmark send-only mode completes" "Bidirectional Latency Test Results" "$SENDONLY_OUTPUT"

echo ""

# Test 7: mes_rtt_perf help
log_test "Testing mes_rtt_perf --help"
RTT_HELP=$("$BIN_DIR/mes_rtt_perf" --help 2>&1)
check_result "mes_rtt_perf --help shows usage" "Usage:" "$RTT_HELP"
check_result "mes_rtt_perf --help shows -m option" "-m, --mode" "$RTT_HELP"
check_result "mes_rtt_perf --help shows -V option" "-V, --verify" "$RTT_HELP"
check_result "mes_rtt_perf --help shows -E option" "-E, --inject-error" "$RTT_HELP"

echo ""

# Test 8: mes_rtt_perf IPC mode (server + client)
log_test "Testing mes_rtt_perf IPC mode"

# Start server in background
"$BIN_DIR/mes_rtt_perf" -m server -p ipc -i 1 > /tmp/rtt_server.log 2>&1 &
SERVER_PID=$!
log_info "Started server (PID: $SERVER_PID)"

# Wait for server to initialize
sleep 2

# Run client
RTT_OUTPUT=$("$BIN_DIR/mes_rtt_perf" -m client -p ipc -i 2 --target-id 1 -c 100 -s 64 2>&1)
RTT_EXIT_CODE=$?

# Stop server
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

check_result "mes_rtt_perf IPC client completes" "RTT Performance Test" "$RTT_OUTPUT"
check_result "mes_rtt_perf IPC shows success count" "Success count" "$RTT_OUTPUT"

# Extract success count
RTT_SUCCESS=$(extract_value "$RTT_OUTPUT" "Success count")
check_numeric_result "mes_rtt_perf IPC success count >= 90" 90 "$RTT_SUCCESS"

echo ""

# Test 9: mes_rtt_perf with verification (no error injection)
log_test "Testing mes_rtt_perf with verification (no errors)"

# Start server in background
"$BIN_DIR/mes_rtt_perf" -m server -p ipc -i 1 > /tmp/rtt_server.log 2>&1 &
SERVER_PID=$!
sleep 2

# Run client with verification
RTT_VERIFY=$("$BIN_DIR/mes_rtt_perf" -m client -p ipc -i 2 --target-id 1 -c 100 -s 256 -V 2>&1)

# Stop server
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

check_result "mes_rtt_perf verification shows ALL PASSED" "ALL PASSED" "$RTT_VERIFY"

echo ""

# Test 10: mes_rtt_perf with verification and error injection
log_test "Testing mes_rtt_perf with verification and error injection"

# Start server in background
"$BIN_DIR/mes_rtt_perf" -m server -p ipc -i 1 > /tmp/rtt_server.log 2>&1 &
SERVER_PID=$!
sleep 2

# Run client with verification and error injection
RTT_ERROR=$("$BIN_DIR/mes_rtt_perf" -m client -p ipc -i 2 --target-id 1 -c 200 -s 512 -V -E 2>&1)

# Stop server
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

check_result "mes_rtt_perf error injection shows FAILED" "FAILED" "$RTT_ERROR"

# Verify error count
RTT_CHECKSUM_FAILED=$(extract_value "$RTT_ERROR" "Checksum Failed")
check_numeric_result "mes_rtt_perf checksum failed count >= 1" 1 "$RTT_CHECKSUM_FAILED"

echo ""

# Test 11: mes_rtt_perf with multiple threads
log_test "Testing mes_rtt_perf with multiple threads"

# Start server in background
"$BIN_DIR/mes_rtt_perf" -m server -p ipc -i 1 > /tmp/rtt_server.log 2>&1 &
SERVER_PID=$!
sleep 2

# Run client with multiple threads
RTT_THREADS=$("$BIN_DIR/mes_rtt_perf" -m client -p ipc -i 2 --target-id 1 -c 200 -s 64 -t 4 2>&1)

# Stop server
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

check_result "mes_rtt_perf multi-thread test shows thread count" "4 threads" "$RTT_THREADS"
RTT_THREAD_SUCCESS=$(extract_value "$RTT_THREADS" "Success count")
check_numeric_result "mes_rtt_perf multi-thread success count >= 180" 180 "$RTT_THREAD_SUCCESS"

echo ""

# Test 12: mes_rtt_perf with large message
log_test "Testing mes_rtt_perf with large message"

# Start server in background
"$BIN_DIR/mes_rtt_perf" -m server -p ipc -i 1 > /tmp/rtt_server.log 2>&1 &
SERVER_PID=$!
sleep 2

# Run client with large message
RTT_LARGE=$("$BIN_DIR/mes_rtt_perf" -m client -p ipc -i 2 --target-id 1 -c 50 -s 16384 2>&1)

# Stop server
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

check_result "mes_rtt_perf large message test completes" "RTT Performance Test" "$RTT_LARGE"

echo ""

# Test 13: Verify statistics output format
log_test "Testing statistics output format"
STATS_OUTPUT=$("$BIN_DIR/mes_benchmark" -t ipc -c 50 -s 64 2>&1)
check_result "Statistics shows Average RTT" "Average RTT" "$STATS_OUTPUT"
check_result "Statistics shows Min RTT" "Min RTT" "$STATS_OUTPUT"
check_result "Statistics shows Max RTT" "Max RTT" "$STATS_OUTPUT"
check_result "Statistics shows P50 RTT" "P50 RTT" "$STATS_OUTPUT"
check_result "Statistics shows P95 RTT" "P95 RTT" "$STATS_OUTPUT"
check_result "Statistics shows P99 RTT" "P99 RTT" "$STATS_OUTPUT"
check_result "Statistics shows Std Dev" "Std Dev" "$STATS_OUTPUT"
check_result "Statistics shows Latency Breakdown" "Latency Breakdown" "$STATS_OUTPUT"
check_result "Statistics shows Throughput" "Throughput" "$STATS_OUTPUT"

echo ""

# Test 14: Verify error injection frequency
log_test "Testing error injection frequency (every 100 messages)"
FREQ_OUTPUT=$("$BIN_DIR/mes_benchmark" -t ipc -V -E -c 500 -s 256 2>&1)
# For 500 messages, expect ~5 errors (at seq 0, 100, 200, 300, 400)
FREQ_FAILED=$(extract_value "$FREQ_OUTPUT" "Checksum Failed")
if [[ "$FREQ_FAILED" -ge 3 && "$FREQ_FAILED" -le 7 ]]; then
    log_info "PASSED: Error injection frequency correct (expected ~5, got $FREQ_FAILED)"
    ((TESTS_PASSED++))
else
    log_error "FAILED: Error injection frequency incorrect (expected ~5, got $FREQ_FAILED)"
    ((TESTS_FAILED++))
fi

echo ""

# Cleanup
rm -f /tmp/rtt_server.log

# Summary
echo "========================================"
echo "Test Summary"
echo "========================================"
echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"
echo ""

if [[ $TESTS_FAILED -eq 0 ]]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
fi
