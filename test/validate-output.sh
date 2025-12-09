#!/bin/bash
# Validates that script output only contains properly formatted log messages
# All output from openvpn-install.sh should use logging functions
#
# Usage: ./validate-output.sh <output_file>
#        Or pipe: some_command | ./validate-output.sh

set -euo pipefail

INPUT_FILE="${1:-/dev/stdin}"

# Valid output patterns:
# - Lines starting with ANSI escape codes (colored output)
# - Lines starting with our log prefixes (non-TTY mode)
# - Lines starting with > (command echo from run_cmd)
# - Empty lines

# ANSI escape code pattern
ANSI_PATTERN=$'^\033\\['

# Log prefix patterns (for non-TTY mode where colors are disabled)
# These match: [INFO], [WARN], [ERROR], [OK], [DEBUG], or > (command line)
LOG_PREFIXES='^(\[INFO\]|\[WARN\]|\[ERROR\]|\[OK\]|\[DEBUG\]|> )'

# Count issues
INVALID_LINES=0
TOTAL_LINES=0
LINE_NUM=0

echo "Validating script output for unformatted lines..."
echo ""

while IFS= read -r line || [[ -n "$line" ]]; do
	LINE_NUM=$((LINE_NUM + 1))

	# Skip empty lines
	if [[ -z "$line" ]]; then
		continue
	fi

	TOTAL_LINES=$((TOTAL_LINES + 1))

	# Check if line starts with ANSI escape code (colored output from log functions)
	if [[ "$line" =~ $ANSI_PATTERN ]]; then
		continue
	fi

	# Check if line starts with our log prefixes (non-TTY mode)
	if [[ "$line" =~ $LOG_PREFIXES ]]; then
		continue
	fi

	# If we get here, the line doesn't match expected patterns - it's raw output
	INVALID_LINES=$((INVALID_LINES + 1))
	# Truncate long lines for display
	if [[ ${#line} -gt 100 ]]; then
		DISPLAY_LINE="${line:0:100}..."
	else
		DISPLAY_LINE="$line"
	fi
	echo "  [LEAK] Line $LINE_NUM: $DISPLAY_LINE"

done <"$INPUT_FILE"

echo ""
echo "----------------------------------------"
echo "Total lines checked: $TOTAL_LINES"
echo "Invalid lines found: $INVALID_LINES"

if [[ $INVALID_LINES -gt 0 ]]; then
	echo ""
	echo "ERROR: Found $INVALID_LINES line(s) without proper log formatting."
	echo ""
	echo "All user-visible output should use log_* functions:"
	echo "  - log_info 'message'    -> [INFO] message"
	echo "  - log_warn 'message'    -> [WARN] message"
	echo "  - log_error 'message'   -> [ERROR] message"
	echo "  - log_success 'message' -> [OK] message"
	echo "  - run_cmd 'desc' cmd    -> > cmd"
	echo ""
	echo "Raw echo statements or command output should not leak to stdout."
	exit 1
fi

echo ""
echo "All output is properly formatted!"
exit 0
