#!/bin/bash
# start_proxy.sh - Script to easily start the HTTP proxy logger
#

# Set default values
PORT=8080
TARGET="http://example.com"
TRANSPARENT=true  # Default to transparent mode
LOGFILE=""
HOST="0.0.0.0"
TRUNCATE_LIMIT=10000  # Default truncate limit (10000 characters)

# Function to display help message
show_help() {
    cat << EOF
HTTP Proxy Logger - Usage Guide
==============================

BASIC USAGE:
  ./start_proxy.sh [PORT] [MODE] [LOGFILE] [TRUNCATE_LIMIT]

DEFAULT BEHAVIOR:
  Without arguments, starts in transparent mode on port 8080.

ARGUMENTS:
  PORT            Optional. Port number to listen on (default: 8080)
  MODE            Optional. Either:
                  - "transparent" (default): acts as a real HTTP proxy, forwarding to any host
                  - URL (e.g. "http://example.com"): direct mode, forwards all requests to this target
  LOGFILE         Optional. Path to log file (default: logs to console only)
  TRUNCATE_LIMIT  Optional. Maximum characters to display in request/response bodies (default: 10000)
                  Use 0 for no truncation

EXAMPLES:
  ./start_proxy.sh                         # Transparent mode, port 8080
  ./start_proxy.sh 9000                    # Transparent mode, port 9000
  ./start_proxy.sh 8080 http://target.com  # Direct mode to specific target
  ./start_proxy.sh 8080 transparent        # Explicit transparent mode
  ./start_proxy.sh 8080 transparent proxy.log  # Transparent mode with logging
  ./start_proxy.sh 8080 transparent proxy.log 0  # No truncation of bodies (show all content)

OPTIONS:
  -h, --help    Show this help message

EOF
    exit 0
}

# Check for help parameter
if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    show_help
fi

# Check for custom port argument
if [ ! -z "$1" ] && [[ "$1" =~ ^[0-9]+$ ]]; then
    PORT="$1"
fi

# Check for custom target or transparent mode argument
if [ ! -z "$2" ]; then
    if [ "$2" = "transparent" ]; then
        TRANSPARENT=true
        TARGET=""
    elif [[ "$2" =~ ^http:// ]] || [[ "$2" =~ ^https:// ]]; then
        TRANSPARENT=false
        TARGET="$2"
    else
        echo "Error: Invalid MODE parameter. Use 'transparent' or a URL starting with http:// or https://"
        show_help
    fi
fi

# Set the transparent argument based on the mode
if [ "$TRANSPARENT" = true ]; then
    TRANSPARENT_ARG="--transparent"
else
    TRANSPARENT_ARG=""
fi

# Check for log file argument
if [ ! -z "$3" ]; then
    LOGFILE="$3"
    LOG_ARGS="--logfile $LOGFILE"
else
    LOG_ARGS=""
fi

# Check for truncate limit argument
if [ ! -z "$4" ] && [[ "$4" =~ ^[0-9]+$ ]]; then
    TRUNCATE_LIMIT="$4"
fi
TRUNCATE_ARGS="--truncate-limit $TRUNCATE_LIMIT"

# Print banner
echo "═══════════════════════════════════════════"
echo "       HTTP PROXY LOGGER"
echo "═══════════════════════════════════════════"
echo "Starting proxy with:"
echo "- Host: $HOST"
echo "- Port: $PORT"
if [ "$TRANSPARENT" = true ]; then
    echo "- Mode: Transparent (will proxy to requested hosts)"
else
    echo "- Mode: Direct, Target: $TARGET"
fi
echo "- Log: ${LOGFILE:-console only}"
echo "- Truncate limit: ${TRUNCATE_LIMIT} characters" $([ "$TRUNCATE_LIMIT" -eq 0 ] && echo "(disabled)")
echo "═══════════════════════════════════════════"

# Run the proxy
if [ "$TRANSPARENT" = true ]; then
    python3 "$(dirname "$0")/http_proxy_logger.py" --host "$HOST" --port "$PORT" --transparent $LOG_ARGS $TRUNCATE_ARGS
else
    python3 "$(dirname "$0")/http_proxy_logger.py" --host "$HOST" --port "$PORT" --target "$TARGET" $LOG_ARGS $TRUNCATE_ARGS
fi
