#!/bin/bash
# Function to check curl response
check_response() {
    local url=$1
    local expected_status=$2
    local expected_body=$3
    local params=$4

    # Perform the curl request and capture response
    response=$(curl -s -o response_body.txt -w "%{http_code}" $params $url)
    body=$(<response_body.txt)

    # Check status code
    if [[ "$response" -ne "$expected_status" ]]; then
        echo "FAIL: Expected status $expected_status but got $response for URL: $url"
        return 1
    fi

    # Check response body
    if [[ "$body" != *"$expected_body"* ]]; then
        echo "FAIL: Expected body to contain '$expected_body' but got '$body' for URL: $url"
        return 1
    fi

    echo "PASS: Received expected response for URL: $url"
    return 0
}

# Test cases
echo "Running tests..."

# Test Case 1: Valid Request
check_response "http://10.201.0.10/?id=1'%20OR%201=1--" 403 "" ""
check_response "http://10.201.0.10" 403 "" "-H \"X-Test-Header: 1' OR 1=1--\""
check_response "http://10.201.0.10" 403 "" "-H \"X-Test-Header: asd\""
check_response "http://10.201.0.10/" 200 "" "-X POST -d \"username=admin' OR 1=1--\""
check_response "" 200 ""
