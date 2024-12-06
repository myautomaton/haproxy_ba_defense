-- Magic characters ^$()%.[]*+-? need to be escaped by prepending %
local log4j_patterns = {
    "jndi:ldap://",  -- LDAP injection
    "jndi:rmi://",   -- RMI injection
    "jndi:http://",  -- HTTP injection
    "jndi:",         -- General JNDI
    "env:",          -- Environment variable injection
    "lower:",        -- Lower case transformation
    "uppercase:",    -- Upper case transformation
}
-- "${${::",          -- Nested variable injection


-- Function to check if a string matches any LOG4J injection pattern
local function is_log4j_injection(input)
    for _, pattern in ipairs(log4j_patterns) do
        if input:lower():find(pattern) then
            return true
        end
    end
    return false
end

-- Function to log abuse incidents when LOG4J injection is detected
function logAbuse(ip, path, body, headers)
    -- Generate a unique filename using the IP address and the current timestamp
    local fileName = string.format(
        "%s.%s.yaml",
        ip,
        os.time(os.date("!*t"))
    )

    -- Attempt to open the file for writing; if unsuccessful, log an alert
    local file, err = io.open("/etc/haproxy/abuse/"..fileName, "w+")
    if not file then
        core.Alert("Error opening file: " .. tostring(err)) -- Log error if file can't be opened
        return
    end

    -- Log abuse alert with IP address to HAProxy logs
    core.log(core.info, string.format("Log4j RCE attempt from %s ", ip))

    -- Format the abuse log entry with relevant details in YAML format
    local log_entry = string.format(
        "abuser:\n  date: \"%s\"\n  ip: \"%s\"\n  abuse: \"%s\"\n  path: \"%s\"\n  body: \"%s\"\n  headers: %s\n", 
        os.date("%Y-%m-%d %H:%M:%S"), 
        ip,
        "log4j-injection", 
        path,
        body,
        headers
    )    

    -- Write the formatted log entry to the file and close it
    file:write(log_entry)
    file:close()
end

-- Function to format and collect HTTP headers into a structured YAML list
function squashHeaders(txn)
    local squash = "\n"
    -- Iterate through each header name and append it with its value to the list
    for headerName in string.gmatch(txn.f:req_hdr_names(","), '([^,]+)') do
        squash = string.format(
            "%s  - %s: \"%s\"\n",
            squash,
            headerName,
            txn.f:req_hdr(headerName)
        )
    end
    return squash  -- Return the formatted string of headers
end

-- Function to inspect incoming requests for LOG4J injection
local function detect_log4j(txn)
    local path = txn.sf:query()               -- Get the URL query string
    local headers = txn.f:req_hdr_names(",")  -- Get the names of all HTTP headers
    local body = txn.f:req_body()             -- Get the request body

    -- Get the client IP address; prioritize "x-forwarded-for" header if present
    local x_forwarded_for = txn.f:req_hdr("x-forwarded-for")
    local src_ip = x_forwarded_for or tostring(txn.f:src())

    -- Check if the query string contains LOG4J injection patterns
    if path and is_log4j_injection(path) then
        logAbuse(src_ip, path, body, squashHeaders(txn))  -- Log the abuse
        return true                                       -- Return true to indicate LOG4J injection
    end

    -- Check each HTTP header for LOG4J injection patterns
    for headerName in string.gmatch(headers, '([^,]+)') do
        if is_log4j_injection(txn.f:req_hdr(headerName)) then
            logAbuse(src_ip, path, body, squashHeaders(txn))  -- Log the abuse
            return true                                       -- LOG4J injection detected in header
        end
    end

    -- For POST requests, check the body for LOG4J injection patterns
    if txn.sf:method() == "POST" then
        if body and is_log4j_injection(body) then
            logAbuse(src_ip, path, body, squashHeaders(txn))  -- Log the abuse
            return true                                       -- LOG4J injection detected in body
        end
    end

    return false  -- No LOG4J injection detected
end

-- Register the Lua function to be executed on HTTP requests
core.register_fetches("detect_log4j", detect_log4j)


local function log4j_block(applet)
    local response = "Error: Access Denied. Potential Log4j RCE attempt \n"
    applet:set_status(403)
    applet:add_header("content-length", string.len(response))
    applet:add_header("content-type", "text/plain")
    applet:start_response()
    applet:send(response)

end
core.register_service("log4j_block", "http", log4j_block)