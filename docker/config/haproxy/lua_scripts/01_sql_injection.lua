-- Define patterns commonly used in SQL injection attacks
local sql_patterns = {
    "select%s+.*%s+from",   -- Pattern to detect "SELECT * FROM" statement
    "union%s+select",       -- Pattern to detect "UNION SELECT" statement
    "'%s*or%s+1=1",         -- Pattern to detect "' OR 1=1" condition often used in SQL injection
    "%-%-",                 -- Pattern to detect SQL comment symbol "--"
    ";%s*shutdown",         -- Pattern to detect "SHUTDOWN" command
    "';%s*drop%s+table",    -- Pattern to detect "DROP TABLE" command
    "exec%s+xp_cmdshell",   -- Pattern to detect execution of "xp_cmdshell" command (SQL Server)
    "insert%s+into",        -- Pattern to detect "INSERT INTO" statement
    "update%s+.*%s+set",    -- Pattern to detect "UPDATE ... SET" statement
    "delete%s+from"         -- Pattern to detect "DELETE FROM" statement
}

-- Function to check if input contains any SQL injection patterns
local function is_sql_injection(input)
    for _, pattern in ipairs(sql_patterns) do  -- Loop through all SQL patterns
        if input:lower():find(pattern) then    -- If the input matches any pattern, SQL injection is detected
            return true                        -- Return true to indicate SQL injection detected
        end
    end
    return false                               -- Return false if no patterns matched
end

-- Function to log abuse incidents when SQL injection is detected
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
    core.log(core.info, string.format("SQL Injection detected from %s ", ip))

    -- Format the abuse log entry with relevant details in YAML format
    local log_entry = string.format(
        "abuser:\n  date: \"%s\"\n  ip: \"%s\"\n  abuse: \"%s\"\n  path: \"%s\"\n  body: \"%s\"\n  headers: %s\n", 
        os.date("%Y-%m-%d %H:%M:%S"), 
        ip,
        "sql-injection", 
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

-- Main function to check for SQL injection patterns in HTTP request components
local function check_sql_injection(txn)
    local path = txn.sf:query()               -- Get the URL query string
    local headers = txn.f:req_hdr_names(",")  -- Get the names of all HTTP headers
    local body = txn.f:req_body()             -- Get the request body

    -- Get the client IP address; prioritize "x-forwarded-for" header if present
    local x_forwarded_for = txn.f:req_hdr("x-forwarded-for")
    local src_ip = x_forwarded_for or tostring(txn.f:src())

    -- Check if the query string contains SQL injection patterns
    if path and is_sql_injection(path) then
        logAbuse(src_ip, path, body, squashHeaders(txn))  -- Log the abuse
        return true                                       -- Return true to indicate SQL injection
    end

    -- Check each HTTP header for SQL injection patterns
    for headerName in string.gmatch(headers, '([^,]+)') do
        if is_sql_injection(txn.f:req_hdr(headerName)) then
            logAbuse(src_ip, path, body, squashHeaders(txn))  -- Log the abuse
            return true                                       -- SQL injection detected in header
        end
    end

    -- For POST requests, check the body for SQL injection patterns
    if txn.sf:method() == "POST" then
        if body and is_sql_injection(body) then
            logAbuse(src_ip, path, body, squashHeaders(txn))  -- Log the abuse
            return true                                       -- SQL injection detected in body
        end
    end

    return false  -- No SQL injection detected
end
-- Register the SQL injection check function as a custom fetch method in HAProxy
core.register_fetches("check_sql_injection", check_sql_injection)

-- Function to deny requests when SQL injection is detected
local function deny_sql_injection(applet)
    local response = "SQL Injection detected!\n\n"  -- Response message to send
    applet:set_status(403)                          -- Set HTTP status to 403 Forbidden
    applet:add_header("content-length", string.len(response))  -- Set content length header
    applet:add_header("content-type", "text/plain")  -- Set content type header to plain text
    applet:start_response()                          -- Start the HTTP response
    applet:send(response)                            -- Send the response message
end

-- Register the SQL injection denial function as an HTTP service in HAProxy
core.register_service("deny_sql_injection", "http", deny_sql_injection)