-- Table of patterns that may indicate a potential Cross-Site Scripting (XSS) attack
local xss_patterns = {
    "<script>",          -- JavaScript tags often used in XSS
    "javascript:",       -- JavaScript protocol, used in XSS attacks
    "onerror=",          -- HTML event attribute often used in XSS payloads
    "onclick=",          -- Another event attribute used for XSS
    "alert(",            -- JavaScript alert function, commonly used for testing XSS
    "onload=",           -- Event handler often targeted in XSS
    "Cscript",           -- Alternate script tag, possibly for obfuscation
    "Ciframe",           -- Alternate iframe tag, possibly for obfuscation
    "<iframe>",          -- iframe tag, used to load external content
    "eval(",             -- JavaScript eval function, can execute arbitrary code
    "document.cookie",   -- Accessing cookies, a potential XSS sign
    ".asp"               -- .asp extension, which could suggest a script or file inclusion
}

-- Function to check if an input string contains any XSS patterns
local function is_sql_injection(input)
    for _, pattern in ipairs(xss_patterns) do  -- Loop through each XSS pattern
        if input:lower():find(pattern) then    -- Convert input to lowercase and check for pattern
            return true                        -- Return true if a pattern match is found
        end
    end
    return false                               -- Return false if no pattern matches
end

-- Function to log detected abuse attempts into a file
function logAbuse(ip, path, body, headers)
    -- Construct a unique filename based on IP and current timestamp
    local fileName = string.format(
        "%s.%s.yaml",
        ip,
        os.time(os.date("!*t"))
    )

    -- Attempt to open the file in write mode and handle errors
    local file, err = io.open("/etc/haproxy/abuse/"..fileName, "w+")
    if not file then
        core.Alert("Error opening file: " .. tostring(err))  -- Log an alert if file cannot be opened
        return
    end

    core.log(core.info, string.format("Cross-Site Scripting attempt detected from %s ", ip))  -- Log detection

    -- Create a structured log entry for the abuse attempt
    local log_entry = string.format(
        "abuser:\n  date: \"%s\"\n  ip: \"%s\"\n  abuse: \"%s\"\n  path: \"%s\"\n  body: \"%s\"\n  headers: %s\n", 
        os.date("%Y-%m-%d %H:%M:%S"),  -- Log current date and time
        ip,
        "xss-attempt",                 -- Mark abuse type as XSS attempt
        path,
        body,
        headers
    )    

    file:write(log_entry)  -- Write log entry to the file
    file:close()            -- Close the file after writing
end

-- Function to concatenate all request headers into a single formatted string
function squashHeaders(txn)
    local squash = "\n"
    -- Loop through each header name
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

-- Main function to detect potential XSS attacks by inspecting URL, headers, and body
local function detect_xss(txn)
    local path = txn.sf:query()               -- Get the URL query string
    local headers = txn.f:req_hdr_names(",")  -- Get all HTTP header names
    local body = txn.f:req_body()             -- Get the request body

    -- Get source IP, preferring "x-forwarded-for" header if present
    local x_forwarded_for = txn.f:req_hdr("x-forwarded-for")
    local src_ip = x_forwarded_for or tostring(txn.f:src())

    -- Check if the URL query string contains any XSS patterns
    if path and is_sql_injection(path) then
        logAbuse(src_ip, path, body, squashHeaders(txn))  -- Log XSS attempt if detected in URL
        return true                                       -- Return true to indicate detection
    end

    -- Check each HTTP header for XSS patterns
    for headerName in string.gmatch(headers, '([^,]+)') do
        if is_sql_injection(txn.f:req_hdr(headerName)) then
            logAbuse(src_ip, path, body, squashHeaders(txn))  -- Log XSS attempt if detected in headers
            return true                                      -- Return true for detected XSS in headers
        end
    end

    -- For POST requests, check the request body for XSS patterns
    if txn.sf:method() == "POST" then
        if body and is_sql_injection(body) then
            logAbuse(src_ip, path, body, squashHeaders(txn))  -- Log XSS attempt if detected in body
            return true                                       -- Return true for detected XSS in body
        end
    end

    return false  -- Return false if no XSS patterns were detected
end
core.register_fetches("detect_xss", detect_xss)  -- Register detect_xss function as fetch in HAProxy

-- Function to block requests with detected XSS attempts, returning an error response
local function xss_block(applet)
    local response = "Error: Access Denied. Potential Cross-Site Scripting attempt detected."  -- Define XSS error message
    applet:set_status(403)                               -- Set HTTP response status to 403 (Forbidden)
    applet:add_header("content-length", string.len(response))  -- Set content length header
    applet:add_header("content-type", "text/plain")      -- Set content type to plain text
    applet:start_response()                              -- Start sending the response
    applet:send(response)                                -- Send the response message
end
core.register_service("xss_block", "http", xss_block)   -- Register xss_block as a service in HAProxy
