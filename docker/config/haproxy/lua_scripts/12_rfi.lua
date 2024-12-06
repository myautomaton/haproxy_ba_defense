-- Table of patterns used to detect potential Remote File Inclusion (RFI) attacks
local rfi_patterns = {
    "http://",   -- Match HTTP URL pattern
    "https://",  -- Match HTTPS URL pattern
    "ftp://",    -- Match FTP URL pattern
    "file://",   -- Match File URL pattern (local or remote)
    "%.php",     -- Match PHP file extension
    "%.js",      -- Match JavaScript file extension
    "%.asp"      -- Match ASP file extension
}

-- Function to check if input contains any rfi injection patterns
local function is_rfi_injection(input)
    for _, pattern in ipairs(rfi_patterns) do  -- Loop through all rfi patterns
        if input:lower():find(pattern) then    -- If the input matches any pattern, rfi injection is detected
            return true                        -- Return true to indicate rfi injection detected
        end
    end
    return false                               -- Return false if no patterns matched
end

-- Function to log abuse incidents when rfi injection is detected
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
    core.log(core.info, string.format("rfi Injection detected from %s ", ip))

    -- Format the abuse log entry with relevant details in YAML format
    local log_entry = string.format(
        "abuser:\n  date: \"%s\"\n  ip: \"%s\"\n  abuse: \"%s\"\n  path: \"%s\"\n  body: \"%s\"\n  headers: %s\n", 
        os.date("%Y-%m-%d %H:%M:%S"), 
        ip,
        "rfi-injection", 
        path,
        body,
        headers
    )    

    -- Write the formatted log entry to the file and close it
    file:write(log_entry)
    file:close()
end

-- Function to concatenate all request headers into a single string, each on a new line
function squashHeaders(txn)
    local squash = "\n"  -- Initialize with a newline for formatting
    for headerName in string.gmatch(txn.f:req_hdr_names(","), '([^,]+)') do
        squash = string.format(
            "%s  - %s: \"%s\"\n",
            squash,
            headerName,
            txn.f:req_hdr(headerName)
        )
    end
    return squash  -- Return the concatenated headers string
end

-- Function to detect RFI attempts in the URL query, headers, and body
local function detect_rfi(txn)
    local path = txn.sf:query()               -- Retrieve the URL query string
    local headers = txn.f:req_hdr_names(",")  -- Get a list of all HTTP header names
    local body = txn.f:req_body()             -- Retrieve the HTTP request body

    -- Check for the presence of "x-forwarded-for" header to identify the source IP address
    local x_forwarded_for = txn.f:req_hdr("x-forwarded-for")
    local src_ip = x_forwarded_for or tostring(txn.f:src())  -- Use "x-forwarded-for" IP if present, otherwise client IP

    -- Check if the URL query string contains any RFI patterns
    if path and is_rfi_injection(path) then
        logAbuse(src_ip, path, body, squashHeaders(txn))  -- Log the abuse if RFI pattern is detected in the URL
        return true                                       -- Return true to indicate a detected RFI attempt
    end

    -- Iterate through each header and check for RFI patterns
    for headerName in string.gmatch(headers, '([^,]+)') do
        if is_rfi_injection(txn.f:req_hdr(headerName)) then
            logAbuse(src_ip, path, body, squashHeaders(txn))  -- Log the abuse if RFI pattern is detected in headers
            return true                                      -- Return true for detected RFI in headers
        end
    end

    -- Check if the request method is POST and if the request body contains any RFI patterns
    if txn.sf:method() == "POST" then
        if body and is_rfi_injection(body) then
            logAbuse(src_ip, path, body, squashHeaders(txn))  -- Log the abuse if RFI pattern is detected in the body
            return true                                       -- Return true for detected RFI in the body
        end
    end

    return false  -- Return false if no RFI patterns were detected in URL, headers, or body
end

-- Register detect_rfi as a fetch method in HAProxy
core.register_fetches("detect_rfi", detect_rfi)


-- Function to block requests containing potential RFI attempts by sending an error response
local function rfi_block(applet)
    local response = "Error: Access Denied. Potential Remote File Inclusion attempt detected.\n"  -- Define RFI error message
    applet:set_status(403)                             -- Set HTTP response status to 403 (Forbidden)
    applet:add_header("content-length", string.len(response))  -- Set content length header
    applet:add_header("content-type", "text/plain")    -- Set content type to plain text
    applet:start_response()                            -- Start sending the response
    applet:send(response)                              -- Send the response message
end

-- Register rfi_block as a custom service in HAProxy for blocking detected RFI attempts
core.register_service("rfi_block", "http", rfi_block)