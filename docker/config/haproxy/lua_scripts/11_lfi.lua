-- Magic characters ^$()%.[]*+-? need to be escaped by prepending %
local lfi_patterns = {
    '%.%./',
    '%.%.2f',
    'etc/passwd',
    'php://'
}



-- Function to check if input contains any LFI injection patterns
local function is_LFI_injection(input)
    for _, pattern in ipairs(lfi_patterns) do  -- Loop through all LFI patterns
        if input:lower():find(pattern) then    -- If the input matches any pattern, LFI injection is detected
            return true                        -- Return true to indicate LFI injection detected
        end
    end
    return false                               -- Return false if no patterns matched
end

-- Function to log abuse incidents when LFI injection is detected
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
    core.log(core.info, string.format("LFI Injection detected from %s ", ip))

    -- Format the abuse log entry with relevant details in YAML format
    local log_entry = string.format(
        "abuser:\n  date: \"%s\"\n  ip: \"%s\"\n  abuse: \"%s\"\n  path: \"%s\"\n  body: \"%s\"\n  headers: %s\n", 
        os.date("%Y-%m-%d %H:%M:%S"), 
        ip,
        "lfi-injection", 
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

-- Main function to check for LFI injection patterns in HTTP request components
local function detect_lfi(txn)
    local path = txn.sf:path()             -- Get the URL query string
    local headers = txn.f:req_hdr_names(",")  -- Get the names of all HTTP headers
    local body = txn.f:req_body()             -- Get the request body

    -- Get the client IP address; prioritize "x-forwarded-for" header if present
    local x_forwarded_for = txn.f:req_hdr("x-forwarded-for")
    local src_ip = x_forwarded_for or tostring(txn.f:src())

    -- Check if the query string contains LFI injection patterns
    if path and is_LFI_injection(path) then
        logAbuse(src_ip, path, body, squashHeaders(txn))  -- Log the abuse
        return true                                       -- Return true to indicate LFI injection
    end

    -- Check each HTTP header for LFI injection patterns
    for headerName in string.gmatch(headers, '([^,]+)') do
        if is_LFI_injection(txn.f:req_hdr(headerName)) then
            logAbuse(src_ip, path, body, squashHeaders(txn))  -- Log the abuse
            return true                                       -- LFI injection detected in header
        end
    end

    -- For POST requests, check the body for LFI injection patterns
    if txn.sf:method() == "POST" then
        if body and is_LFI_injection(body) then
            logAbuse(src_ip, path, body, squashHeaders(txn))  -- Log the abuse
            return true                                       -- LFI injection detected in body
        end
    end

    return false  -- No LFI injection detected
end
-- Register the LFI injection check function as a custom fetch method in HAProxy
core.register_fetches("detect_lfi", detect_lfi)

local function lfi_block(applet)
    local response = "Error: Access Denied. Potential Local File Inclusion attempt detected."
    applet:set_status(403)
    applet:add_header("content-length", string.len(response))
    applet:add_header("content-type", "text/plain")
    applet:start_response()
    applet:send(response)

end
core.register_service("lfi_block", "http", lfi_block)