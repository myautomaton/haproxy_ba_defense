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
    core.log(core.info, string.format("XFF Blacklist from %s ", ip))

    -- Format the abuse log entry with relevant details in YAML format
    local log_entry = string.format(
        "abuser:\n  date: \"%s\"\n  ip: \"%s\"\n  abuse: \"%s\"\n  path: \"%s\"\n  body: \"%s\"\n  headers: %s\n", 
        os.date("%Y-%m-%d %H:%M:%S"), 
        ip,
        "xff-blacklist", 
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

-- Utility function to check if a substring exists within a string
local function contains(str, substr)
    if string.find(str, substr) then  -- Check if 'substr' is found in 'str'
        return true                   -- Return true if found
    else
        return false                  -- Return false if not found
    end
end

-- Function to inspect the X-Forwarded-For header
local function inspect_x_forwarded_for(txn)
    local path = txn.sf:query()               -- Get the URL query string
    local headers = txn.f:req_hdr_names(",")  -- Get the names of all HTTP headers
    local body = txn.f:req_body()             -- Get the request body

    -- Retrieve the "X-Forwarded-For" header, or use the source IP if not present
    local x_forwarded_for = txn.f:req_hdr("x-forwarded-for")
    local src_ip = x_forwarded_for or tostring(txn.f:src())

    -- Check if the "X-Forwarded-For" header exists
    if x_forwarded_for then
        local search_value = "192.168.1.1"  -- Define the IP address to search for

        -- Check if the "X-Forwarded-For" header contains the search IP address
        if contains(x_forwarded_for, search_value) then
            logAbuse(src_ip, path, body, squashHeaders(txn))  -- Log abuse if IP is found
            return true                                       -- Return true for abuse detection
        end
        return false                                          -- Return false if IP not found
    end
end

-- Register the inspect_x_forwarded_for function as a fetch method in HAProxy
core.register_fetches("inspect_x_forwarded_for", inspect_x_forwarded_for)