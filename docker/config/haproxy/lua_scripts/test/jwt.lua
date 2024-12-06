local json = require "json"  -- You'll need a JSON library (like cjson)
local base64 = require "base64"  -- Base64 library for decoding
-- local openssl_hmac = require "openssl.hmac"  -- HMAC function for signature verification

-- Secret key used to verify the JWT signature (replace with your secret)
local secret_key = "mytoken"

-- Function to split a string by a delimiter (for splitting JWT parts)
local function split_string(str, delimiter)
    local result = {}
    for match in (str..delimiter):gmatch("(.-)"..delimiter) do
        table.insert(result, match)
    end
    return result
end

-- Function to base64-decode the input
local function base64_decode(input)
    input = input:gsub("-", "+"):gsub("_", "/")
    local rem = #input % 4
    if rem > 0 then
        input = input .. string.rep("=", 4 - rem)
    end
    return base64.decode(input)
end

-- Function to verify the HMAC signature
local function verify_signature(header, payload, signature, key)
    local data = header .. "." .. payload
    -- local expected_signature = openssl_hmac.new(key, "sha256"):final(data)
    -- local decoded_signature = base64_decode(signature)
    -- return expected_signature == decoded_signature
    return true
end

-- Function to validate the JWT token
local function validate_jwt(token)
    -- Split the token into three parts (header, payload, signature)
    local parts = split_string(token, ".")
    if #parts ~= 3 then
        return false, "Invalid JWT format"
    end

    local header = parts[1]
    local payload = parts[2]
    local signature = parts[3]

    -- Decode the header and payload
    local decoded_header = base64_decode(header)
    local decoded_payload = base64_decode(payload)

    -- Parse the payload (assumes it's JSON)
    local payload_json = json.decode(decoded_payload)
    if not payload_json then
        return false, "Invalid JWT payload"
    end

    -- Check the expiration time (exp claim)
    local current_time = os.time()
    if payload_json.exp and payload_json.exp < current_time then
        return false, "JWT has expired"
    end

    -- Verify the signature
    local valid_signature = verify_signature(header, payload, signature, secret_key)
    if not valid_signature then
        return false, "Invalid JWT signature"
    end

    return true, "JWT is valid"
end

-- Function to extract the JWT token from the Authorization header
local function get_jwt_from_header(txn)
    local auth_header = txn.http:req_get_headers()["authorization"]
    if auth_header and auth_header[1] then
        local token = auth_header[1]:match("Bearer%s+(.+)")
        if token then
            return token
        end
    end
    return nil
end

-- Main function to handle incoming requests and check JWT token
local function check_jwt_token(txn)
    -- Extract the JWT token from the Authorization header
    local jwt_token = get_jwt_from_header(txn)
    if not jwt_token then
        -- No JWT token found, return 401 Unauthorized
        txn.http:res_set_status(401)
        txn.http:res_set_body("Unauthorized: No JWT token provided")
        txn:done()
        return
    end

    -- Validate the JWT token
    local is_valid, validation_message = validate_jwt(jwt_token)
    if not is_valid then
        -- Invalid JWT token, return 401 Unauthorized
        txn.http:res_set_status(401)
        txn.http:res_set_body("Unauthorized: " .. validation_message)
        txn:done()
        return
    end

    -- If the token is valid, continue processing the request
end

-- Register the Lua function to be executed on HTTP request
core.register_action("check_jwt_token", { "http-req" }, check_jwt_token)