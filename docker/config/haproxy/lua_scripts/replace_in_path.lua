-- This Lua script redirects strips from url

function new_path(txn)
    local result = ''
    local path = txn.sf:path()
    result = string.gsub(path, "/foo", "")
    return result
end
  
core.register_fetches("new_path", new_path)