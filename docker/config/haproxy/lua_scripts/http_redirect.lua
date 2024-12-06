-- This Lua script redirects requests based on
-- HTTP request port or path.

function path_redirect(txn)
    local result = ''
    local path = txn.sf:path()
    local path_start = string.match(path, '([^/]+)')
    if path_start == 'foo' then
      result = 'backend1'
    elseif path_start == 'bar' then
      result = 'backend2'
    else
      result = 'nobkselected'
    end
    return result
  end
  
  core.register_fetches("path_redirect", path_redirect)
  
  function port_redirect(txn)
    local base = txn.sf:base()
    txn.Info(txn, 'Port: ' .. base)
    local host, port, rest = string.match(base, '([^:]+):([^/]+)/?(.+)]?')
    txn.Info(txn, 'Port: ' .. port)
    if port == '15081' then
      result = 'backend1'
    elseif port == '15082' then
      result = 'backend2'
    else
      result = 'nobkselected'
    end
    return result
  end
  
  core.register_fetches("port_redirect", port_redirect)