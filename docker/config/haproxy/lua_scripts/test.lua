-- This function returns all condition in an array.
function get_variables(txn)

	-- This array will contains conditions
	local cond = {}

	-- True if the path starts with "/payment/"
	cond['is_payment_page'] = string.match(txn.sf:path(), '^/payment/') ~= nil

	-- True if the front connection is SSL
	cond['is_ssl'] = txn.f:ssl_fc() == 1

	-- True if the domain name asked is preprod
	cond['is_preprod'] = txn.f:req_fhdr('host') == 'preprod.test.com'

	-- True if the cookie 'DEBUG' is set
	cond['is_cookie_exception'] = txn.f:req_cook_cnt('DEBUG') >= 1

	-- Display extracted conditions
-- print_r(cond)
	return cond
end

-- This sample fetch return 1 if we need HTTPS redirect
core.register_fetches("sample2_1", function(txn)

	-- Get input conditions
	local cond = get_variables(txn)

	-- Return result according with conditions value and policy.
	if cond['is_ssl']              then return 0 end
	if cond['is_cookie_exception'] then return 0 end
	if cond['is_preprod']          then return 0 end
	if cond['is_payment_page']     then return 1 end
	return 0
end)

-- This sample fetch returns 1 if we need HTTP redirect
core.register_fetches("sample2_2", function(txn)

	-- Get input conditions
	local cond = get_variables(txn)

	-- Return result according with conditions value and policy.
	if not cond['is_ssl']          then return 0 end
	if cond['is_cookie_exception'] then return 1 end
	if cond['is_preprod']          then return 1 end
	if not cond['is_payment_page'] then return 1 end
	return 0
end)


-- listen sample2
-- 	mode http
-- 	bind *:10020
-- 	bind *:10021 ssl crt www.test.com.crt crt preprod.test.com.crt
-- 	http-request redirect location /to-https if { lua.sample2_1 1 }
-- 	http-request redirect location /to-http  if { lua.sample2_2 1 }
-- 	http-request redirect location /forward