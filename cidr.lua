local ffi = require "ffi"                                                                                                                                                                                                                   
local cidr = ffi.load("./libcidr.so")
 
ffi.cdef[[
int is_cidr_contains_ip(const char *cidr_str, const char *ip_str);
]]

local _M = {}

_M.cidr_match = function(cidr_str, ip_str)
    return cidr.is_cidr_contains_ip(cidr_str, ip_str)
end

return _M
