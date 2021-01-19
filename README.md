# lua-cidr  
Supported ipv4/ipv6/CIDR, based on **Nginx** implementation.  
# How to use
See `test_cidr.lua`. Require `cidr` in your project(it should run by luajit, because of the ffi), like,
```
local cidr = require "cidr"

...

local retval = cidr.cidr_match(cidr, target_ip) -- return 1 for match, 0 for mismatch, -1 for error
```
