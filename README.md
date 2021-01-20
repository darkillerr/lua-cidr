# lua-cidr  
Supported ipv4/ipv6/CIDR, based on **Nginx** implementation.  
# Example  
Run `test_cidr.lua` use `luajit test_cidr.lua`
```
match ::1 & ::1 success
match 0:0::1 & ::1 success
match fe90::f8a6:3eff:fa10:a0b3/80 & fe90::f8a6:3eab:fa1e:b2 success
match fe90::f8a6:3eff:fa10:a0b3 & fe90:0:0:0:f8a6:3eff:fa10:a0b3 success
match 0.0.0.1 & ::1 failed
match 127.0.0.1 & 127.0.0.1 success
match ::ffff:0/96 & ::ffff:10.144.52.38 success
```
# How to use
See `test_cidr.lua`. Require `cidr` in your project(it should run by luajit, because of the ffi), like,
```
local cidr = require "cidr"

...

local retval = cidr.cidr_match(cidr, target_ip) -- return 1 for match, 0 for mismatch, -1 for error
```
