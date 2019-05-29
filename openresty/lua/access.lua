local redis = require "redis"

local hash = ngx.req.get_headers()["x-ja3-hash"]
local ua = ngx.req.get_headers()["x-ja3-ua"]
local fp = ngx.req.get_headers()["x-ja3-fp"]

redis.RedisSet(hash, ua..'/n'..fp)