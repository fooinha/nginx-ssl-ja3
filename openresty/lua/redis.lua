local M = {}

local redis = require "resty/redis"

local REDIS_ADDR = "192.168.15.111"

function M.RedisGet(key)
  local red = redis:new()
  if not red then
    ngx.log(ngx.ERR, "REDIS| Failed to load Redis client")
    return nil
  end
  red:set_timeout(1000)
  local ok, err = red:connect(REDIS_ADDR, 6379)
  if not ok then
    ngx.log(ngx.ERR, "REDIS| Failed connect to Redis")
    return nil
  end
  local res, err = red:get(key)

  local ok, err = red:close() --red:set_keepalive(5000, 200)
  if not ok then
    ngx.say("REDIS| Failed to set keepalive: ", err)
  end

  if res == ngx.null then
    return nil
  end
  return res
end

function M.RedisSet(key, value)
  local red = redis:new()
  red:set_timeout(1000)
  local ok, err = red:connect(REDIS_ADDR, 6379)
  if not ok then
    ngx.log(ngx.ERR, "REDIS| Failed connect to Redis")
    return nil
  end
  local _return = red:set(key, value)
  local ok, err = red:close() --red:set_keepalive(5000, 200)
  if not ok then
    ngx.say("REDIS| Failed to set keepalive: ", err)
  end
  return _return
end

function M.RedisSetExpire(key, value, expiretime)
  local red = redis:new()
  red:set_timeout(1000)
  local ok, err = red:connect(REDIS_ADDR, 6379)
  if not ok then
    ngx.log(ngx.ERR, "REDIS| Failed connect to Redis")
    return nil
  end
  local _return = red:setex(key, expiretime, value)
  local ok, err = red:close() --red:set_keepalive(5000, 200)
  if not ok then
    ngx.say("REDIS| Failed to set keepalive: ", err)
  end
  return _return
end

function M.RedisDelete(key)
  local red = redis:new()
  red:set_timeout(1000)
  local ok, err = red:connect(REDIS_ADDR, 6379)
  if not ok then
    ngx.log(ngx.ERR, "REDIS| Failed connect to Redis")
    return nil
  end
  local _return = red:del(key)
  local ok, err = red:close() --red:set_keepalive(5000, 200)
  if not ok then
    ngx.say("REDIS| Failed to set keepalive: ", err)
  end
  return _return
end

function M.RedisFlushConfig()
  local red = redis:new()
  red:set_timeout(1000)
  local ok, err = red:connect(REDIS_ADDR, 6379)
  if not ok then
    ngx.log(ngx.ERR, "REDIS| Failed connect to Redis")
    return nil
  end
  for _,k in ipairs(red:keys('config:*')) do
    red:del(k)
  end
  local ok, err = red:close() --red:set_keepalive(5000, 200)
  if not ok then
    ngx.say("REDIS| Failed to set keepalive: ", err)
  end
end

function M.FlushDirectory()
  local lfs = require "lfs";
  local doc_path = '/var/lib/cleafy/stream/data/keys/';
  local resultOK, errorMsg;

  for file in lfs.dir(doc_path) do
    local theFile = doc_path .. file

    if (lfs.attributes(theFile, "mode") ~= "directory") then
      resultOK, errorMsg = os.remove(theFile);

      if (resultOK) then
      --print(file.." removed");
      else
        ngx.log(ngx.ERR, "Error removing file: "..file..":"..errorMsg);
      end
    end
  end
end

return M