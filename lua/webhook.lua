local h = ngx.req.get_headers()

signature = h["X-Hub-Signature"]

if signature == nil then
    ngx.exit(ngx.HTTP_FORBIDDEN)
end

for k, v in string.gmatch(signature, "(%w+)=(%w+)") do
    -- expect 'sha1=xxxxxxxxx'
    signature = v
end

ngx.req.read_body()
local data = ngx.req.get_body_data()
if data == nil then
    ngx.exit(ngx.HTTP_BAD_REQUEST)
end

local str = require "resty.string"
local hmac = str.to_hex(ngx.hmac_sha1(os.getenv('GITHUB_WEBHOOK_SECRET'), data))

if hmac ~= signature then
    ngx.exit(ngx.HTTP_FORBIDDEN)
end

local ngx_pipe = require "ngx.pipe"
local proc, err = ngx_pipe.spawn({"git", "-C", "/data", "pull"})
if not proc then
    ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
    ngx.say(err)
    return
end

ngx.say("successfully spawned")
