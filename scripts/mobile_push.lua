freeswitch.consoleLog("err", "Mobile push notify fired!\n")

local call_id = event:getHeader('uuid') or '';
local call_type = event:getHeader('type') or '';
local user = event:getHeader('user') or '';
local domain_context = event:getHeader('realm') or '';
local dialer_number = event:getHeader('dialer') or '';

local server_url = "http://172.16.86.193:9701/api/v1/mobile/inbound-notify-agent"
local jsonRequest = string.format('{"domainContext": "%s","agentExtension":"%s","callId":"%s","callerNumber":"%s"}',domain_context,user,call_id,dialer_number)
local api = freeswitch.API();
freeswitch.consoleLog("info", uuid .. " detect voice mail request: " .. jsonRequest .. "\n")
local response = api:executeString("curl ".. server_url .. " timeout 3 content-type 'application/json' post '"..jsonRequest.."'") or '';
freeswitch.consoleLog("info", uuid .. " detect voice mail response: " .. response .. "\n")

local event = freeswitch.Event("mobile::push::response");                                                                                                              
event:addHeader("uuid", call_id);                                                                                                                 
event:addHeader("response", "sent");                                                                                                 
event:fire();