freeswitch.consoleLog("err", "Mobile push notify fired!\n")

-- curl --location --max-time 3 'http://172.16.86.193:9701/api/v1/mobile/inbound-notify-agent' \
-- --header 'Content-Type: application/json' \
-- --data '{
--   "domainContext": "omicxdev.metechvn.com",
--   "agentExtension": "100019",
--   "callId" : "xxx-xxxx",
--   "callerNumber" : "0979019082"
-- }'