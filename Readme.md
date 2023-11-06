
copy mobile_push.lua to /opt/freeswitch/scripts
add line to: /etc/freeswitch/autoload_configs/lua.conf.xml

<hook event="CUSTOM" subclass="mobile::push::notification" script="/opt/freeswitch/scripts/mobile_push.lua" />