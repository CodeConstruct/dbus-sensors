#!/bin/bash
set -x

# set up busctl flag for user session
if [ "$DBUS_STARTER_BUS_TYPE" == "session" ] && [ -n "$DBUS_SESSION_BUS_ADDRESS" ]
then
    USER_FLAG=--user
else
    USER_FLAG=
fi

# exit if the O-M has started
busctl $USER_FLAG tree xyz.openbmc_project.ObjectMapper && exit 0

# override the system config if not using against user session
if [ -z "$USER_FLAG" ]; then
    sudo sed -i -E 's/<deny( send_type="method_call"\/>)/<allow\1/' /usr/share/dbus-1/system.conf
    sudo sed -i -E 's/<deny( own="\*"\/>)/<allow\1/'  /usr/share/dbus-1/system.conf
    sudo service dbus restart
fi

# restart O-M so it picks up the correct dbus
kill $(pgrep mapperx)
for ((i=1; i<=5; i++))
do
    LD_LIBRARY_PATH="/usr/local/lib/x86_64-linux-gnu/:/usr/local/lib/" start-stop-daemon --start -b  --exec /usr/local/libexec/phosphor-objmgr/mapperx  -- "--service-namespaces=com.google.gbmc com.intel xyz.openbmc_project org.openbmc" "--interface-namespaces=org.freedesktop.DBus.ObjectManager com.google.gbmc com.intel xyz.openbmc_project org.openbmc" --service-blacklists= && break
    sleep 1
done

sleep 1
busctl $USER_FLAG tree xyz.openbmc_project.ObjectMapper
