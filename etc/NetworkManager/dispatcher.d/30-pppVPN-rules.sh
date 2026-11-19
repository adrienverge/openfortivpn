#!/bin/bash
# Sample script to add in the /etc/NetworkManager/dispatcher.d folder.
# Allowing you to properly configure additional routes if needed
# There might be better way to do this, but I'm not aware of them in my specific case.


# The UUID of the connection profile we want to target. Use it if the UUID is fixed in your case.
#TARGET_CONNECTION_UUID="a1b2c3d4-e5f6-7890-1234-56789abcdef0"

# The interface name (if UUID is not fixed). don't forget to use the --tun-ifname=pppVPN to your config file.
TARGET_INTERFACE="pppVPN"

# The interface name (e.g., ppp0, enp3s0) is the first argument
INTERFACE="$1"
# The action (e.g., "up", "down") is the second argument
ACTION="$2"

# Check if the script is being run for our target connection
#if [ "$CONNECTION_UUID" = "$TARGET_CONNECTION_UUID"  ]; then
if [ "$INTERFACE" = "$TARGET_INTERFACE" ]; then
    case "$ACTION" in
        up)
            # This code runs when the connection comes up
            logger "NetworkManager Dispatcher: Applying custom rules for $INTERFACE"
            # Add specific resources route rules here (more easy than the +ipv4.route using the via which could be random):
            #ip route add 10.10.10.0/24 dev $TARGET_INTERFACE scope link
            #ip route add 10.10.20.0/24 dev $TARGET_INTERFACE scope link
            #ip route add 10.10.30.120/32 dev $TARGET_INTERFACE scope link
            ;;
        down)
            # This code runs when the connection goes down
            logger "NetworkManager Dispatcher: Removing custom rules for $INTERFACE"
            # if using the dev $TARGET_INTERFACE nothing to do, if not, you should remove your rules here
            ;;
    esac
fi

true
