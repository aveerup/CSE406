#! /bin/bash

sudo ip netns exec victim \
  python3 source\ codes/defender/dhcp_guard.py \
  --iface v-victim \
  --enforce