sudo ip netns exec legit dnsmasq \
  --interface=v-legit --bind-interfaces \
  --dhcp-range=10.0.0.100,10.0.0.150,255.255.255.0,12h \
  --dhcp-option=3,10.0.0.1 \
  --dhcp-option=6,8.8.8.8 \
  --no-daemon --log-dhcp