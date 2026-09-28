#! /bin/bash

if [ "$EUID" -ne 0 ]; then
    exec sudo "$0" "$@"
fi

echo "command -v ip python3 dnsmasq dhclient iptables"
echo "If anything not found, then install otherwise good to go"
echo ""
command -v ip python3 dnsmasq dhclient iptables
echo ""

echo "clean up the earlier lab"
sudo ip link del b-victim 2>/dev/null
sudo ip link del b-legit 2>/dev/null
sudo ip link del b-attacker 2>/dev/null
sudo ip link del br0 2>/dev/null
sudo ip netns del victim 2>/dev/null
sudo ip netns del legit 2>/dev/null
sudo ip netns del attacker 2>/dev/null
echo ""

echo "setting up the lab environment"
sudo ip netns add victim
sudo ip netns add legit
sudo ip netns add attacker

sudo ip link add br0 type bridge
sudo ip link set br0 up

for ns in victim legit attacker; do
  sudo ip link add v-$ns type veth peer name b-$ns
  sudo ip link set v-$ns netns $ns
  sudo ip link set b-$ns master br0
  sudo ip link set b-$ns up
  sudo ip netns exec $ns ip link set v-$ns up
  sudo ip netns exec $ns ip link set lo up
done
echo "lab set up done"
echo ""

echo "assign the legit dhcp server ip addr"
sudo ip netns exec legit ip addr add 10.0.0.1/24 dev v-legit
echo ""

echo "check v-legit has gotten an ip and bridge has three links"
sudo ip netns exec legit ip addr show dev v-legit
bridge link
echo ""

