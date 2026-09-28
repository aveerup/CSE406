# reset

sudo pkill -f dnsmasq  
sudo pkill dhcpd  
sudo ip link del v-victim 2>/dev/null  
sudo ip link del b-victim 2>/dev/null  
sudo ip link del v-legit 2>/dev/null  
sudo ip link del b-legit 2>/dev/null  
sudo ip link del v-attacker 2>/dev/null  
sudo ip link del b-attacker 2>/dev/null  
sudo ip link del br0

# setup sandbox 

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
sudo ip netns exec legit ip addr add 10.0.0.1/24 dev v-legit  

# start server

sudo ip netns exec legit dnsmasq \
  --interface=v-legit --bind-interfaces \
  --dhcp-range=10.0.0.100,10.0.0.150,255.255.255.0,12h \
  --dhcp-option=3,10.0.0.1 \
  --dhcp-option=6,8.8.8.8 \
  --no-daemon --log-dhcp

# start attacker server 

sudo ip netns exec attacker \
  python3 attacker/rogue_dhcp_server.py \
  --iface v-attacker \
  --attacker-ip 10.0.0.66 \
  --netmask 255.255.255.0 \
  --gateway 10.0.0.66 \
  --dns 10.0.0.66 \
  --pool-start 10.0.0.200 \
  --pool-end 10.0.0.220 \
  --lease-time 300

# start the victim

sudo ip netns exec victim ip route

# running defense 

sudo ip netns exec legit ip addr show v-legit ## to show the mac and ip address of real server

sudo ip netns exec victim \
  python3 defender/dhcp_guard.py \
  --iface v-victim \
  --enforce

# generate plots

python3 tests/benchmark.py
python3 tests/plot_results.py
