# Run from `source codes` and only on a host you control.

# reset -- stop namespace processes, then remove the previous lab
for ns in victim legit attacker; do
  sudo ip netns pids "$ns" 2>/dev/null | xargs -r sudo kill
done
sudo ip link del b-victim 2>/dev/null
sudo ip link del b-legit 2>/dev/null
sudo ip link del b-attacker 2>/dev/null
sudo ip link del br0 2>/dev/null
sudo ip netns del victim 2>/dev/null
sudo ip netns del legit 2>/dev/null
sudo ip netns del attacker 2>/dev/null

# Start each experiment with fresh generated logs.
: > logs/attacker.log
: > logs/dhcp_guard_alerts.log

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

# Start the following long-running services in separate terminals.

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

# start the victim (after the server, guard, and rogue-server simulation)

sudo ip netns exec victim dhclient -v -1 v-victim
sudo ip netns exec victim ip addr show dev v-victim
sudo ip netns exec victim ip route

# running defense 

sudo ip netns exec legit ip addr show v-legit # copy its current MAC into trusted_servers.json

sudo ip netns exec victim \
  python3 defender/dhcp_guard.py \
  --iface v-victim \
  --enforce

# generate plots

python3 tests/benchmark.py
python3 tests/plot_results.py
