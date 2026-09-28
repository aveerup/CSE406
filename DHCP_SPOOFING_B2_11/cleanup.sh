
echo "clean up the earlier lab"
sudo ip link del b-victim 2>/dev/null
sudo ip link del b-legit 2>/dev/null
sudo ip link del b-attacker 2>/dev/null
sudo ip link del br0 2>/dev/null
sudo ip netns del victim 2>/dev/null
sudo ip netns del legit 2>/dev/null
sudo ip netns del attacker 2>/dev/null


