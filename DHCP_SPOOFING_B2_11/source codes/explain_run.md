# Guide to `run.md`

`run.md` is a command checklist for building a small, isolated Linux network
lab. It has three participants on one virtual Layer-2 network:

```text
victim namespace      legitimate namespace      attacker namespace
      v-victim              v-legit                 v-attacker
          \                   |                         /
                    br0 (virtual bridge)
```

The namespaces are isolated from the host's normal network, while `br0` acts
like a simple Ethernet switch between them. Use this lab only on a machine you
control.

## 1. Reset the previous lab

```sh
sudo pkill -f dnsmasq
sudo pkill dhcpd
```

Stops any DHCP server processes left from an earlier run. `dnsmasq` is the
legitimate DHCP server used later. `dhcpd` is included in case an alternative
DHCP server was used during testing.

```sh
sudo ip link del v-victim 2>/dev/null
sudo ip link del b-victim 2>/dev/null
sudo ip link del v-legit 2>/dev/null
sudo ip link del b-legit 2>/dev/null
sudo ip link del v-attacker 2>/dev/null
sudo ip link del b-attacker 2>/dev/null
sudo ip link del br0
```

These commands remove the virtual interfaces and bridge created by a prior
run. Each `v-*` interface is one end of a virtual Ethernet pair; each `b-*`
interface is the matching end attached to the bridge.

`2>/dev/null` hides the expected error when an interface does not exist. The
commands are intentionally tolerant so the setup can be rerun.

## 2. Create isolated network participants

```sh
sudo ip netns add victim
sudo ip netns add legit
sudo ip netns add attacker
```

Creates three Linux network namespaces. A namespace has its own interfaces,
IP addresses, routes, firewall state, and processes.

- `victim`: the DHCP client that will request a configuration.
- `legit`: the legitimate DHCP server.
- `attacker`: the simulated rogue DHCP server.

```sh
sudo ip link add br0 type bridge
sudo ip link set br0 up
```

Creates and enables `br0`, a software Ethernet switch on the host. It connects
the three namespaces at Layer 2, so broadcasts such as DHCP discovery packets
reach both servers.

```sh
for ns in victim legit attacker; do
  sudo ip link add v-$ns type veth peer name b-$ns
  sudo ip link set v-$ns netns $ns
  sudo ip link set b-$ns master br0
  sudo ip link set b-$ns up
  sudo ip netns exec $ns ip link set v-$ns up
  sudo ip netns exec $ns ip link set lo up
done
```

The loop performs the same setup for each namespace:

1. Creates a **veth pair**, similar to a virtual Ethernet cable. For `victim`,
   the pair is `v-victim` and `b-victim`.
2. Moves `v-<namespace>` into that namespace. This becomes the namespace's
   network-card side of the cable.
3. Keeps `b-<namespace>` on the host and attaches it to `br0`. This becomes
   the switch-facing side.
4. Brings both ends up, plus the namespace loopback interface (`lo`).

After the loop, all participants share the same virtual Ethernet segment but
remain separate hosts.

```sh
sudo ip netns exec legit ip addr add 10.0.0.1/24 dev v-legit
```

Assigns the legitimate server the fixed address `10.0.0.1/24`. The `/24`
means the subnet is `10.0.0.0` through `10.0.0.255` with netmask
`255.255.255.0`.

## 3. Start the legitimate DHCP server

```sh
sudo ip netns exec legit dnsmasq \
  --interface=v-legit --bind-interfaces \
  --dhcp-range=10.0.0.100,10.0.0.150,255.255.255.0,12h \
  --dhcp-option=3,10.0.0.1 \
  --dhcp-option=6,8.8.8.8 \
  --no-daemon --log-dhcp
```

Runs `dnsmasq` **inside the `legit` namespace**. It is the server the victim
should trust.

| Option | Meaning |
| --- | --- |
| `--interface=v-legit` | Listen only on the lab interface. |
| `--bind-interfaces` | Bind specifically to that interface. |
| `--dhcp-range=...` | Lease addresses `10.0.0.100–10.0.0.150` for 12 hours. |
| `--dhcp-option=3,10.0.0.1` | Give clients default gateway `10.0.0.1`. DHCP option 3 is Router. |
| `--dhcp-option=6,8.8.8.8` | Give clients DNS server `8.8.8.8`. DHCP option 6 is DNS. |
| `--no-daemon` | Keep it in the foreground so its output is visible. |
| `--log-dhcp` | Log DHCP requests and leases. |

Leave this command running in its own terminal. The next sections need
separate terminals.

## 4. Start the simulated rogue server

```sh
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
```

Runs the project’s packet-crafting DHCP server inside the `attacker`
namespace. It listens for a client's DHCP requests and races to reply before
the legitimate server.

- It identifies itself as `10.0.0.66`.
- It offers addresses from `10.0.0.200–10.0.0.220`, separate from the
  legitimate pool so the source of a lease is easy to see.
- It advertises itself as both gateway and DNS server. This is the security
  impact being demonstrated: a victim accepting this lease would send these
  important network services through the rogue host.
- `--lease-time 300` makes the lease five minutes, helpful for repeated lab
  demonstrations.

Leave this running in a second terminal.

## 5. Inspect or trigger the victim

```sh
sudo ip netns exec victim ip route
```

Shows the victim's routing table. Before a DHCP lease, it normally has no
default route through this lab interface. After a lease, inspect it again to
see which server's gateway was accepted.

To actually produce a DHCP exchange, a DHCP client must be run in the victim
namespace. `run.md` does not currently include that command. Depending on
which client is installed, use one appropriate to your lab, for example:

```sh
sudo ip netns exec victim dhclient -v v-victim
```

This causes the normal DHCP sequence:

```text
victim: DHCPDISCOVER  (broadcast)
servers: DHCPOFFER    (both may reply)
victim: DHCPREQUEST   (chooses one offer)
chosen server: DHCPACK
```

Check `ip addr show v-victim` and `ip route` afterward. A lease in the
legitimate range with gateway `10.0.0.1` is legitimate; a lease in the rogue
range with gateway `10.0.0.66` shows the simulated attack won the race.

## 6. Run the defense

```sh
sudo ip netns exec legit ip addr show v-legit
```

Displays the legitimate server's MAC address and IP address. Copy these into
`defender/trusted_servers.json` before starting the guard. The IP must be a
plain host address, not CIDR notation:

```json
{
  "trusted_servers": [
    {"mac": "aa:bb:cc:dd:ee:ff", "ip": "10.0.0.1"}
  ]
}
```

The current example uses `10.0.0.1/24`, but `dhcp_guard.py` compares the
value directly with packet source IP `10.0.0.1`. Keeping `/24` there therefore
causes false rogue-server alerts for the legitimate server.

```sh
sudo ip netns exec victim \
  python3 defender/dhcp_guard.py \
  --iface v-victim \
  --enforce
```

Runs the host-based DHCP guard in the victim namespace.

- It captures DHCP replies on `v-victim` using a raw socket.
- It treats a reply as trusted only when its source MAC, source IP, and DHCP
  server identifier match the JSON allowlist.
- It logs rogue replies and also warns when two different servers answer one
  DHCP transaction ID (`xid`), a DHCP race.
- `--enforce` adds iptables rules so DHCP server replies are accepted only
  from listed trusted MAC addresses. Stop the guard cleanly with `Ctrl+C` so
  it can remove its rules.

For a clean demonstration, start the guard before running the victim DHCP
client command in the previous section.

## 7. Generate measurements and plots

```sh
python3 tests/benchmark.py
```

Measures the speed of the project’s custom checksum, packet building, and
packet parsing functions. It writes CSV data to `logs/benchmark.csv`.

```sh
python3 tests/plot_results.py
```

Reads the attacker log, defense log, and benchmark CSV, then creates plots in
`logs/plots/`. These visualize packet-processing performance, rogue response
latency, captured leases, and guard alerts.

## Recommended terminal order

1. Run the reset and setup sections once.
2. Terminal 1: start `dnsmasq` in `legit`.
3. Terminal 2: start `dhcp_guard.py --enforce` in `victim` after correcting
   the trusted-server entry.
4. Terminal 3: start `rogue_dhcp_server.py` in `attacker`.
5. Terminal 4: run the victim DHCP client and inspect its IP address/routes.
6. Stop the long-running processes with `Ctrl+C`, then run the reset section
   when finished.
