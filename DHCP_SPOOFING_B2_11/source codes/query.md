# Project Questions and Answers

## 1. What is an isolated Linux network? How do we create, use, modify, and remove one?

An **isolated Linux network** is a small, separate network created inside one
Linux machine. It lets you simulate multiple computers without connecting the
experiment to your real Wi-Fi, Ethernet network, or other external devices.

This project creates three virtual computers:

```text
victim ── veth ── br0 ── veth ── legit
                         └─ veth ── attacker
```

- `victim` acts as the DHCP client.
- `legit` runs the legitimate DHCP server.
- `attacker` runs the simulated rogue DHCP server.
- `br0` is a virtual Ethernet switch joining them.

The project uses two Linux features to build this:

1. **Network namespaces**: Separate network environments. Each namespace has
   its own interfaces, IP addresses, routes, firewall rules, and processes.
   A process started with `ip netns exec victim ...` sees the `victim`
   namespace's network rather than the host's network.
2. **Virtual Ethernet pairs (veth pairs)**: A pair behaves like a virtual
   network cable. A packet entering one end leaves from the other end. One end
   is placed in a namespace (`v-victim`, for example); the other remains on
   the host (`b-victim`) and is attached to the bridge.

### Create the network

First create the three namespaces:

```sh
sudo ip netns add victim
sudo ip netns add legit
sudo ip netns add attacker
```

Then create and enable a bridge:

```sh
sudo ip link add br0 type bridge
sudo ip link set br0 up
```

Next, create one veth pair per namespace. The project does that in a loop:

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

For the `victim` namespace, this creates a cable with two ends:

```text
v-victim (inside victim) <---- virtual cable ----> b-victim (on host, connected to br0)
```

Finally, the legitimate DHCP server is given a fixed address so it can act as
the intended default gateway:

```sh
sudo ip netns exec legit ip addr add 10.0.0.1/24 dev v-legit
```

### Use the network

Run a command inside a namespace with this pattern:

```sh
sudo ip netns exec <namespace> <command>
```

Examples from this project:

```sh
# Inspect the victim's interfaces and routes
sudo ip netns exec victim ip addr
sudo ip netns exec victim ip route

# Run the legitimate DHCP service only inside the legit namespace
sudo ip netns exec legit dnsmasq ...

# Run the project's simulated rogue server only inside attacker
sudo ip netns exec attacker python3 attacker/rogue_dhcp_server.py ...
```

The DHCP broadcast from `victim` travels through `v-victim`, across the bridge
`br0`, and reaches both server namespaces. It does not need to leave the
virtual lab.

### Modify the network

Useful inspection commands:

```sh
sudo ip netns list                         # list namespaces
sudo ip netns exec victim ip link show     # show victim interfaces and MACs
sudo ip netns exec victim ip addr show     # show assigned addresses
sudo ip netns exec victim ip route         # show routes
ip link show br0                           # inspect the host-side bridge
bridge link                                # show bridge ports, if available
```

Common modifications:

```sh
# Replace an address (remove first, then add the new one)
sudo ip netns exec legit ip addr del 10.0.0.1/24 dev v-legit
sudo ip netns exec legit ip addr add 10.0.0.254/24 dev v-legit

# Temporarily disconnect a participant
sudo ip netns exec attacker ip link set v-attacker down

# Reconnect it
sudo ip netns exec attacker ip link set v-attacker up
```

If the legitimate server IP changes, update the DHCP-server command's gateway
option and `defender/trusted_servers.json` as well. In the JSON file, use the
plain host IP (`10.0.0.1`), not CIDR notation (`10.0.0.1/24`), because the
guard compares it to a packet source IP.

### Remove the network

Stop long-running lab processes first with `Ctrl+C`. Then delete the bridge
ports, bridge, and namespaces:

```sh
sudo ip link del b-victim 2>/dev/null
sudo ip link del b-legit 2>/dev/null
sudo ip link del b-attacker 2>/dev/null
sudo ip link del br0 2>/dev/null
sudo ip netns del victim 2>/dev/null
sudo ip netns del legit 2>/dev/null
sudo ip netns del attacker 2>/dev/null
```

Deleting a host-side `b-*` veth endpoint also removes its peer inside the
namespace. Deleting `br0` removes the software switch, while deleting each
namespace removes its isolated network environment. The current reset section
in `run.md` removes interfaces and the bridge but does not remove namespaces;
include the `ip netns del` commands above before recreating a fully fresh lab.

### Why it is useful here

The isolation gives the project a repeatable environment for observing DHCP
behavior and defenses without involving a real LAN. It also means each role
can be started, stopped, inspected, and reset independently.

## 2. What does each command in the virtual-interface setup loop do?

The commands run once for every namespace named by the loop:

```sh
for ns in victim legit attacker; do
  # commands...
done
```

`$ns` is the loop variable. Its value is `victim`, then `legit`, then
`attacker`. For example, in the `victim` iteration, `v-$ns` becomes
`v-victim` and `b-$ns` becomes `b-victim`.

```sh
sudo ip link add v-$ns type veth peer name b-$ns
```

Creates a **virtual Ethernet pair**—two connected virtual interfaces that act
like the two ends of an Ethernet cable. In the first iteration it creates:

```text
v-victim <---- virtual cable ----> b-victim
```

A packet sent through one endpoint appears at the other endpoint. At creation,
both endpoints initially exist in the host's default network namespace.

```sh
sudo ip link set v-$ns netns $ns
```

Moves the `v-*` endpoint into the named network namespace. For example,
`v-victim` is moved into `victim`; it becomes that simulated computer's
network interface. `b-victim` stays on the host side.

```sh
sudo ip link set b-$ns master br0
```

Attaches the host-side endpoint to `br0`. Here, `master br0` means that `br0`
is the interface's bridge master—not that it has administrator privileges.

For example, `b-victim` becomes a port on the virtual Ethernet switch. The
same happens to `b-legit` and `b-attacker`, allowing their namespace-side
peers to exchange Ethernet frames through the bridge.

```sh
sudo ip link set b-$ns up
```

Enables the host-side endpoint. Network interfaces are administratively down
when created, so this makes the bridge-facing end able to send and receive
frames.

```sh
sudo ip netns exec $ns ip link set v-$ns up
```

Runs `ip link set v-$ns up` **inside** the current namespace and enables the
namespace-side endpoint. Both ends of a veth connection must be up for normal
traffic to pass. For the first iteration, it is equivalent to:

```sh
sudo ip netns exec victim ip link set v-victim up
```

```sh
sudo ip netns exec $ns ip link set lo up
```

Enables the namespace's `lo` (loopback) interface. Loopback lets software in
the same namespace communicate with itself using addresses such as
`127.0.0.1`. It is standard practice to enable it in every namespace, even
though the DHCP exchange itself uses `v-*`, not loopback.

After one full iteration, the resulting path is:

```text
process inside victim
       ↓
v-victim (inside the victim namespace)
       ↓
b-victim (host-side bridge port)
       ↓
br0 (virtual Layer-2 switch)
```

After all three iterations, `br0` forwards broadcasts and normal Ethernet
traffic between the victim, legitimate-server, and attacker namespaces.

## 3. Why are `netns` and `master` used in these commands?

```sh
sudo ip link set v-$ns netns $ns
```

`netns` means **network namespace**. This command changes which network
environment owns an interface.

Before this command, both endpoints of the new veth pair belong to the host's
default network namespace:

```text
Host namespace:  v-victim <----> b-victim
```

When `$ns` is `victim`, the command moves `v-victim` into the `victim`
namespace:

```text
victim namespace: v-victim <----> b-victim : Host namespace
```

This is necessary because `v-victim` must behave as the victim computer's
network card. After moving it, commands running in `victim` can see and use
`v-victim`, while ordinary host commands cannot see it unless they explicitly
enter that namespace:

```sh
sudo ip netns exec victim ip link show
```

In short: **`netns $ns` puts one end of the virtual cable inside the simulated
computer.**

```sh
sudo ip link set b-$ns master br0
```

`master` assigns an interface to a controller interface. Here the controller
is `br0`, which is a Linux bridge. A bridge behaves like a virtual Ethernet
switch, and the interfaces attached to it become its switch ports.

For the victim iteration, the command makes `b-victim` a port of `br0`:

```text
v-victim (victim namespace) <----> b-victim --[port]--> br0 bridge
```

The command is equivalent in meaning to saying: “connect the host-side end of
the victim's virtual cable to the virtual switch.” The other host-side
endpoints, `b-legit` and `b-attacker`, are attached to the same bridge, so all
three namespace-side interfaces are on one virtual LAN.

`master` does **not** mean a privileged user or a primary server. It is Linux
networking terminology for the bridge that manages forwarding for its member
interfaces. Without `master br0`, each `b-*` endpoint would exist but would
not be connected to the others, so the namespaces could not exchange DHCP
broadcasts through the lab network.

## 4. What do the parts of `sudo ip netns exec $ns ip link set v-$ns up` mean, and why run it inside the namespace?

```sh
sudo ip netns exec $ns ip link set v-$ns up
```

For the first loop iteration, where `$ns` is `victim`, the shell expands this
into:

```sh
sudo ip netns exec victim ip link set v-victim up
```

Each part has a separate job:

| Part | Meaning |
| --- | --- |
| `sudo` | Run with administrator privileges. Changing interface state needs network-administration permission. |
| `ip` | The Linux command-line networking tool. |
| `netns exec victim` | Enter the network context of `victim` only for the command that follows. |
| `ip link` | Work with network interfaces at Layer 2. |
| `set v-victim` | Change the state/configuration of the `v-victim` interface. |
| `up` | Administratively enable that interface. |

The important point is that the earlier command moved `v-victim` into the
`victim` namespace:

```sh
sudo ip link set v-victim netns victim
```

After that move, `v-victim` no longer belongs to the host's default network
namespace. Therefore this host-side command would not find it:

```sh
# This will fail after v-victim has been moved.
sudo ip link set v-victim up
```

Instead, `ip netns exec victim` temporarily makes the following `ip link`
command see the interfaces that belong to `victim`. It is similar to opening a
terminal inside that simulated computer, running the command there, and then
returning to the host terminal.

Both ends of the virtual cable should be enabled:

```text
victim namespace                    host namespace
v-victim: up  <---- veth pair ----> b-victim: up
```

`b-victim` is enabled from the host because it remains on the host. `v-victim`
is enabled inside `victim` because that is where it now belongs. If either end
is administratively down, normal DHCP frames cannot pass through that virtual
connection.

## 5. What does `sudo ip link add br0 type bridge` do? When should I use `ip link` or `ip netns`?

```sh
sudo ip link add br0 type bridge
```

This creates `br0`, a Linux **bridge**. A bridge is a software Layer-2
Ethernet switch: it learns MAC-address locations and forwards Ethernet frames
between attached ports. In this project, `b-victim`, `b-legit`, and
`b-attacker` are later attached as ports, so the three namespaces share one
virtual LAN.

The parts mean:

| Part | Meaning |
| --- | --- |
| `sudo` | Use administrator privileges, required to create network interfaces. |
| `ip` | Linux networking command-line tool. |
| `link` | Work with network interfaces (Layer-2 links), such as Ethernet, Wi-Fi, veth, bridge, or loopback interfaces. |
| `add` | Create a new interface. |
| `br0` | Name of the new interface. `br` commonly means bridge; `0` distinguishes it from a possible future `br1`. |
| `type bridge` | Select bridge as the interface type, rather than a normal Ethernet device, a veth endpoint, VLAN, and so on. |

Creation alone is not enough: a new interface starts administratively down.
The next command enables it:

```sh
sudo ip link set br0 up
```

### Choosing `ip link` versus `ip netns`

Use `ip link` when the thing you want to create, inspect, remove, or change is
a **network interface**. Examples:

```sh
ip link show                         # list interfaces in the current namespace
sudo ip link set br0 up              # enable a bridge/interface
sudo ip link add br0 type bridge     # create a bridge interface
sudo ip link del br0                 # delete an interface
sudo ip link set b-victim master br0 # attach an interface to a bridge
```

Use `ip netns` when you want to create, list, remove, or enter a **network
namespace**. A namespace is the isolated network environment that contains
interfaces; it is not an interface itself. Examples:

```sh
sudo ip netns add victim                 # create an isolated network environment
sudo ip netns list                       # list namespaces
sudo ip netns exec victim ip link show   # run a command inside victim's network
sudo ip netns del victim                 # remove the namespace
```

A useful mental model is:

```text
network namespace = a simulated computer's network environment
network link      = one interface/cable/switch port inside an environment
```

So the project first uses `ip netns add` to create the three environments,
then uses `ip link` to create interfaces and the bridge. It uses `ip netns
exec` whenever it needs to run `ip link`, `ip addr`, `ip route`, or a server
program inside one particular simulated computer.

For completeness, `ip` has other subcommands for other kinds of networking
data:

| Goal | Typical command |
| --- | --- |
| Assign/view IP addresses | `ip addr` |
| View/change routing | `ip route` |
| View/change interfaces | `ip link` |
| Manage namespaces | `ip netns` |
| View ARP/neighbor mappings | `ip neigh` |

## 6. How do `sudo pkill -f dnsmasq` and `sudo pkill dhcpd` work? What are `dnsmasq` and `dhcpd`?

```sh
sudo pkill -f dnsmasq
sudo pkill dhcpd
```

These are cleanup commands at the beginning of the lab. They stop DHCP-server
processes that may still be running from a previous test, preventing an old
server from affecting the next run.

### What are `dnsmasq` and `dhcpd`?

- **`dnsmasq`** is a lightweight network service. It can provide DNS caching
  and forwarding, DHCP address assignment, and related local-network
  services. This project actually starts `dnsmasq` in the `legit` namespace,
  where it acts as the legitimate DHCP server.
- **`dhcpd`** is the conventional process name for the ISC DHCP server
  daemon. It is another DHCP-server implementation. This project does not
  start it in `run.md`, but the reset command stops it in case it was used in
  an earlier experiment or is running on the lab machine.

### Parts of the commands

```sh
sudo pkill -f dnsmasq
```

| Part | Meaning |
| --- | --- |
| `sudo` | Run with administrator privileges, so processes started as root can be signalled. |
| `pkill` | Find processes matching a pattern, then send each one a signal. |
| `-f` | Match against the process's full command line, including its command-line arguments. |
| `dnsmasq` | The search pattern. |

`-f` matters here because the process was started with a long command line,
such as `dnsmasq --interface=v-legit ...`. It makes `pkill` search that whole
line for `dnsmasq`.

```sh
sudo pkill dhcpd
```

Without `-f`, `pkill` matches the process name itself. It searches for a
process named `dhcpd` and signals it.

### Does `pkill` need a process ID?

No. `kill` and `pkill` are related but take different inputs:

```sh
kill 1234             # signal the specific process whose PID is 1234
pkill dnsmasq         # find processes matching dnsmasq, then signal all matches
pgrep dnsmasq         # only print the matching process IDs; do not signal them
```

`pkill` internally finds the matching PIDs first, then signals them. You do
not have to discover and type each PID manually.

By default, `pkill` sends `SIGTERM` (signal 15), which asks a process to stop
cleanly. It is more accurate to say it **signals** the process than that it
immediately kills it; a program may handle or ignore `SIGTERM`. A forced
signal such as `pkill -9 ...` uses `SIGKILL`, but it should be a last resort
because the process cannot clean up first.

### Important caution about `-f`

`pkill -f dnsmasq` is broader than `pkill dnsmasq`: it can match any process
whose full command line contains the text `dnsmasq`. That is acceptable for a
small, controlled lab cleanup, but exact matching is safer when needed:

```sh
pgrep -af dnsmasq      # inspect matching PID(s) and full command lines first
sudo pkill -x dnsmasq  # match the exact process name only
```

If no matching process is running, `pkill` prints nothing and exits with a
non-zero status. That is expected during reset; the commands are simply trying
to ensure no old DHCP server remains.

## 7. What does “matching processes” mean?

A **process** is one running instance of a program. For example, after this
lab command starts the legitimate server:

```sh
dnsmasq --interface=v-legit --dhcp-range=...
```

Linux gives that running instance information such as:

```text
PID:          4281
process name: dnsmasq
command line: dnsmasq --interface=v-legit --dhcp-range=...
```

**Matching** means comparing text you provide with one of those pieces of
process information and selecting the processes whose text fits the pattern.

For example:

```sh
pgrep dnsmasq
```

looks for processes whose **process name** matches `dnsmasq`. If it finds the
server above, it prints its PID, such as `4281`.

```sh
pgrep -f dnsmasq
```

uses `-f` to search the complete **command line** instead. The command line
contains the word `dnsmasq`, so it matches too.

`pkill` performs the same matching but sends a signal to every selected
process:

```text
pkill dnsmasq
  │
  ├─ find every process whose name matches "dnsmasq"
  └─ send SIGTERM to each matching PID
```

You can inspect matches safely before stopping anything:

```sh
pgrep -a dnsmasq       # PID and command line for name matches
pgrep -af dnsmasq      # PID and command line for full-command-line matches
```

This is why the word **matching** is used rather than “one process”: the
pattern may find zero, one, or several running processes. In a lab, several
old `dnsmasq` instances could exist, and `pkill` attempts to stop all of the
ones that match.

## 8. What happens if multiple processes match `pkill`?

`pkill` sends its signal to **every** process that matches the pattern. It is
not limited to the first match it finds.

For example, suppose these two `dnsmasq` processes are running:

```text
PID 4281: dnsmasq --interface=v-legit --dhcp-range=...
PID 7730: dnsmasq --interface=test0 --dhcp-range=...
```

Then:

```sh
sudo pkill -f dnsmasq
```

finds both command lines and sends `SIGTERM` to both PIDs. This is useful for
the project's reset step because it aims to remove leftover DHCP-server
processes from previous lab attempts.

It can also be too broad. If the host is using another `dnsmasq` process for
an unrelated network, that process may match and be stopped as well. For that
reason, inspect before signalling whenever you are unsure:

```sh
pgrep -af dnsmasq
```

The output shows every matched PID and its complete command line. You can then
choose one specific process:

```sh
sudo kill 4281
```

or narrow the rule. For example, an exact process-name match avoids matching a
command that merely mentions the word:

```sh
sudo pkill -x dnsmasq
```

However, `-x` can still stop several separate processes all named `dnsmasq`.
To target the lab most precisely, identify the correct PID from `pgrep -af`
and use `kill <PID>`. The general rule is: use `pkill` for deliberate
group-cleanup; use `kill PID` when only one known process should stop.

## 9. What does `ip addr add 10.0.0.1/24 dev v-legit` mean?

In the full command, `sudo ip netns exec legit` has already placed us inside
the `legit` namespace. The remaining part is:

```sh
ip addr add 10.0.0.1/24 dev v-legit
```

| Part | Meaning |
| --- | --- |
| `ip` | The Linux networking tool. |
| `addr` | Work with IP addresses assigned to interfaces. `address` is the longer equivalent spelling. |
| `add` | Add a new address; it does not replace every existing address on the interface. |
| `10.0.0.1/24` | The IPv4 address to assign plus its prefix length (subnet size). |
| `dev` | Means “device”; the next word names the interface that receives the address. |
| `v-legit` | The network interface inside the `legit` namespace. |

### Understanding `10.0.0.1/24`

`10.0.0.1` is the interface's own address. `/24` means the first 24 bits are
the network portion of the address, which is equivalent to subnet mask
`255.255.255.0`.

```text
Address:      10.0.0.1
Prefix:       /24
Subnet mask:  255.255.255.0
Network:      10.0.0.0/24
Usable hosts: 10.0.0.1 through 10.0.0.254
Broadcast:    10.0.0.255
```

This tells Linux that devices with addresses such as `10.0.0.66` or
`10.0.0.200` are on the same local network as `v-legit`; traffic for them can
be sent directly as Ethernet frames rather than sent to another router.

`dev v-legit` is needed because a namespace can have several interfaces. It
removes ambiguity by saying exactly where the address belongs. You can verify
the result with:

```sh
sudo ip netns exec legit ip addr show dev v-legit
```

If you had to remove this same address later, the parallel command would be:

```sh
sudo ip netns exec legit ip addr del 10.0.0.1/24 dev v-legit
```

## 10. What is the `v-legit` device? Is it a router, mobile phone, or something else?

`v-legit` is a **virtual Ethernet network interface**. It is not a physical
router, mobile phone, or separate real device. It is the virtual equivalent of
an Ethernet/Wi-Fi network card attached to the simulated `legit` computer.

The project creates a virtual cable with two endpoints:

```text
inside the legit namespace                  on the host
v-legit  <--------- virtual cable --------> b-legit
                                                │
                                               br0
```

The names are chosen by the project:

- `v-legit`: `v` likely means “virtual”; this endpoint is inside the
  `legit` namespace.
- `b-legit`: `b` likely means “bridge”; this endpoint stays on the host and
  is attached to the `br0` virtual switch.

The `legit` **namespace** is what represents the separate simulated machine.
It is most accurate to think of it as a small virtual server/computer with one
network card, `v-legit`. The project starts `dnsmasq` in that namespace, so
its role is **legitimate DHCP server**.

```text
Role / object                 What it is in this project
----------------------------  ----------------------------------------------
legit                         A simulated Linux host (network namespace)
v-legit                       Its virtual Ethernet network card
dnsmasq                       The DHCP-server program running on that host
10.0.0.1                      The IP address assigned to that interface
br0                           The virtual Ethernet switch joining all hosts
```

`v-legit` is not automatically a router just because it is assigned
`10.0.0.1` and advertised as a DHCP gateway. A real router must also forward
packets between at least two networks, normally with IP forwarding enabled and
often NAT/firewall rules. This lab does not configure those features. It uses
the gateway value to demonstrate the dangerous DHCP option that a rogue server
can replace.

The same design applies to the other roles:

```text
victim namespace   → v-victim is its virtual network card
attacker namespace → v-attacker is its virtual network card
```

So, if a physical-network analogy helps: each namespace is a separate small
computer, each `v-*` interface is that computer's network card, and `br0` is
the Ethernet switch connecting the cards.

## 11. What does the `dnsmasq` command do, part by part?

```sh
sudo ip netns exec legit dnsmasq \
  --interface=v-legit --bind-interfaces \
  --dhcp-range=10.0.0.100,10.0.0.150,255.255.255.0,12h \
  --dhcp-option=3,10.0.0.1 \
  --dhcp-option=6,8.8.8.8 \
  --no-daemon --log-dhcp
```

This starts the legitimate DHCP server inside the simulated `legit` host. It
waits for DHCP client broadcasts from the victim and gives clients an address,
network mask, gateway, DNS server, and lease duration.

### The command structure

| Part | Meaning |
| --- | --- |
| `sudo` | Run with administrator privileges. DHCP listens on privileged UDP port 67 and configures network-related services. |
| `ip netns exec legit` | Run only the following program inside the `legit` namespace. Therefore the server sees `v-legit`, not the host's regular interfaces. |
| `dnsmasq` | Start the lightweight DNS/DHCP service. With the options below, this project uses its DHCP-server feature. |
| `\` | A shell line-continuation character. It means “this command continues on the next line.” All displayed lines are one command. |

### Interface options

```sh
--interface=v-legit
```

Tell `dnsmasq` to serve DHCP on `v-legit`, the legitimate server's virtual
network card. DHCP broadcasts sent by `v-victim` reach this interface through
the `br0` bridge.

```sh
--bind-interfaces
```

Tell `dnsmasq` to bind specifically to the selected interface/address instead
of listening broadly on every interface it can see. This keeps the service
limited to the virtual lab network and avoids conflicts with other local
services.

### Address-pool option

```sh
--dhcp-range=10.0.0.100,10.0.0.150,255.255.255.0,12h
```

This defines which addresses the legitimate DHCP server may lease:

| Value | Meaning |
| --- | --- |
| `10.0.0.100` | First leaseable client address. |
| `10.0.0.150` | Last leaseable client address. |
| `255.255.255.0` | Client subnet mask; equivalent to prefix `/24`. |
| `12h` | Lease duration: 12 hours. Clients must renew before it expires. |

So a normal client can receive an address from `10.0.0.100` through
`10.0.0.150`. The rogue server intentionally uses the separate range
`10.0.0.200–10.0.0.220`, making it easy to recognize which server supplied a
lease.

### DHCP configuration options

```sh
--dhcp-option=3,10.0.0.1
```

Send DHCP **option 3**, called the *Router* option. It tells a client that its
default gateway should be `10.0.0.1`. A default gateway is where a client
sends traffic intended for destinations outside its local subnet.

```sh
--dhcp-option=6,8.8.8.8
```

Send DHCP **option 6**, called the *Domain Name Server* option. It tells a
client to use `8.8.8.8` for DNS lookups. DNS translates names such as
`example.com` into IP addresses.

These two options are central to the project: a rogue DHCP server can try to
replace the real gateway and DNS values with attacker-controlled ones.

### Runtime and logging options

```sh
--no-daemon
```

Keep `dnsmasq` in the foreground instead of making it detach and run in the
background as a daemon. This makes its output visible in the terminal and
makes `Ctrl+C` stop it directly.

```sh
--log-dhcp
```

Log DHCP activity, such as client requests, offers, acknowledgements, and
leases. These messages help verify that the legitimate server saw the victim's
DHCP request.

Because `dnsmasq` stays in the foreground, leave it running in its own
terminal while using other terminals for the guard, rogue-server simulation,
and victim DHCP client.

## 12. What is `common/dhcp.py` for?

`common/dhcp.py` is the project's shared **DHCP packet-format library**. It is
not a standalone program that you run from the terminal. Instead, the attacker
and defender import it so they use the same rules for creating and reading
DHCP messages.

In simple terms, it translates between:

```text
Python values                         DHCP packet bytes sent on the network
"10.0.0.66", OFFER, client MAC   ⇄   binary DHCP message
```

### Who uses it?

| Project component | How it uses `dhcp.py` |
| --- | --- |
| `attacker/rogue_dhcp_server.py` | Builds forged DHCP `OFFER` and `ACK` messages, then parses client `DISCOVER` and `REQUEST` messages. |
| `defender/dhcp_guard.py` | Parses server replies so it can identify the message type, offered IP, gateway, DNS, server ID, and client MAC. |
| `tests/benchmark.py` | Measures the speed of DHCP packet building and parsing. |

### What each part does

#### 1. DHCP constants

The first section gives meaningful names to protocol values:

```python
SERVER_PORT = 67
CLIENT_PORT = 68

DISCOVER, OFFER, REQUEST, DECLINE, ACK, NAK, RELEASE, INFORM = range(1, 9)
```

For example, code can write `dhcp.OFFER` instead of the unexplained number
`2`, and `dhcp.SERVER_PORT` instead of `67`. It also defines DHCP option
numbers, including:

```text
1   subnet mask
3   router/default gateway
6   DNS server
50  requested IP address
51  lease time
53  DHCP message type
54  DHCP server identifier
```

#### 2. Option-building helpers

DHCP options are small *type-length-value* fields at the end of a DHCP packet.
For example, the message type option contains “option 53, length 1, value 2”
for a DHCP Offer.

```python
opt_byte(...)  # create a one-byte option, such as message type
opt_ip(...)    # create an IPv4-address option, such as gateway or DNS
opt_u32(...)   # create a four-byte integer option, such as lease time
build_options(...)  # join options and append the required end marker
```

The rogue server uses these functions to construct the options in the DHCP
replies it sends.

#### 3. `build_dhcp_packet(...)`

This function creates the binary DHCP payload. It fills fields such as:

```text
op       whether the message is a request or reply
xid      transaction ID linking a reply to a client's request
chaddr   client hardware (MAC) address
yiaddr   "your IP address" offered to the client
siaddr   server IP address
options  DHCP configuration values
```

The resulting bytes are then wrapped by the other shared modules in a UDP
header, IPv4 header, and Ethernet header before being sent as a frame.

#### 4. `parse_dhcp_packet(data)`

This does the reverse. It receives raw DHCP payload bytes and returns a Python
dictionary with readable values, for example:

```python
{
    "xid": 0x12345678,
    "chaddr": "aa:bb:cc:dd:ee:ff",
    "yiaddr": "10.0.0.200",
    "msg_type": dhcp.OFFER,
    "server_id": "10.0.0.66",
    "requested_ip": "10.0.0.200",
}
```

The defender relies on this parsed data to decide whether a DHCP reply comes
from the allowlisted server and to log suspicious gateway/DNS settings.

### Why the project needs this file

Python's normal network APIs do not automatically give the project a complete
DHCP message builder/parser at the Ethernet-frame level. `dhcp.py`, together
with `eth.py`, `ip.py`, `udp.py`, and `checksum.py`, lets the project work
directly with the protocol structure rather than using a packet-crafting
library.

It intentionally implements the subset of DHCP needed for this controlled
demonstration; it is not a complete production DHCP implementation.

## 13. Why did this project not use a production-level DHCP implementation?

Because the main goal is to **show how DHCP spoofing works at packet level and
how it can be detected**, not to build a dependable DHCP service for a real
network.

The project actually uses both approaches:

```text
Legitimate DHCP server  → dnsmasq (mature, real-world DHCP software)
Rogue-server simulation → custom Python packet code (teaching/demo code)
```

Using `dnsmasq` for the legitimate server makes the normal side of the lab
realistic. Using small custom modules such as `dhcp.py`, `udp.py`, and `ip.py`
for the simulated rogue server makes the protocol fields visible and
controllable for study.

### What the custom implementation helps demonstrate

- How a DHCP message is structured: fixed fields, magic cookie, and options.
- How an attacker-controlled reply can set the offered IP, gateway, DNS,
  server identifier, and lease time.
- How Ethernet, IP, UDP, and DHCP headers fit together in one raw frame.
- How the guard can read the same packet fields and identify an unexpected
  server.
- The time required to build and parse packets, which the benchmark measures.

If the project used only a library such as Scapy or a full DHCP server, much of
that packet-level logic would be hidden behind library calls. That would be
convenient, but less useful for explaining the security mechanism in a course
project.

### Why it is not production-ready

A real DHCP implementation must handle much more than this demonstration:

| Production concern | What a full implementation needs |
| --- | --- |
| Protocol coverage | DHCP relays, many more options, renew/rebind/release behavior, option overload, and unusual client states. |
| Robust parsing | Strict length/bounds checks and safe handling of malformed packets. |
| Lease management | Persistent lease storage, conflict detection, expiration, recovery after restart, and concurrent clients. |
| Reliability | Retries, retransmissions, timing behavior, error handling, monitoring, and logging. |
| Security | Authentication where applicable, access controls, DHCP snooping at switches, alerting, and resistance to spoofed MAC/IP values. |
| Operations | Configuration management, service supervision, updates, tests, and support for large networks. |

The custom parser is purposely small and assumes well-formed packets in the
controlled namespace lab. For example, it only implements the DHCP options
needed by the project and does not aim to cover every valid DHCP case.

### Which approach should be used in practice?

For a real network, use a maintained DHCP server such as `dnsmasq`, Kea DHCP,
or an enterprise network appliance, together with switch-level DHCP snooping
and trusted-port controls. Use this project’s custom code only for learning,
testing in an authorized isolated lab, and demonstrating the detection idea.

## 14. How do I run the project step by step, and what output should I expect?

Run this only on a Linux machine you control. It creates an isolated namespace
lab; do not use these steps on a real network.

### Before starting

Open a terminal in the source directory:

```sh
cd "/home/avee/Downloads/DHCP_SPOOFING_B2_11/source codes"
```

You need Linux with `sudo`, `ip`, Python 3, `dnsmasq`, a DHCP client such as
`dhclient`, and `iptables` for `--enforce`. Graph generation additionally
needs `matplotlib`. Check the main programs with:

```sh
command -v ip python3 dnsmasq dhclient iptables
```

### 1. Clean up an earlier lab

Stop any lab programs in their terminals with `Ctrl+C`. Then stop any
remaining processes **inside the lab namespaces** and remove the old lab:

```sh
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
```

This avoids the old broad `pkill` cleanup. Start every experiment with fresh
logs as `run.md` now does:

```sh
: > logs/attacker.log
: > logs/dhcp_guard_alerts.log
```

### 2. Create the isolated network

Run these once in **Terminal 1**:

```sh
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
```

Check that `v-legit` has `10.0.0.1/24` and `br0` has three ports:

```sh
sudo ip netns exec legit ip addr show dev v-legit
bridge link
```

### 3. Correct the trusted-server allowlist

Get the current MAC address:

```sh
sudo ip netns exec legit cat /sys/class/net/v-legit/address
```

Put it in `defender/trusted_servers.json`, using a plain IP address—not CIDR:

```json
{
  "trusted_servers": [
    {"mac": "replace-with-the-command-output", "ip": "10.0.0.1"}
  ]
}
```

The `/24` must not be in this JSON field, or the guard will falsely classify
the legitimate server as rogue.

### 4. Start the legitimate server

In **Terminal 2**, run:

```sh
sudo ip netns exec legit dnsmasq \
  --interface=v-legit --bind-interfaces \
  --dhcp-range=10.0.0.100,10.0.0.150,255.255.255.0,12h \
  --dhcp-option=3,10.0.0.1 \
  --dhcp-option=6,8.8.8.8 \
  --no-daemon --log-dhcp
```

Leave it running. When a client asks for a lease, it prints DHCP events such
as `DHCPDISCOVER`, `DHCPOFFER`, `DHCPREQUEST`, and `DHCPACK`.

### 5. Start the defense

In **Terminal 3**, run:

```sh
sudo ip netns exec victim \
  python3 defender/dhcp_guard.py \
  --iface v-victim \
  --enforce
```

Expected startup output resembles:

```text
[dhcp-guard] Enforcement ENABLED: only <legitimate-MAC> may deliver DHCP server replies to this host
[dhcp-guard] DHCP Guard watching for rogue DHCP servers (... enforce=True)
```

It also writes to `logs/dhcp_guard_alerts.log`.

### 6. Start the simulated rogue server

In **Terminal 4**, run:

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

Expected startup output resembles:

```text
[rogue-dhcp] Rogue DHCP server up on v-attacker (attacker_ip=10.0.0.66 mac=...) - gateway/dns -> 10.0.0.66
```

### 7. Trigger the victim DHCP request

`run.md` only displays the victim route table; it does not start a DHCP
client. In **Terminal 5**, trigger one exchange:

```sh
sudo ip netns exec victim dhclient -v -1 v-victim
```

`-v` prints the exchange; `-1` exits after a successful lease or failure. If
`dhclient` is unavailable, use the DHCP client installed by your distribution,
such as `udhcpc`.

Inspect the resulting configuration:

```sh
sudo ip netns exec victim ip addr show dev v-victim
sudo ip netns exec victim ip route
```

### Expected results

Both servers can receive the victim broadcast. Which offer the client accepts
is timing-dependent.

| Situation | Expected result |
| --- | --- |
| Legitimate reply | `dnsmasq` logs an offer/ack; the guard logs `Legit DHCP OFFER` or `Legit DHCP ACK`. |
| Rogue reply observed | The guard logs `ROGUE DHCP OFFER` or `ROGUE DHCP ACK` with source IP `10.0.0.66`. |
| Both respond to one request | The guard logs `RACE CONDITION: xid=... has 2 distinct DHCP servers replying`. |
| Guard running with correct allowlist | The raw socket can still observe/log rogue packets, while iptables is intended to stop the victim networking stack accepting untrusted DHCP replies. The victim should normally receive a legitimate lease. |
| Guard off or started too late | The rogue server may win. Its log records `LEASE ACKNOWLEDGED (unverified acceptance)` once per unique MAC/IP lease; verify the victim address and route before treating it as accepted. |

`10.0.0.1` is not a complete Internet router in this lab because forwarding
and Internet connectivity are not configured. The meaningful result is which
DHCP configuration was accepted and whether the guard detected it.

### 8. Generate measurements and graphs

After stopping the long-running programs with `Ctrl+C`, run:

```sh
python3 tests/benchmark.py
python3 tests/plot_results.py
```

This creates `logs/benchmark.csv` and PNG charts in `logs/plots/`.

### 9. Finish cleanly

Stop the guard with `Ctrl+C` first so it removes its iptables rules. Stop the
servers with `Ctrl+C`, then run the cleanup commands from step 1.

## 15. How could the earlier report show 10 DHCPDISCOVER events but 70 “victims captured”?

That was a measurement bug in the earlier version of the project. It counted
repeated forged-ACK log events as if each represented a new victim. The current
code fixes this by recording each unique `(MAC, IP)` lease once and labelling
it `LEASE ACKNOWLEDGED (unverified acceptance)` rather than a confirmed victim
capture.

The historical report is still incorrect: 70 log events never established 70
different victims or 70 accepted leases.

The plotting code counts a discovery only when it sees a `forged OFFER` log
line:

```python
if "forged OFFER" in line:
    discovers += 1
```

It increments `victims` once for **every** `VICTIM CAPTURED` log line:

```python
elif "VICTIM CAPTURED" in line:
    victims += 1
```

However, the rogue server writes `VICTIM CAPTURED` every time it receives a
matching DHCP `REQUEST`:

```python
self._send_dhcp(..., dhcp.ACK)
self.captured.append((chaddr, offered_ip, time.time()))
log.warning("VICTIM CAPTURED: mac=%s ip=%s ...", chaddr, offered_ip, ...)
```

It does not check whether this MAC address was already recorded, does not
remove the transaction from `offered_xids`, and does not verify the victim
actually configured the lease. Therefore one client can create many “capture”
events.

```text
One victim sends DHCPDISCOVER       → 1 forged OFFER log line
The victim retransmits DHCPREQUEST → 1 forged ACK + 1 “captured” log line
The victim retransmits again       → another ACK + another “captured” line
... repeated requests ...          → many “captured” lines for one victim
```

DHCP clients can retransmit requests when a reply is delayed, lost, filtered,
or during repeated testing. Since the attacker keeps the original transaction
record, it replies to those repeated requests and counts each reply again.

### What the figure should say

Instead of:

```text
10 DHCPDISCOVER events; 70 victims captured
```

it should say something like:

```text
10 forged-OFFER/DHCPDISCOVER events; 70 forged-ACK/capture log events
```

Those are packet/log events, not unique compromised clients.

### How to measure real unique victims

For the attacker's log, count unique client MAC addresses, or unique
`(client MAC, assigned IP)` pairs, rather than every capture line. Also clear
the log before each experiment, otherwise results from earlier runs are added
to the next graph.

Most importantly, a forged ACK being sent is not proof it was accepted. To
confirm a victim actually accepted a lease, inspect the victim namespace after
the exchange:

```sh
sudo ip netns exec victim ip addr show dev v-victim
sudo ip netns exec victim ip route
```

A rogue result would show an address from `10.0.0.200–10.0.0.220` and a
default route via `10.0.0.66`. A legitimate result should use the legitimate
address pool and gateway `10.0.0.1`.

The current accumulated `attacker.log` provides a concrete warning: it has
many repeated capture lines for the same MAC/IP pair, so it cannot be treated
as one unique victim per line.
