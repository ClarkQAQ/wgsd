# wgsd

Wireguard Peer Discovery Helper

> As we all know, Wireguard is a point-to-point VPN protocol. However, most people and tutorials typically use a star-shaped topology, which means that every node needs to go through a central node to connect to other nodes. But when it comes to achieving P2P connections, it becomes a challenge due to Wireguard's lack of built-in device discovery. This often requires two nodes, with one of them having a fixed public network or manually modifying the configuration files each time. This tool is created to address this issue!

### Principle

In reality, it's quite simple. You run a service on each node, and the central node no longer handles data exchange; instead, it is used for device discovery. The main function of each service is to obtain the peer addresses of devices corresponding to local public keys from specified addresses. It also serves other devices, providing them with the peer addresses of all locally connected devices. This concept is somewhat akin to a simplified version of a DHT (Distributed Hash Table network structure) (although it is far from the same level of complexity).

For example, suppose you have the following devices:

| Device Name | Public Address (Address+Port) | Peer Address |
| ----------- | ----------------------------- | ------------ |
| A           | 10.0.114.1:19198              | 10.0.6.1     |
| B           | NAT: 10.0.114.2:11451         | 10.0.6.2     |
| C           | NAT: 10.0.114.2:11452         | 10.0.6.3     |

In this scenario, typically, you would configure A as a peer on B and C. But what if you need B and C to communicate directly? Even though they are on the same local network and can assign LAN peer addresses to each other directly, if B and C are on different networks, manual address configuration becomes impractical. Moreover, with each connection, the port for address translation may vary.

Solution:
With wgsd, this process can be simplified. Start by running `./wgsd -l :51220` on A (51220 is the server port, the port that other nodes will connect to). Then, on B and C, run `./wgsd -l :51221 -u IP:51220 "Server Public Key" "Multiple Public Keys" (the public keys are used to prevent circular configurations). With A having a public network connection and accessible by B and C, B can use A's service to obtain C's peer address (and vice versa). As a result, B can directly connect to C, thereby achieving P2P connections!

Additionally, each instance of wgsd can function as both a server and a client, enabling the creation of a cellular network discovery.

### Usage

```bash
# Server
./wgsd -l :51220

# Client
./wgsd -l :51221 -u IP:51220 "Server Public Key" "Multiple Public Keys" (public keys are used to prevent circular configurations)
```

### TODO

1. Add support for multiple servers on the client.
2. Implement a handshake simulation before writing to the Wireguard configuration file to verify connectivity.
3. Implement automatic discovery of wgsd services.
