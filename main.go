// Command wgctrl is a testing utility for interacting with WireGuard via package
// wgctrl.
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
	"uw/ulog"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var emptyPublicKey = make([]byte, wgtypes.KeyLen)

type Device struct {
	InterfaceName       string          // 接口名称
	ListenAddr          string          // 本地监听地址
	UpstreamAddr        string          // 上游服务器地址
	IgnorePublicKeys    []string        // 忽略变更的公钥
	IgnorePublicKeysMap map[string]bool // 忽略变更的公钥
	Interval            time.Duration   // 发起查询间隔
	MaxHandshakeTime    time.Duration   // 最大请求握手时间
	Timeout             time.Duration   // 请求超时时间

	Client         *wgctrl.Client  // wgctrl 客户端
	ListenConn     *net.UDPConn    // 监听连接
	IntervalTicker *time.Ticker    // 查询定时器
	Context        context.Context // context
}

func main() {
	c, e := wgctrl.New()
	if e != nil {
		ulog.Fatal("failed to open client: %s", e)
	}
	defer c.Close()

	d := &Device{Client: c}

	flag.StringVar(&d.InterfaceName, "i", "wg0", "wireguard `interface` name")
	flag.StringVar(&d.ListenAddr, "l", ":51220", "wgsd `listen` address (empty for no listen)")
	flag.StringVar(&d.UpstreamAddr, "u", "", "`upstream` server address (empty for no upstream)")
	flag.DurationVar(&d.Interval, "d", 60*time.Second, "query `interval`")
	flag.DurationVar(&d.MaxHandshakeTime, "t", 5*time.Minute, "max `handshake` time")
	flag.DurationVar(&d.Timeout, "o", 5*time.Second, "request `timeout`")
	flag.Usage = func() {
		ulog.Info("Usage: %s [options] [ignore public keys]", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()
	d.IgnorePublicKeys = flag.Args()
	d.IgnorePublicKeysMap = make(map[string]bool, len(d.IgnorePublicKeys))
	for i := 0; i < len(d.IgnorePublicKeys); i++ {
		d.IgnorePublicKeysMap[d.IgnorePublicKeys[i]] = true
	}

	ulog.Debug("interface name: %s, listen address: %s, upstream address: %s, "+
		"query interval: %s, max handshake time: %s, ignore public keys: %v",
		d.InterfaceName, d.ListenAddr, d.UpstreamAddr, d.Interval,
		d.MaxHandshakeTime, d.IgnorePublicKeys)

	device, e := c.Device(d.InterfaceName)
	if e != nil {
		ulog.Fatal("failed to get device %q: %s", d.InterfaceName, e)
	}

	ulog.Info("local public key: %s, listen port: %d", device.PublicKey, device.ListenPort)

	wg := &sync.WaitGroup{}

	if d.ListenAddr != "" {
		wg.Add(1)
		go func(device *Device) {
			defer wg.Done()

			if e := device.listenService(); e != nil {
				ulog.Fatal("listen service: %s", e)
			}
		}(d)
	}

	if d.UpstreamAddr != "" {
		wg.Add(1)
		go func(device *Device) {
			defer wg.Done()

			if e := device.queryService(); e != nil {
				ulog.Fatal("query service: %s", e)
			}
		}(d)
	}

	wg.Add(1)
	go func(d *Device) {
		defer wg.Done()

		var cancel func()
		d.Context, cancel = context.WithCancel(context.Background())
		defer cancel()

		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
		for {
			switch <-ch {
			case syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT:
				ulog.Info("signal: exit")

				if d.ListenConn != nil {
					if e := d.ListenConn.Close(); e != nil {
						ulog.Error("failed to close udp: %s", e)
					}
				}

				if d.IntervalTicker != nil {
					d.IntervalTicker.Stop()
				}

				cancel()
				return
			}
		}
	}(d)

	ulog.Info("full started")
	wg.Wait()
}

const basePacketSize = 4 + wgtypes.KeyLen

type packet struct {
	_         uint32      // CRC 校验位
	PublicKey wgtypes.Key // 公钥
	Addr      []byte      // 地址
}

func (m *packet) String() string {
	ap := &netip.AddrPort{}
	if len(m.Addr) > 1 {
		if e := ap.UnmarshalBinary(m.Addr); e != nil {
			return fmt.Sprintf("public key: %s, addr unmarshal error: %s", m.PublicKey.String(), e)
		}
	}

	return fmt.Sprintf("public key: %s, addr: %s", m.PublicKey.String(), ap.String())
}

func (m *packet) MarshalBinary() []byte {
	b := make([]byte, basePacketSize)
	copy(b[4:36], m.PublicKey[:])
	b = append(b, m.Addr...)
	binary.LittleEndian.PutUint32(b[:4], crc32.ChecksumIEEE(b[4:]))
	return b
}

func (m *packet) UnmarshalBinary(data []byte) error {
	if len(data) < basePacketSize {
		return fmt.Errorf("invalid message packet length: %d", len(data))
	}

	if binary.LittleEndian.Uint32(data[:4]) != crc32.ChecksumIEEE(data[4:]) {
		return errors.New("invalid message packet checksum")
	}

	copy(m.PublicKey[:], data[4:36])
	m.Addr = data[36:]
	return nil
}

func (d *Device) listenService() (e error) {
	laddr, e := net.ResolveUDPAddr("udp", d.ListenAddr)
	if e != nil {
		ulog.Fatal("failed to resolve udp address %q: %s", d.ListenAddr, e)
	}

	ulog.Info("resolved udp address: %s", laddr)

	d.ListenConn, e = net.ListenUDP("udp", laddr)
	if e != nil {
		return fmt.Errorf("failed to listen udp: %w", e)
	}

	defer d.ListenConn.Close()

	laddrString := d.ListenConn.LocalAddr()
	ulog.Info("listen udp: %s", laddrString)

	for {
		m, buf := &packet{}, make([]byte, 4096)
		n, raddr, e := d.ListenConn.ReadFromUDP(buf)
		if e != nil {
			if errors.Is(e, net.ErrClosed) {
				return nil
			}

			ulog.Warn("failed to read udp: %s", e)
			continue
		}

		if e := m.UnmarshalBinary(buf[:n]); e != nil {
			ulog.Warn("failed to unmarshal message packet: %s", e)
			continue
		}

		ulog.Debug("packet(%s <<< %s): %s", laddrString,
			raddr.String(), m.String())

		if !bytes.Equal(m.PublicKey[:], emptyPublicKey) {
			endpoint, e := d.queryEndpoint(m.PublicKey)
			if e != nil {
				ulog.Warn("failed to query endpoint: %s", e)
			} else {
				ulog.Info("query endpoint: %s", endpoint.String())
				if m.Addr, e = endpoint.AddrPort().MarshalBinary(); e != nil {
					ulog.Warn("failed to marshal binary: %s", e)
				}
			}
		}

		ulog.Debug("packet(%s >>> %s): %s", laddrString,
			raddr.String(), m.String())
		if _, e := d.ListenConn.WriteToUDP(m.MarshalBinary(), raddr); e != nil {
			ulog.Warn("failed to write udp: %s", e)
		}
	}
}

func (d *Device) queryEndpoint(publicKey wgtypes.Key) (*net.UDPAddr, error) {
	device, e := d.Client.Device(d.InterfaceName)
	if e != nil {
		return nil, fmt.Errorf("failed to get device %q: %w", d.InterfaceName, e)
	}

	for i := 0; i < len(device.Peers); i++ {
		if bytes.Equal(device.Peers[i].PublicKey[:], publicKey[:]) {
			return device.Peers[i].Endpoint, nil
		}
	}

	return nil, fmt.Errorf("peer not found: %s", publicKey.String())
}

func (d *Device) queryService() error {
	d.IntervalTicker = time.NewTicker(d.Interval)
	defer d.IntervalTicker.Stop()

	d.queryFunc()

	for {
		select {
		case <-d.IntervalTicker.C:
			d.queryFunc()
		case <-d.Context.Done():
			return nil
		}
	}
}

func (d *Device) queryFunc() {
	device, e := d.Client.Device(d.InterfaceName)
	if e != nil {
		ulog.Error("failed to get device %q: %s", d.InterfaceName, e)
		return
	}

	ulog.Debug("device: %+v", device)

	conf := &wgtypes.Config{
		PrivateKey:   &device.PrivateKey,
		ListenPort:   &device.ListenPort,
		FirewallMark: &device.FirewallMark,
		ReplacePeers: true,
		Peers:        make([]wgtypes.PeerConfig, len(device.Peers)),
	}

	for i := 0; i < len(device.Peers); i++ {
		conf.Peers[i] = wgtypes.PeerConfig{
			PublicKey:                   device.Peers[i].PublicKey,
			Remove:                      false,
			UpdateOnly:                  false,
			PresharedKey:                &device.Peers[i].PresharedKey,
			Endpoint:                    device.Peers[i].Endpoint,
			PersistentKeepaliveInterval: &device.Peers[i].PersistentKeepaliveInterval,
			ReplaceAllowedIPs:           true,
			AllowedIPs:                  device.Peers[i].AllowedIPs,
		}

		if time.Since(device.Peers[i].LastHandshakeTime) < d.MaxHandshakeTime ||
			d.IgnorePublicKeysMap[device.Peers[i].PublicKey.String()] {
			continue
		}

		addr, e := d.queryUpstream(device.Peers[i].PublicKey)
		if e != nil {
			ulog.Warn("failed to query upstream: %s", e)
			continue
		}

		conf.Peers[i].Endpoint = addr
	}

	ulog.Debug("configuring: %+v", conf)

	if e := d.Client.ConfigureDevice(device.Name, *conf); e != nil {
		ulog.Warn("failed to configure device: %s", e)
	}
}

func (d *Device) queryUpstream(publicKey wgtypes.Key) (*net.UDPAddr, error) {
	if len(d.UpstreamAddr) < 1 {
		return nil, errors.New("upstream address is empty")
	}

	raddr, e := net.ResolveUDPAddr("udp", d.UpstreamAddr)
	if e != nil {
		return nil, fmt.Errorf("failed to resolve udp address %q: %w", d.UpstreamAddr, e)
	}

	ulog.Info("resolved udp address: %s", raddr)

	conn, e := net.DialUDP("udp", nil, raddr)
	if e != nil {
		return nil, fmt.Errorf("failed to dial udp: %w", e)
	}

	defer conn.Close()

	laddrString := conn.LocalAddr()

	m := &packet{PublicKey: publicKey}
	ulog.Debug("packet(%s >>> %s): %s", laddrString,
		raddr.String(), m.String())

	if e := conn.SetWriteDeadline(time.Now().Add(d.Timeout)); e != nil {
		return nil, fmt.Errorf("failed to set write deadline: %w", e)
	}

	if _, e := conn.Write(m.MarshalBinary()); e != nil {
		return nil, fmt.Errorf("failed to write udp: %w", e)
	}

	if e := conn.SetReadDeadline(time.Now().Add(d.Timeout)); e != nil {
		return nil, fmt.Errorf("failed to set read deadline: %w", e)
	}

	buf := make([]byte, 4096)
	n, e := conn.Read(buf)
	if e != nil {
		return nil, fmt.Errorf("failed to read udp: %w", e)
	}

	if e := m.UnmarshalBinary(buf[:n]); e != nil {
		return nil, fmt.Errorf("failed to unmarshal message packet: %w", e)
	}

	ulog.Debug("packet(%s <<< %s): %s", laddrString,
		raddr.String(), m.String())

	if len(m.Addr) < 2 {
		return nil, errors.New("address is empty")
	}

	ap := &netip.AddrPort{}
	if e := ap.UnmarshalBinary(m.Addr); e != nil {
		return nil, fmt.Errorf("failed to unmarshal binary: %w", e)
	}

	ulog.Debug("address: %s", ap.String())

	addr, e := net.ResolveUDPAddr("udp", ap.String())
	if e != nil {
		return nil, fmt.Errorf("failed to resolve udp address %q: %w", ap.String(), e)
	}

	return addr, nil
}
