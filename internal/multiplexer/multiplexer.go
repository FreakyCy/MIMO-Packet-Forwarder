package multiplexer

import (
	"encoding/base64"
	"encoding/hex"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type udpPacket struct {
	addr *net.UDPAddr
	data []byte
}

// MIMO-Packet-Forwarder packet-forwarder UDP data to multiple backends.
type Multiplexer struct {
	sync.RWMutex
	wg sync.WaitGroup

	conn     *net.UDPConn
	config   Config
	closed   bool
	backends map[string]map[string]*net.UDPConn // [backendHost][gatewayID]UDPConn
	gateways map[string]*net.UDPAddr            // [gatewayID]UDPAddr

}

// New creates a new multiplexer.
func New(c Config) (*Multiplexer, error) {
	log.Println("New function called")

	m := Multiplexer{
		config:   c,
		backends: make(map[string]map[string]*net.UDPConn),
		gateways: make(map[string]*net.UDPAddr),
	}

	if c.Bind == "" {
		c.Bind = ":1800"
	}

	addr, err := net.ResolveUDPAddr("udp", c.Bind)
	if err != nil {
		log.Println("resolve udp addr error:", err)
		return nil, errors.Wrap(err, "resolve udp addr error")
	}

	log.Println("starting listener on address:", addr)
	m.conn, err = net.ListenUDP("udp", addr)
	if err != nil {
		log.Println("listen udp error:", err)
		return nil, errors.Wrap(err, "listen udp error")
	}

	log.Println("initializing backends")
	for _, backendConfig := range m.config.Backends {
		backend := backendConfig // Create a copy of the backendConfig for this iteration
		if backend.Host == "" {
			backend.Host = "eu1.cloud.thethings.network:1700"
		}
		addr, err := net.ResolveUDPAddr("udp", backend.Host)
		if err != nil {
			log.Println("resolve udp addr error for backend host:", backend.Host, "error:", err)
			return nil, errors.Wrap(err, "resolve udp addr error")
		}

		for _, gatewayID := range backend.GatewayIDs {
			gatewayID = strings.ToLower(gatewayID)

			log.Println("dial udp for gatewayID:", gatewayID, "host:", backend.Host)
			conn, err := net.DialUDP("udp", nil, addr)
			if err != nil {
				log.Println("dial udp error for gatewayID:", gatewayID, "error:", err)
				return nil, errors.Wrap(err, "dial udp error")
			}

			if _, ok := m.backends[backend.Host]; !ok {
				m.backends[backend.Host] = make(map[string]*net.UDPConn)
				log.Println("initialized backend host in backends map:", backend.Host)
			}

			m.backends[backend.Host][gatewayID] = conn
			log.Println("added gateway to backends map, host:", backend.Host, "gatewayID:", gatewayID)

			go func(backend, gatewayID string, conn *net.UDPConn) {
				m.wg.Add(1)
				err := m.readDownlinkPackets(backend, gatewayID, conn)
				if !m.isClosed() {
					log.WithError(err).Error("read udp packets error")
				}
				m.wg.Done()
			}(backend.Host, gatewayID, conn)
		}
	}

	go func() {
		m.wg.Add(1)
		err := m.readUplinkPackets()
		if !m.isClosed() {
			log.Println("read udp packets error:", err)
		}
		m.wg.Done()
	}()

	return &m, nil
}

// Close closes the multiplexer.
func (m *Multiplexer) Close() error {
	m.Lock()
	m.closed = true

	log.Info("closing listener")
	if err := m.conn.Close(); err != nil {
		return errors.Wrap(err, "close udp listener error")
	}

	log.Info("closing backend connections")
	for _, gws := range m.backends {
		for _, conn := range gws {
			if err := conn.Close(); err != nil {
				return errors.Wrap(err, "close udp connection error")
			}
		}
	}

	m.Unlock()
	m.wg.Wait()
	return nil
}

func (m *Multiplexer) isClosed() bool {
	m.RLock()
	defer m.RUnlock()
	return m.closed
}

func (m *Multiplexer) setGateway(gatewayID string, addr *net.UDPAddr) error {
	m.Lock()
	defer m.Unlock()
	m.gateways[gatewayID] = addr
	return nil
}

func (m *Multiplexer) getGateway(gatewayID string) (*net.UDPAddr, error) {
	m.RLock()
	defer m.RUnlock()

	addr, ok := m.gateways[gatewayID]
	if !ok {
		return nil, errors.New("gateway does not exist")
	}
	return addr, nil
}

func (m *Multiplexer) readUplinkPackets() error {
	buf := make([]byte, 65507) // max udp data size
	for {
		i, addr, err := m.conn.ReadFromUDP(buf)
		if err != nil {
			if m.isClosed() {
				return nil
			}
			log.WithError(err).Error("read from udp error")
			continue
		}

		data := make([]byte, i)
		copy(data, buf[:i])
		up := udpPacket{data: data, addr: addr}

		hexDump := hex.Dump(buf[:i])
		readableOutput := processHexDump(hexDump)

		processRxpkPacket(readableOutput)

		log.WithFields(log.Fields{
			"addr": up.addr,
		}).Info("Packet received from gateway")

		// Handle packet asynchronously
		go func(up udpPacket) {
			if err := m.handleUplinkPacket(up); err != nil {
				log.WithError(err).WithFields(log.Fields{
					"data_base64": base64.StdEncoding.EncodeToString(up.data),
					"addr":        up.addr,
				}).Error("Could not handle packet")
			}
		}(up)
	}
}

func processHexDump(hexDump string) string {
	var sb strings.Builder
	lines := strings.Split(hexDump, "\n")
	for _, line := range lines {
		start := strings.Index(line, "|")
		end := strings.LastIndex(line, "|")
		if start != -1 && end != -1 && start != end {
			content := line[start+1 : end]
			sb.WriteString(content)
		}
	}
	return sb.String()
}

func processRxpkPacket(readableOutput string) {
	if strings.Contains(readableOutput, "rxpk") {
		log.Debug("Paket rxpk empfangen!")
		if strings.Contains(readableOutput, "LORA") {
			log.WithFields(log.Fields{
				"Rohdaten": readableOutput,
			}).Debug("Paket mit Lora-Daten empfangen!")
			processRSSI(readableOutput)
			processDataValue(readableOutput)
		}
	} else {
		log.WithFields(log.Fields{
			"Rohdaten": readableOutput,
		}).Debug("Kein rxpk Paket")
	}
}

func processRSSI(readableOutput string) {
	r1 := regexp.MustCompile(`"rssi":(-?\d+)`)
	match1 := r1.FindStringSubmatch(readableOutput)
	if len(match1) > 1 {
		rssiValueStr := match1[1]
		rssiValue, err := strconv.Atoi(rssiValueStr)
		if err != nil {
			log.WithError(err).WithFields(log.Fields{
				"data": readableOutput,
			}).Error("Fehler beim Konvertieren des RSSI-Werts:")
		} else {
			log.WithFields(log.Fields{
				"RSSI": rssiValue,
			}).Debug("RSSI-Wert:")
		}
	} else {
		log.WithFields(log.Fields{
			"data": readableOutput,
		}).Error("RSSI-Wert nicht gefunden")
	}
}

func processDataValue(readableOutput string) {
	re := regexp.MustCompile(`"data":"([^"]+)"`)
	match := re.FindStringSubmatch(readableOutput)
	if len(match) > 1 {
		dataValue := match[1]
		log.WithFields(log.Fields{
			"DATA": dataValue,
		}).Debug("Data-Wert:")
	} else {
		log.WithFields(log.Fields{
			"data": readableOutput,
		}).Error("Fehler beim Konvertieren des DATA-Werts:")
	}
}

func (m *Multiplexer) readDownlinkPackets(backend, gatewayID string, conn *net.UDPConn) error {
	buf := make([]byte, 65507) // max udp data size
	for {
		i, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if m.isClosed() {
				return nil
			}

			log.WithError(err).Error("read from udp error")
			continue
		}

		data := make([]byte, i)
		copy(data, buf[:i])
		up := udpPacket{data: data, addr: addr}

		// handle packet async
		go func(up udpPacket) {
			if err := m.handleDownlinkPacket(backend, gatewayID, up); err != nil {
				log.WithError(err).WithFields(log.Fields{
					"data_base64": base64.StdEncoding.EncodeToString(up.data),
					"addr":        up.addr,
				}).Error("could not handle packet")
			}
		}(up)
	}
}

func (m *Multiplexer) handleUplinkPacket(up udpPacket) error {
	log.WithFields(log.Fields{
		"addr": up.addr,
	}).Debug("handling uplink packet")

	pt, err := GetPacketType(up.data)
	if err != nil {
		log.WithError(err).Error("get packet-type error")
		return errors.Wrap(err, "get packet-type error")
	}

	gatewayID, err := GetGatewayID(up.data)
	if err != nil {
		log.WithError(err).Error("get gateway id error")
		return errors.Wrap(err, "get gateway id error")
	}

	log.WithFields(log.Fields{
		"packet_type": pt,
		"addr":        up.addr,
		"gateway_id":  gatewayID,
	}).Info("packet received from gateway")

	switch pt {
	case PushData:
		log.Debug("packet type is PushData")
		return m.handlePushData(gatewayID, up)
	case PullData:
		log.Debug("packet type is PullData")
		if err := m.setGateway(gatewayID, up.addr); err != nil {
			log.WithError(err).Error("set gateway error")
			return errors.Wrap(err, "set gateway error")
		}
		return m.handlePullData(gatewayID, up)
	case TXACK:
		log.Debug("packet type is TXACK")
		return m.forwardUplinkPacket(gatewayID, up)
	default:
		log.Warn("unhandled packet type")
	}

	return nil
}

func (m *Multiplexer) handleDownlinkPacket(backend, gatewayID string, up udpPacket) error {
	pt, err := GetPacketType(up.data)
	if err != nil {
		return errors.Wrap(err, "get packet-type error")
	}

	log.WithFields(log.Fields{
		"packet_type": pt,
		"gateway_id":  gatewayID,
		"host":        backend,
	}).Info("packet received from backend")

	switch pt {
	case PullResp:
		return m.forwardPullResp(backend, gatewayID, up)
	}

	return nil
}

func (m *Multiplexer) handlePushData(gatewayID string, up udpPacket) error {
	if len(up.data) < 12 {
		return errors.New("expected at least 12 bytes of data")
	}

	// respond with PushACK
	log.WithFields(log.Fields{
		"addr":        up.addr,
		"packet_type": PushACK,
		"gateway_id":  gatewayID,
	}).Info("sending packet to gateway")
	b := make([]byte, 4)
	copy(b[:3], up.data[:3])
	b[3] = byte(PushACK)
	if _, err := m.conn.WriteToUDP(b, up.addr); err != nil {
		return errors.Wrap(err, "write to udp error")

	}

	return m.forwardUplinkPacket(gatewayID, up)
}

func (m *Multiplexer) handlePullData(gatewayID string, up udpPacket) error {
	if len(up.data) < 12 {
		return errors.New("expected at least 12 bytes of data")
	}

	// respond with PullACK
	log.WithFields(log.Fields{
		"addr":        up.addr,
		"packet_type": PullACK,
		"gateway_id":  gatewayID,
	}).Info("sending packet to gateway")
	b := make([]byte, 4)
	copy(b[:3], up.data[:3])
	b[3] = byte(PullACK)
	if _, err := m.conn.WriteToUDP(b, up.addr); err != nil {
		return errors.Wrap(err, "write to udp error")
	}

	return m.forwardUplinkPacket(gatewayID, up)
}

func (m *Multiplexer) forwardUplinkPacket(gatewayID string, up udpPacket) error {

	log.WithFields(log.Fields{
		"gateway_id": gatewayID,
		"backends":   m.backends,
	}).Debug("forwardUplinkPacket called")

	for host, gwIDs := range m.backends {
		log.WithField("host", host).Debug("checking host")
		for gwID, conn := range gwIDs {
			log.WithFields(log.Fields{
				"expected_gateway_id": gwID,
				"actual_gateway_id":   gatewayID,
			}).Debug("checking gateway id")
			if gwID == gatewayID {
				pt, err := GetPacketType(up.data)
				if err != nil {
					return errors.Wrap(err, "get packet-type error")
				}
				log.WithFields(log.Fields{
					"from":        up.addr,
					"to":          host,
					"gateway_id":  gatewayID,
					"packet_type": pt,
				}).Info("forwarding packet to backend")
				if _, err := conn.Write(up.data); err != nil {
					log.WithError(err).WithFields(log.Fields{
						"host":       host,
						"gateway_id": gwID,
					}).Error("udp write error")
				} else {
					log.WithFields(log.Fields{
						"host":       host,
						"gateway_id": gwID,
					}).Info("packet forwarded successfully")
				}
			} else {
				log.WithFields(log.Fields{
					"expected_gateway_id": gwID,
					"actual_gateway_id":   gatewayID,
				}).Debug("gateway_id does not match, not forwarding")
			}
		}
	}

	return nil
}

func (m *Multiplexer) forwardPullResp(backend, gatewayID string, up udpPacket) error {
	addr, err := m.getGateway(gatewayID)
	if err != nil {
		return errors.Wrap(err, "get gateway error")
	}

	if m.backendIsUplinkOnly(backend) {
		log.WithFields(log.Fields{
			"packet_type": PullResp,
			"gateway_id":  gatewayID,
			"host":        backend,
		}).Info("ignoring downlink packet, backend is uplink only")
		return nil
	}

	log.WithFields(log.Fields{
		"from":        backend,
		"to":          addr,
		"packet_type": PullResp,
		"gateway_id":  gatewayID,
	}).Info("forwarding packet to gateway")
	if _, err := m.conn.WriteToUDP(up.data, addr); err != nil {
		return errors.Wrap(err, "write to udp error")
	}

	return nil
}

func (m *Multiplexer) backendIsUplinkOnly(backend string) bool {
	for _, be := range m.config.Backends {
		if be.Host == backend {
			return be.UplinkOnly
		}
	}

	return true
}

func logBackends(backends map[string]map[string]*net.UDPConn) {
	for host, gwIDs := range backends {
		for gwID, conn := range gwIDs {
			log.WithFields(log.Fields{
				"host":       host,
				"gateway_id": gwID,
				"conn":       conn.LocalAddr(),
			}).Info("Backend connection")
		}
	}
}
