package core

import (
	"bufio"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"
)

type practicalBandwidthConfig struct {
	bandwidthBytesPerSec float64
	bandwidthScope       string
	bandwidthStateFile   string
	bandwidthSocket      string
}

var (
	bandwidthConfigOnce sync.Once
	bandwidthConfig     practicalBandwidthConfig
	bandwidth           practicalBandwidthLimiter
	bwSocket            practicalBandwidthSocketClient
)

func loadBandwidthConfigFromEnv() practicalBandwidthConfig {
	cfg := practicalBandwidthConfig{
		bandwidthBytesPerSec: bandwidthBytesPerSecondFromEnv(),
	}
	if cfg.bandwidthBytesPerSec > 0 {
		cfg.bandwidthScope = bandwidthScopeFromEnv("PRACTICAL_BANDWIDTH_SCOPE")
		cfg.bandwidthStateFile = stringsTrim(os.Getenv("PRACTICAL_BANDWIDTH_STATE_FILE"))
		cfg.bandwidthSocket = stringsTrim(os.Getenv("PRACTICAL_BANDWIDTH_SOCKET"))
	}
	return cfg
}

func bandwidthBytesPerSecondFromEnv() float64 {
	raw := stringsTrim(os.Getenv("PRACTICAL_BANDWIDTH_MBPS"))
	if raw == "" {
		return 0
	}
	mbps, err := strconv.ParseFloat(raw, 64)
	if err != nil || mbps <= 0 {
		return 0
	}
	return mbps * 1000 * 1000 / 8
}

func bandwidthScopeFromEnv(name string) string {
	switch stringsTrim(os.Getenv(name)) {
	case "", "shared":
		return "shared"
	case "per-node-egress":
		return "per-node-egress"
	default:
		return "shared"
	}
}

func bandwidthConfigValue() practicalBandwidthConfig {
	bandwidthConfigOnce.Do(func() {
		bandwidthConfig = loadBandwidthConfigFromEnv()
	})
	return bandwidthConfig
}

type bandwidthWriteConn struct {
	net.Conn
}

func (c *bandwidthWriteConn) Write(p []byte) (int, error) {
	throttleBandwidth(len(p))
	return c.Conn.Write(p)
}

type practicalBandwidthLimiter struct {
	mu   sync.Mutex
	next time.Time
}

func throttleBandwidth(n int) {
	if n <= 0 {
		return
	}
	cfg := bandwidthConfigValue()
	bytesPerSec := cfg.bandwidthBytesPerSec
	if bytesPerSec <= 0 {
		return
	}
	if cfg.bandwidthScope == "shared" {
		if cfg.bandwidthSocket != "" && throttleSocketBandwidth(n, cfg.bandwidthSocket) {
			return
		}
		if cfg.bandwidthStateFile != "" {
			throttleSharedBandwidth(n, bytesPerSec, cfg.bandwidthStateFile)
			return
		}
	}
	throttleLocalBandwidth(n, bytesPerSec)
}

func throttleLocalBandwidth(n int, bytesPerSec float64) {
	duration := time.Duration(float64(time.Second) * float64(n) / bytesPerSec)
	if duration <= 0 {
		return
	}
	bandwidth.mu.Lock()
	now := time.Now()
	start := now
	if bandwidth.next.After(now) {
		start = bandwidth.next
	}
	readyAt := start.Add(duration)
	bandwidth.next = readyAt
	wait := readyAt.Sub(now)
	bandwidth.mu.Unlock()
	if wait > 0 {
		time.Sleep(wait)
	}
}

type practicalBandwidthSocketClient struct {
	mu         sync.Mutex
	conn       net.Conn
	reader     *bufio.Reader
	socketPath string
}

func throttleSocketBandwidth(n int, socketPath string) bool {
	wait, ok := bwSocket.reserve(n, socketPath)
	if !ok {
		return false
	}
	if wait > 0 {
		time.Sleep(wait)
	}
	return true
}

func (c *practicalBandwidthSocketClient) reserve(n int, socketPath string) (time.Duration, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for attempt := 0; attempt < 2; attempt++ {
		if c.conn == nil || c.socketPath != socketPath {
			c.closeLocked()
			conn, err := net.DialTimeout("unix", socketPath, 5*time.Second)
			if err != nil {
				return 0, false
			}
			c.conn = conn
			c.reader = bufio.NewReader(conn)
			c.socketPath = socketPath
		}
		_ = c.conn.SetDeadline(time.Now().Add(30 * time.Second))
		if _, err := c.conn.Write([]byte(strconv.Itoa(n) + "\n")); err != nil {
			c.closeLocked()
			continue
		}
		line, err := c.reader.ReadString('\n')
		if err != nil {
			c.closeLocked()
			continue
		}
		waitNs, err := strconv.ParseInt(stringsTrim(line), 10, 64)
		if err != nil || waitNs < 0 {
			return 0, false
		}
		return time.Duration(waitNs), true
	}
	return 0, false
}

func (c *practicalBandwidthSocketClient) closeLocked() {
	if c.conn != nil {
		_ = c.conn.Close()
	}
	c.conn = nil
	c.reader = nil
	c.socketPath = ""
}

func throttleSharedBandwidth(n int, bytesPerSec float64, stateFile string) {
	duration := time.Duration(float64(time.Second) * float64(n) / bytesPerSec)
	if duration <= 0 {
		return
	}
	file, err := os.OpenFile(stateFile, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		throttleLocalBandwidth(n, bytesPerSec)
		return
	}
	defer file.Close()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		throttleLocalBandwidth(n, bytesPerSec)
		return
	}
	now := time.Now()
	start := now
	if _, err := file.Seek(0, 0); err == nil {
		if raw, err := io.ReadAll(file); err == nil {
			if nextUnixNano, err := strconv.ParseInt(stringsTrim(string(raw)), 10, 64); err == nil && nextUnixNano > 0 {
				if next := time.Unix(0, nextUnixNano); next.After(now) {
					start = next
				}
			}
		}
	}
	readyAt := start.Add(duration)
	_ = file.Truncate(0)
	_, _ = file.Seek(0, 0)
	_, _ = file.WriteString(strconv.FormatInt(readyAt.UnixNano(), 10))
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	if wait := readyAt.Sub(now); wait > 0 {
		time.Sleep(wait)
	}
}

func dialWithBandwidth(network, addr string, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout(network, addr, timeout)
	if err != nil {
		return nil, err
	}
	if bandwidthConfigValue().bandwidthBytesPerSec <= 0 {
		return conn, nil
	}
	return &bandwidthWriteConn{Conn: conn}, nil
}

func stringsTrim(s string) string {
	i := 0
	j := len(s)
	for i < j && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
		i++
	}
	for i < j && (s[j-1] == ' ' || s[j-1] == '\t' || s[j-1] == '\n' || s[j-1] == '\r') {
		j--
	}
	return s[i:j]
}
