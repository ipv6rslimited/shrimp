/*
**
** shrimp
** A simple forward proxy written in GoLang
**
** Distributed under the COOL License.
**
** Copyright (c) 2024 IPv6.rs <https://ipv6.rs>
** All Rights Reserved
**
*/

package main

import (
  "bufio"
  "context"
  "crypto/tls"
  "encoding/base64"
  "encoding/json"
  "fmt"
  "io"
  "log"
  "net"
  "os"
  "regexp"
  "strings"
  "sync"
  "time"
  "github.com/ipv6rslimited/lrucache"
  "github.com/ipv6rslimited/peter"
  "golang.org/x/crypto/bcrypt"
)

type Config struct {
  ListenAddrs         []string   `json:"listenAddrs"`
  PlaintextAddr         string   `json:"plaintextAddr"`
  LockdownMode          bool     `json:"lockdownMode"`
  IPv6Interface         string   `json:"ipv6Interface"`
  DNS64Server           string   `json:"dns64Server"`
  CredentialsFile       string   `json:"credentialsFile"`
  DebugMode             bool     `json:"debugMode"`
  CertFile              string   `json:"certFile"`
  KeyFile               string   `json:"keyFile"`
  DNSCacheCapacity      int      `json:"dnsCacheCapacity"`
  DNSTTL                int      `json:"dnsTTL"`
  IPv4Translator        string   `json:"ipv4Translator"`
  AllowedHosts        []string   `json:"allowedHosts"`
  DisallowedHosts     []string   `json:"disallowedHosts"`
}

type CacheEntry struct {
  Address               string
  Timestamp             time.Time
}

type nullWriter struct{}

var (
  config                Config
  users                 map[string]string
  configLock            sync.RWMutex
  logger               *log.Logger
  dnsCache             *lrucache.LRUCache
  systemDNS           []string
  maxBufferedDataSize = 8192
)


func main() {
  loadConfig()
  setLogger(config.DebugMode)
  loadCredentials()
  loadSystemDNS()

  dnsCache = lrucache.NewLRUCache(config.DNSCacheCapacity)

  cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
  if err != nil {
    logger.Fatalf("Error loading certificate: %v", err)
  }

  tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{cert},
    MinVersion:   tls.VersionTLS12,
  }

  listeners := createListeners(tlsConfig)
  plaintextListener := createPlaintextListener()
  listeners = append(listeners, plaintextListener)

  var wg sync.WaitGroup
  for _, listener := range listeners {
    wg.Add(1)
    go func(l net.Listener) {
      defer wg.Done()
      for {
        conn, err := l.Accept()
        if err != nil {
          logger.Printf("Error accepting connection: %v", err)
          continue
        }
        go handleConn(conn, l.Addr().String())
      }
    }(listener)
  }
  wg.Wait()
}

func (nw nullWriter) Write(p []byte) (n int, err error) {
  return len(p), nil
}

func setLogger(enable bool) {
  if enable {
    logger = log.New(os.Stdout, "", log.LstdFlags)
  } else {
    logger = log.New(nullWriter{}, "", log.LstdFlags)
  }
}

func loadConfig() {
  configLock.Lock()
  defer configLock.Unlock()

  file, err := os.Open("shrimp.conf")
  if err != nil {
    logger.Fatalf("Error opening config file: %v", err)
  }
  defer file.Close()

  decoder := json.NewDecoder(file)
  if err := decoder.Decode(&config); err != nil {
    logger.Fatalf("Error decoding config file: %v", err)
  }
}

func loadCredentials() {
  configLock.Lock()
  defer configLock.Unlock()

  file, err := os.Open(config.CredentialsFile)
  if err != nil {
    logger.Fatalf("Error opening credentials file: %v", err)
  }
  defer file.Close()

  users = make(map[string]string)
  scanner := bufio.NewScanner(file)
  for scanner.Scan() {
    parts := strings.SplitN(scanner.Text(), ":", 2)
    if len(parts) != 2 {
      logger.Fatalf("Invalid credentials format")
    }
    users[parts[0]] = parts[1]
  }

  if err := scanner.Err(); err != nil {
    logger.Fatalf("Error reading credentials file: %v", err)
  }
}

func loadSystemDNS() {
  file, err := os.Open("/etc/resolv.conf")
  if err != nil {
    logger.Fatalf("Error opening /etc/resolv.conf: %v", err)
  }
  defer file.Close()

  scanner := bufio.NewScanner(file)
  for scanner.Scan() {
    line := scanner.Text()
    if strings.HasPrefix(line, "nameserver") {
      parts := strings.Fields(line)
      if len(parts) > 1 {
        systemDNS = append(systemDNS, parts[1]+":53")
      }
    }
  }

  if err := scanner.Err(); err != nil {
    logger.Fatalf("Error reading /etc/resolv.conf: %v", err)
  }
}

func createListeners(tlsConfig *tls.Config) []net.Listener {
  var listeners []net.Listener
  for _, addr := range config.ListenAddrs {
    listener, err := tls.Listen("tcp", addr, tlsConfig)
    if err != nil {
      logger.Fatalf("Error starting proxy on %s: %v", addr, err)
    }
    listeners = append(listeners, listener)
    logger.Printf("Proxy listening on %s", addr)
  }
  return listeners
}

func createPlaintextListener() net.Listener {
  listener, err := net.Listen("tcp", config.PlaintextAddr)
  if err != nil {
    logger.Fatalf("Error starting plaintext proxy on %s: %v", config.PlaintextAddr, err)
  }
  logger.Printf("Plaintext proxy listening on %s", config.PlaintextAddr)
  return listener
}

func handleConn(conn net.Conn, addr string) {
  defer conn.Close()

  reader := bufio.NewReader(conn)
  host, bufferedData, err := getNameAndBufferFromHTTPConnection(reader)
  if err != nil {
    logger.Printf("Error extracting host: %v", err)
    sendErrorResponse(conn, 400, "Invalid Request")
    return
  }

  if !isHostAllowed(host) {
    logger.Printf("Host %s is not allowed", host)
    sendErrorResponse(conn, 403, "Access Denied.")
    return
  }

  auth := extractAuth(bufferedData)
  authenticated, promptPassword := checkAuth(auth)
  if !authenticated {
    if promptPassword {
      sendErrorResponse(conn, 407, "Proxy Authentication Required. Please provide credentials.")
    } else {
      sendErrorResponse(conn, 403, "Access Denied.")
    }
    return
  }

  if isWebSocketUpgrade(bufferedData) {
    handleWebSocket(conn, host, bufferedData)
    return
  }

  if isConnectMethod(bufferedData) {
    handleHTTPS(conn, host)
  } else {
    handleHTTP(conn, host, bufferedData)
  }
}

func getNameAndBufferFromHTTPConnection(reader *bufio.Reader) (string, []byte, error) {
  logger.Println("Extracting name from HTTP connection")
  bufferedData := make([]byte, 0, maxBufferedDataSize)
  var host string

  for {
    line, err := reader.ReadString('\n')
    if err != nil {
      if err == io.EOF {
        break
      }
      return "", nil, fmt.Errorf("failed to read line: %w", err)
    }

    bufferedData = append(bufferedData, []byte(line)...)
    if len(bufferedData) > maxBufferedDataSize {
      return "", nil, fmt.Errorf("buffered data exceeds maximum size")
    }

    line = strings.TrimRight(line, "\r\n")

    if strings.HasPrefix(strings.ToLower(line), "host: ") {
      host = strings.TrimSpace(line[6:])
      host = stripPort(host)
      logger.Printf("Extracted host from HTTP: %s", host)
    }

    if len(line) == 0 {
      break
    }
  }

  if host == "" {
    return "", nil, fmt.Errorf("host header not found")
  }

  remainingData := make([]byte, reader.Buffered())
  n, err := reader.Read(remainingData)
  if err != nil && err != io.EOF {
    return "", nil, fmt.Errorf("failed to read remaining data: %w", err)
  }

  if len(bufferedData)+n > maxBufferedDataSize {
    return "", nil, fmt.Errorf("remaining data exceeds maximum buffer size")
  }
  bufferedData = append(bufferedData, remainingData[:n]...)

  return host, bufferedData, nil
}

func stripPort(host string) string {
  if strings.HasPrefix(host, "[") {
    endIndex := strings.Index(host, "]")
    if endIndex == -1 {
      return host
    }
    if endIndex+1 < len(host) && host[endIndex+1] == ':' {
      return host[:endIndex+1]
    }
    return host
  }
  if colonIndex := strings.LastIndex(host, ":"); colonIndex != -1 {
    return host[:colonIndex]
  }
  return host
}

func extractAuth(data []byte) string {
  lines := strings.Split(string(data), "\r\n")
  for _, line := range lines {
    if strings.HasPrefix(strings.ToLower(line), "proxy-authorization: ") {
      return strings.TrimSpace(line[len("proxy-authorization: "):])
    }
  }
  return ""
}

func sendErrorResponse(conn net.Conn, statusCode int, message string) {
  response := fmt.Sprintf("HTTP/1.1 %d %s\r\nProxy-Authenticate: Basic realm=\"Access to the proxy\"\r\nContent-Length: %d\r\nContent-Type: text/plain\r\n\r\n%s", statusCode, getStatusText(statusCode), len(message), message)
  conn.Write([]byte(response))
}

func getStatusText(statusCode int) string {
  switch statusCode {
    case 400:
      return "Bad Request"
    case 403:
      return "Forbidden"
    case 407:
      return "Proxy Authentication Required"
    case 503:
      return "Service Unavailable"
    default:
      return "Unknown Status"
  }
}

func handleHTTPS(conn net.Conn, host string) {
  logger.Printf("Handling CONNECT method for host: %s", host)

  host, port := getHostPort(host, "443")

  destConn, err := connectTo(host, port)
  if err != nil {
    logger.Printf("Error connecting to host %s: %v", host, err)
    sendErrorResponse(conn, 503, "Service Unavailable")
    return
  }
  defer destConn.Close()

  conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

  p := peter.NewPeter(conn, destConn)
  p.Start()
  logger.Printf("HTTPS connection closed for host: %s", host)
}

func handleHTTP(conn net.Conn, host string, bufferedData []byte) {
  logger.Printf("Handling HTTP request for host: %s", host)

  host, port := getHostPort(host, "80")

  destConn, err := connectTo(host, port)
  if err != nil {
    logger.Printf("Error connecting to host %s: %v", host, err)
    sendErrorResponse(conn, 503, "Service Unavailable")
    return
  }
  defer destConn.Close()

  forwardedData := removeAuthHeader(bufferedData)

  _, err = destConn.Write(forwardedData)
  if err != nil {
    logger.Printf("Error writing request to destination: %v", err)
    return
  }

  p := peter.NewPeter(conn, destConn)
  p.Start()
  logger.Printf("HTTP connection closed for host: %s", host)
}

func handleWebSocket(conn net.Conn, host string, bufferedData []byte) {
  logger.Printf("Handling WebSocket upgrade for host: %s", host)

  host, port := getHostPort(host, "80")

  destConn, err := connectTo(host, port)
  if err != nil {
    logger.Printf("Error connecting to host %s: %v", host, err)
    sendErrorResponse(conn, 503, "Service Unavailable")
    return
  }
  defer destConn.Close()

  forwardedData := removeAuthHeader(bufferedData)

  _, err = destConn.Write(forwardedData)
  if err != nil {
    logger.Printf("Error writing WebSocket upgrade request: %v", err)
    return
  }

  p := peter.NewPeter(conn, destConn)
  p.Start()
  logger.Printf("WebSocket connection closed for host: %s", host)
}

func getHostPort(hostport, defaultPort string) (string, string) {
  if strings.HasPrefix(hostport, "[") {
    endIdx := strings.Index(hostport, "]")
    if endIdx == -1 {
      return hostport, defaultPort
    }

    if len(hostport) > endIdx+2 && hostport[endIdx+1] == ':' {
      return hostport[:endIdx+1], hostport[endIdx+2:]
    }
    return hostport[:endIdx+1], defaultPort
  }

  parts := strings.Split(hostport, ":")
  if len(parts) == 2 && parts[1] != "" {
    return parts[0], parts[1]
  } else if len(parts) > 2 {
    return strings.Join(parts[:len(parts)-1], ":"), parts[len(parts)-1]
  }
  return strings.TrimSuffix(hostport, ":"), defaultPort
}

func checkAuth(authHeader string) (bool, bool) {
  if authHeader == "" {
    return false, true
  }

  parts := strings.SplitN(authHeader, " ", 2)
  if len(parts) != 2 || parts[0] != "Basic" {
    return false, true
  }

  auth, err := base64.StdEncoding.DecodeString(parts[1])
  if err != nil {
    return false, true
  }

  creds := strings.SplitN(string(auth), ":", 2)
  if len(creds) != 2 {
    return false, true
  }

  configLock.RLock()
  hashedPassword, ok := users[creds[0]]
  configLock.RUnlock()
  if !ok {
    return false, true
  }

  err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(creds[1]))
  if err != nil {
    return false, true
  }

  return true, false
}

func connectTo(host, port string) (net.Conn, error) {
  host = strings.Trim(host, "[]")
  if net.ParseIP(host) != nil {
    if config.LockdownMode && isIPv4Address(host) {
      host = fmt.Sprintf("%s.%s", host, config.IPv4Translator)
    } else {
      return connectDo(fmt.Sprintf("[%s]",host), host, port)
    }
  }

  ip, err := lookupWithCache(host)
  if err != nil {
    return nil, err
  }

  if !isIPAllowed(ip) {
    return nil, fmt.Errorf("IP %s is not allowed", ip)
  }

  return connectDo(host, ip, port)
}

func connectDo(host, ip, port string) (net.Conn, error) {
  d := &net.Dialer{
    Timeout:   10 * time.Second,
    DualStack: !config.LockdownMode,
  }

  if config.LockdownMode {
    addr, err := getIPv6Addr(config.IPv6Interface)
    if err != nil {
      return nil, err
    }
    d.LocalAddr = addr
  }

  logger.Printf("Connecting to %s:%s (resolved IP: %s)", host, port, ip)

  return d.Dial("tcp", net.JoinHostPort(ip, port))
}

func getIPv6Addr(ifaceName string) (net.Addr, error) {
  iface, err := net.InterfaceByName(ifaceName)
  if err != nil {
    return nil, err
  }

  addrs, err := iface.Addrs()
  if err != nil {
    return nil, err
  }

  for _, addr := range addrs {
    if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() == nil {
      return &net.TCPAddr{IP: ipNet.IP}, nil
    }
  }

  return nil, fmt.Errorf("no IPv6 address found for interface %s", ifaceName)
}

func lookupWithCache(hostname string) (string, error) {
  logger.Printf("Looking up hostname: %s", hostname)
  if entry, found := dnsCache.Get(hostname); found {
    cacheEntry := entry.(CacheEntry)
    if time.Since(cacheEntry.Timestamp) < time.Duration(config.DNSTTL)*time.Second {
      logger.Printf("Cache hit for hostname: %s, address: %s", hostname, cacheEntry.Address)
      return cacheEntry.Address, nil
    }
    go func() {
      if ip, err := lookupRaw(hostname); err == nil {
        dnsCache.Put(hostname, CacheEntry{Address: ip, Timestamp: time.Now()})
      }
    }()
    logger.Printf("Cache stale for hostname: %s, using old address while refreshing", hostname)
    return cacheEntry.Address, nil
  }
  logger.Printf("Cache miss for hostname: %s", hostname)
  return lookupRaw(hostname)
}

func lookupRaw(hostname string) (string, error) {
  logger.Printf("Performing raw lookup for hostname: %s", hostname)
  var ip string
  var err error

  if config.LockdownMode {
    ip, err = resolveDNS64(hostname)
  } else {
    ip, err = resolveDefaultDNS(hostname)
  }

  if err != nil {
    logger.Printf("Raw lookup failed for hostname: %s, error: %v", hostname, err)
    return "", err
  }

  dnsCache.Put(hostname, CacheEntry{Address: ip, Timestamp: time.Now()})
  logger.Printf("Raw lookup succeeded for hostname: %s, address: %s", hostname, ip)
  return ip, nil
}

func resolveDNS64(host string) (string, error) {
  resolver := &net.Resolver{
    Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
      dnsServerAddress := fmt.Sprintf("[%s]:53", config.DNS64Server)
      return net.Dial("udp", dnsServerAddress)
    },
  }

  addrs, err := resolver.LookupHost(context.Background(), host)
  if err != nil {
    return "", err
  }

  for _, addr := range addrs {
    if strings.Contains(addr, ":") {
      logger.Printf("Resolved IPv6 address for host %s: %s", host, addr)
      return addr, nil
    }
  }

  return "", fmt.Errorf("no IPv6 address found for host %s", host)
}

func resolveDefaultDNS(host string) (string, error) {
  addrs, err := net.LookupHost(host)
  if err != nil {
    return "", err
  }

  for _, addr := range addrs {
    if strings.Contains(addr, ":") {
      logger.Printf("Resolved IPv6 address for host %s: %s", host, addr)
      return addr, nil
    }
    if !config.LockdownMode {
      logger.Printf("Resolved IPv4 address for host %s: %s", host, addr)
      return addr, nil
    }
  }

  return "", fmt.Errorf("no valid address found for host %s", host)
}

func removeAuthHeader(data []byte) []byte {
  lines := strings.Split(string(data), "\r\n")
  filteredLines := []string{}
  for _, line := range lines {
    if !strings.HasPrefix(strings.ToLower(line), "proxy-authorization: ") {
      filteredLines = append(filteredLines, line)
    }
  }
  return []byte(strings.Join(filteredLines, "\r\n"))
}

func isIPv4Address(host string) bool {
  ipv4Regex := regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
  return ipv4Regex.MatchString(host)
}

func isHostAllowed(host string) bool {
  for _, pattern := range config.DisallowedHosts {
    matched, _ := regexp.MatchString(pattern, host)
    if matched {
      logger.Printf("Host %s is disallowed by pattern %s", host, pattern)
      return false
    }
  }
  for _, pattern := range config.AllowedHosts {
    matched, _ := regexp.MatchString(pattern, host)
    if matched {
      logger.Printf("Host %s is allowed by pattern %s", host, pattern)
      return true
    }
  }
  logger.Printf("Host %s is not explicitly allowed or disallowed, defaulting to disallowed", host)
  return false
}

func isWebSocketUpgrade(data []byte) bool {
  dataString := strings.ToLower(string(data))
  return strings.Contains(dataString, "connection: upgrade") && strings.Contains(dataString, "upgrade: websocket")
}

func isConnectMethod(data []byte) bool {
  dataString := strings.ToUpper(string(data))
  return strings.HasPrefix(dataString, "CONNECT ")
}

func isIPAllowed(ip string) bool {
  translatedIP := ipv6ToIPv4(ip)

  for _, pattern := range config.DisallowedHosts {
    matched, _ := regexp.MatchString(pattern, ip)
    if matched {
      logger.Printf("IP %s is disallowed by pattern %s", ip, pattern)
      return false
    }
    if translatedIP != ip {
      matched, _ := regexp.MatchString(pattern, translatedIP)
      if matched {
        logger.Printf("Translated IP %s (original %s) is disallowed by pattern %s", translatedIP, ip, pattern)
        return false
      }
    }
  }
  return true
}

func ipv6ToIPv4(ipv6 string) string {
  const prefix = "64:ff9b::"
  if strings.HasPrefix(ipv6, prefix) {
    ipv4Part := ipv6[len(prefix):]
    ipv4Bytes := net.ParseIP(ipv4Part).To4()
    if ipv4Bytes != nil {
      return ipv4Bytes.String()
    }
  }
  return ipv6
}
