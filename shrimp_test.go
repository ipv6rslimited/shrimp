/*
**
** shrimp_test
** Tests for shrimp
**
** Distributed under the COOL License.
**
** Copyright (c) 2024 IPv6.rs <https://ipv6.rs>
** All Rights Reserved
**
*/

package main

import (
  "encoding/base64"
  "testing"
  "net"
  "golang.org/x/crypto/bcrypt"
  "github.com/ipv6rslimited/lrucache"
  "os"
)

func TestStripPort(t *testing.T) {
  tests := []struct {
    input  string
    output string
  }{
    {"example.com:80", "example.com"},
    {"example.com", "example.com"},
    {"example.com:", "example.com"},
    {"127.0.0.1:8080", "127.0.0.1"},
    {"[::1]:443", "[::1]"},
  }

  for _, test := range tests {
    result := stripPort(test.input)
    if result != test.output {
      t.Errorf("stripPort(%s) = %s; want %s", test.input, result, test.output)
    }
  }
}

func TestGetHostPort(t *testing.T) {
  tests := []struct {
    input       string
    defaultPort string
    host        string
    port        string
  }{
    {"example.com:80", "443", "example.com", "80"},
    {"example.com", "443", "example.com", "443"},
    {"example.com:", "443", "example.com", "443"},
    {"127.0.0.1:8080", "443", "127.0.0.1", "8080"},
    {"[::1]:443", "443", "[::1]", "443"},
  }

  for _, test := range tests {
    host, port := getHostPort(test.input, test.defaultPort)
    if host != test.host || port != test.port {
      t.Errorf("getHostPort(%s, %s) = (%s, %s); want (%s, %s)", test.input, test.defaultPort, host, port, test.host, test.port)
    }
  }
}

func TestIsIPv4Address(t *testing.T) {
  tests := []struct {
    input  string
    output bool
  }{
    {"127.0.0.1", true},
    {"::1", false},
    {"192.168.0.1", true},
    {"example.com", false},
    {"2001:db8::ff00:42:8329", false},
  }

  for _, test := range tests {
    result := isIPv4Address(test.input)
    if result != test.output {
      t.Errorf("isIPv4Address(%s) = %t; want %t", test.input, result, test.output)
    }
  }
}

func TestRemoveAuthHeader(t *testing.T) {
  input := "GET / HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\nConnection: close\r\n\r\n"
  expected := "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
  result := removeAuthHeader([]byte(input))
  if string(result) != expected {
    t.Errorf("removeAuthHeader() = %s; want %s", result, expected)
  }
}

func TestCheckAuth(t *testing.T) {
  username := "user"
  password := "pass"
  hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
  users = map[string]string{
    username: string(hashedPassword),
  }

  validAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
  authenticated, promptPassword := checkAuth(validAuth)
  if !authenticated || promptPassword {
    t.Errorf("checkAuth() with valid credentials failed")
  }

  invalidAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":wrongpass"))
  authenticated, promptPassword = checkAuth(invalidAuth)
  if authenticated || !promptPassword {
    t.Errorf("checkAuth() with invalid credentials passed")
  }

  authenticated, promptPassword = checkAuth("")
  if authenticated || !promptPassword {
    t.Errorf("checkAuth() with no credentials passed")
  }

  nonBasicAuth := "Bearer " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
  authenticated, promptPassword = checkAuth(nonBasicAuth)
  if authenticated || !promptPassword {
    t.Errorf("checkAuth() with non-basic auth passed")
  }

  users = nil
}

func TestConnectTo(t *testing.T) {
  host, port := "www.google.com", "80"
  conn, err := connectTo(host, port)
  if err != nil {
    t.Errorf("connectTo(%s, %s) failed: %v", host, port, err)
  }
  if conn != nil {
    conn.Close()
  }
}

func TestLookupWithCache(t *testing.T) {
  hostname := "localhost"
  ip, err := lookupWithCache(hostname)
  if err != nil {
    t.Errorf("lookupWithCache(%s) failed: %v", hostname, err)
  }
  if net.ParseIP(ip) == nil {
    t.Errorf("lookupWithCache(%s) returned invalid IP: %s", hostname, ip)
  }
}

func TestMain(m *testing.M) {
  config = Config{
    DNSCacheCapacity: 10,
    DNSTTL:           60,
    DebugMode:        false,
  }
  setLogger(config.DebugMode)

  dnsCache = lrucache.NewLRUCache(config.DNSCacheCapacity)

  code := m.Run()

  os.Exit(code)
}
