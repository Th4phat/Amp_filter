package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

var (
	working_amp string
	idk_man     []string
)

type amp struct {
	name     string
	protocol string
	port     string
	payload  []byte
}

func main() {
	var wg sync.WaitGroup
	if len(os.Args) != 4 {
		fmt.Printf("usage: %s [Type] [list to check] [output file] [thread]", os.Args[0])
		fmt.Println("[Type] : ldap cldap dns ssdp memcache")
		os.Exit(0)
	}
	amp_type := os.Args[1]
	amps := []amp{ // Hard code
		{name: "ldap", protocol: "udp", port: "389", payload: []byte("\x30\x84\x00\x00\x00\x2d\x02\x01\x01\x63\x84\x00\x00\x00\x24\x04\x00\x0a")},
		{name: "cldap", protocol: "udp", port: "389", payload: []byte("\x30\x25\x02\x01\x01\x63\x20\x04\x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x00\x01\x01\x00\x87\x0b\x6f\x62\x6a\x65\x63\x74\x63\x6c\x61\x73\x73\x30\x00")},
		{name: "dns", protocol: "udp", port: "53", payload: []byte("\xc4\x75\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00\x00\xff\x00\x01\x00")},
		{name: "memcache", protocol: "udp", port: "11211", payload: []byte(`\0\x01\0\0\0\x01\0\0gets a b c d e f g h j k l m n o p q r s t w v u x y a\r\n`)},
		{name: "ntp", protocol: "udp", port: "123", payload: []byte("\x17\x00\x03\x2a\x00\x00\x00\x00")},
		{name: "stun", protocol: "udp", port: "3478", payload: []byte("\x00\x01\x00\x00\x21\x12\xa4\x42\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")},
		{name: "ssdp", protocol: "udp", port: "1900", payload: []byte("\x4d\x2d\x53\x45\x41\x52\x43\x48\x20\x2a\x20\x48\x54\x54\x50\x2f\x31\x2e\x31\x0D​\x0A\x48\x6f\x73\x74\x3a\x32\x33\x39\x2e\x32\x35\x35\x2e\x32\x35\x35\x2e\x32\x35​\x30\x3a\x31\x39\x30\x30\x0D\x0A\x53\x54\x3a\x73\x73\x64\x70\x3a\x61\x6c\x6c\x0D​\x0A\x4d\x61\x6e\x3a\x22\x73\x73\x64\x70\x3a\x64\x69\x73\x63\x6f\x76\x65\x72\x22​\x0D\x0A\x4d\x58\x3a\x33\x0D\x0A\x0D\x0A")},
	}
	for proto, a := range amps {
		if a.name == amp_type {
			fmt.Print("Start checking ...\n")
			for i := 0; i < 20; i++ {
				wg.Add(1)
				go func() {
					check_amp(amps[proto].payload, amps[proto].protocol, amps[proto].port)
					wg.Done()
				}()
			}
			break
		} else {
			fmt.Println("Type was not avalible")
			os.Exit(0)
		}
	}
	wg.Wait()
}

func check_amp(payload []byte, pt string, port string) {
	var ipv4_server []string //  server
	file, err := os.Open(os.Args[2])
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		ipv4_server = append(ipv4_server, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		fmt.Println("Error scanning file:", err)
		return
	}
	ipv4_server = rmdupe(ipv4_server)
	if pt == "udp" {
		fmt.Print("Start checking with udp protocol\n")
		var idk_man []string
		for c := range ipv4_server {
			server := ipv4_server[c]
			address, err := net.ResolveUDPAddr("udp", server+":"+port)
			if err != nil {
				fmt.Println("Error resolving address:", err)
				return
			}
			connection, err := net.DialUDP("udp", nil, address)
			if err != nil {
				fmt.Println("Error connecting:", err)
				return
			}
			defer connection.Close()
			_, err = connection.Write(payload)
			if err != nil {
				fmt.Println("Error sending packet:", err)
				return
			}

			timeout := time.Duration(200) * time.Millisecond
			connection.SetReadDeadline(time.Now().Add(timeout))
			response := make([]byte, 2048)

			_, err = connection.Read(response)
			if err != nil {
				//fmt.Println("Error receiving response:", err)
				continue
			}
			idk_man = append(idk_man, server)
		}
		create_new_file(idk_man)
	} else { // IDK i just Copy paste from above
		fmt.Print("Start checking with tcp protocol\n")
		var idk_man []string
		for c := range ipv4_server {
			server := ipv4_server[c]
			address, err := net.ResolveTCPAddr("tcp", server+":"+port)
			if err != nil {
				fmt.Println("Error resolving address:", err)
				return
			}
			connection, err := net.DialTCP("tcp", nil, address)
			if err != nil {
				fmt.Println("Error connecting:", err)
				return
			}
			defer connection.Close()
			_, err = connection.Write(payload)
			if err != nil {
				fmt.Println("Error sending packet:", err)
				return
			}

			timeout := time.Duration(200) * time.Millisecond
			connection.SetReadDeadline(time.Now().Add(timeout))
			response := make([]byte, 2048)

			_, err = connection.Read(response)
			if err != nil {
				//fmt.Println("Error receiving response:", err)
				continue
			}
			idk_man = append(idk_man, server)
		}
		create_new_file(idk_man)
	}
}

func create_new_file(lines []string) {
	file, err := os.Create(os.Args[3])
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close()
	writer := bufio.NewWriter(file)
	for _, line := range lines {
		_, err := writer.WriteString(line + "\n")
		if err != nil {
			fmt.Println("Error writing to file:", err)
			return
		}
	}
	err = writer.Flush()
	if err != nil {
		fmt.Println("Error flushing writer:", err)
		return
	}

	fmt.Println("File written successfully.")
}

func rmdupe(serv_list []string) []string {
	uniqueserv_list := make(map[string]struct{})
	for _, pepe := range serv_list {
		uniqueserv_list[pepe] = struct{}{}
	}
	var result []string
	for pepe := range uniqueserv_list {
		result = append(result, pepe)
	}
	return result
}
