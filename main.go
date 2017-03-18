package main

import (
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"gopkg.in/urfave/cli.v1"
)

var (
	gatewayMac string
	timeout    time.Duration = 30 * time.Second
	macAddrs   []string
)

func main() {
	app := cli.NewApp()
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "interface, i",
			Usage: "The interface you want to use for the hack.",
		},
		cli.IntFlag{
			Name:  "packet-limit, l",
			Usage: "Limit the number of packets to capture. Default: 10",
		},
		cli.BoolFlag{
			Name:  "promiscuous, p",
			Usage: "Put the interface into promiscuous mode. Default: false",
		},
	}

	app.Action = func(c *cli.Context) error {
		packetLimit := c.Int("packet-limit")
		log.Println(packetLimit)
		if packetLimit == 0 {
			packetLimit = 10
		}

		iface := c.String("interface")
		if len(iface) == 0 {
			return errors.New("Please supply a network interface.")
		}

		promiscuousMode := c.Bool("promiscuous")

		interfaceToUse, err := net.InterfaceByName(iface)
		if err != nil {
			return err
		}

		gatewayMac = interfaceToUse.HardwareAddr.String() // log to file.
		log.Println("Your Mac Address: " + gatewayMac)

		macAddrs := findMacAddrs(interfaceToUse, int32(1024), promiscuousMode, timeout, int32(packetLimit))

		// use a random mac address and spoof the users.
		rand.Seed(time.Now().Unix())
		macAddr := macAddrs[rand.Intn(len(macAddrs))]
		log.Println("Going to use: " + macAddr)
		log.Println(macAddr)

		log.Println("We will now disconnect you from the network and spoof your mac address.")

		return nil
	}

	app.Run(os.Args)
}

func findMacAddrs(iface *net.Interface, snapshotLength int32, promiscuous bool, timeout time.Duration, packetLimit int32) []string {
	handle, err := pcap.OpenLive(iface.Name, snapshotLength, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetCount := int32(0)
	log.Println("Finding client MAC addresses.")
	log.Println("=============================")
	for packet := range packetSource.Packets() {
		// Process packet here
		if packetCount <= packetLimit {
			if ethernetLayer := packet.Layer(layers.LayerTypeEthernet); ethernetLayer != nil {
				// store mac addresses.
				etherPacket, _ := ethernetLayer.(*layers.Ethernet)

				if contains(macAddrs, etherPacket.SrcMAC.String()) == false && etherPacket.SrcMAC.String() != gatewayMac {
					macAddrs = append(macAddrs, etherPacket.SrcMAC.String())
				}

				if contains(macAddrs, etherPacket.DstMAC.String()) == false && etherPacket.DstMAC.String() != gatewayMac {
					macAddrs = append(macAddrs, etherPacket.DstMAC.String())
				}
			}
			packetCount++
			fmt.Print("▓")
		} else {
			handle.Close()
			fmt.Println("")
			break
		}
	}

	return macAddrs
}

func contains(macAddrs []string, addr string) bool {
	for _, v := range macAddrs {
		if v == addr {
			return true
		}
	}

	return false
}
