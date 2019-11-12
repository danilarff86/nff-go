package delegate

import (
	"encoding/json"
	"fmt"
	"github.com/intel-go/nff-go/types"
	"net"
	"os"
)

type HostConfig struct {
	EthIP   types.IPv4Address
	MacAddr [types.EtherAddrLen]uint8
}

type PortConfig struct {
	Local   HostConfig
	Remote  HostConfig
	EthPort uint16
}

type Config struct {
	Wan PortConfig
	Lan PortConfig
}

type hostConfigJSON struct {
	EthIP   string `json:"eth_ip"`
	MACAddr string `json:"mac_addr"`
}

type portConfigJSON struct {
	Local   hostConfigJSON `json:"local"`
	Remote  hostConfigJSON `json:"remote"`
	EthPort uint16         `json:"eth_port"`
}

type configJSON struct {
	WAN portConfigJSON `json:"wan"`
	LAN portConfigJSON `json:"lan"`
}

func parseIP(ipStr string) (net.IP, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, &delegateError{s: "Unable to parse IP address" + ipStr}
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		return nil, &delegateError{s: "Unable to parse IP address" + ipStr}
	}
	return ipv4, nil
}

func parseHostConfig(inCfg hostConfigJSON) (*HostConfig, error) {
	var outConf HostConfig
	ethIP, err := parseIP(inCfg.EthIP)
	if err != nil {
		return nil, err
	}
	outConf.EthIP = types.SliceToIPv4(ethIP)
	mac, err := net.ParseMAC(inCfg.MACAddr)
	if err != nil {
		return nil, &delegateError{s: fmt.Sprintf("Unable to parse MAC address: %s, %+v", inCfg.MACAddr, err)}
	}
	copy(outConf.MacAddr[:], mac)
	return &outConf, nil
}

func parsePortConfig(inCfg portConfigJSON) (*PortConfig, error) {
	localCfg, err := parseHostConfig(inCfg.Local)
	if err != nil {
		return nil, err
	}
	remoteCfg, err := parseHostConfig(inCfg.Remote)
	if err != nil {
		return nil, err
	}
	return &PortConfig{
		Local:   *localCfg,
		Remote:  *remoteCfg,
		EthPort: inCfg.EthPort,
	}, nil
}

func loadConfiguration(file string) (*Config, error) {
	var jsonConfig configJSON
	configFile, err := os.Open(file)
	defer configFile.Close()
	if err != nil {
		return nil, &delegateError{s: fmt.Sprintf("Error opening config file: %+v\n", err)}
	}
	jsonParser := json.NewDecoder(configFile)
	err = jsonParser.Decode(&jsonConfig)
	if err != nil {
		return nil, &delegateError{s: fmt.Sprintf("Unable to decode config: %+v\n", err)}
	}

	wanCfg, err := parsePortConfig(jsonConfig.WAN)
	if err != nil {
		return nil, err
	}
	lanCfg, err := parsePortConfig(jsonConfig.LAN)
	if err != nil {
		return nil, err
	}
	cfg := Config{
		Wan: *wanCfg,
		Lan: *lanCfg,
	}

	//fmt.Printf("ConfigJSON: %+v\n", jsonConfig)
	//fmt.Printf("Config: %+v\n", cfg)
	return &cfg, nil
}

func (this *Config) Parse(file string) error {
	cfg, err := loadConfiguration(file)
	if err == nil {
		*this = *cfg
	}
	return err
}
