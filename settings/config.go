package settings

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"

	"golang.org/x/sys/windows/registry"
)

const (
	proxyAddress = "127.0.0.1"
	proxyPort    = "2080"
)

// Config теперь включает новые секции DNS и Route.
type Config struct {
	Log       Log        `json:"log,omitempty"`
	Inbounds  []Inbounds `json:"inbounds,omitempty"`
	Outbounds []Outbound `json:"outbounds,omitempty"`
	DNS       *DNS       `json:"dns,omitempty"`
	Route     *Route     `json:"route,omitempty"`
}

type Log struct {
	Level string `json:"level,omitempty"`
}

type Inbounds struct {
	Type                       string `json:"type,omitempty"`
	Tag                        string `json:"tag,omitempty"`
	Listen                     string `json:"listen,omitempty"`
	Listen_port                uint   `json:"listen_port,omitempty"`
	Tcp_fast_open              bool   `json:"tcp_fast_open,omitempty"`
	Sniff                      bool   `json:"sniff,omitempty"`
	Sniff_override_destination bool   `json:"sniff_override_destination,omitempty"`
	Set_system_proxy           bool   `json:"set_system_proxy,omitempty"`

	// Дополнительные поля для VPN (TUN) режима:
	Interface_name string   `json:"interface_name,omitempty"`
	Address        []string `json:"address,omitempty"` // Пример: []string{"10.10.0.1/30"}
	Mtu            uint     `json:"mtu,omitempty"`     // Например, 1500
	Auto_route     bool     `json:"auto_route,omitempty"`
	Strict_route   bool     `json:"strict_route,omitempty"`
	Stack          string   `json:"stack,omitempty"` // Например, "system"
}

type Outbound struct {
	Type        string `json:"type,omitempty"`
	Tag         string `json:"tag,omitempty"`
	Server      string `json:"server,omitempty"`
	Server_port uint   `json:"server_port,omitempty"`
	Uuid        string `json:"uuid,omitempty"`
	Flow        string `json:"flow,omitempty"`
	Network     string `json:"network,omitempty"`
	Tls         *TLS   `json:"tls,omitempty"`
}

type TLS struct {
	Enabled     bool     `json:"enabled,omitempty"`
	Server_name string   `json:"server_name,omitempty"`
	Alpn        []string `json:"alpn,omitempty"`
	Utils       *Utils   `json:"utls,omitempty"` // Используем ключ "utls" согласно входящему JSON
	Reality     *Reality `json:"reality,omitempty"`
}

type Utils struct {
	Enabled     bool   `json:"enabled,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

type Reality struct {
	Enabled    bool   `json:"enabled,omitempty"`
	Public_key string `json:"public_key,omitempty"`
	Short_id   string `json:"short_id,omitempty"`
}

// Новая секция DNS
type DNS struct {
	Servers []DNSServer `json:"servers,omitempty"`
	Final   string      `json:"final,omitempty"`
}

type DNSServer struct {
	Tag      string `json:"tag,omitempty"`
	Address  string `json:"address,omitempty"`
	Strategy string `json:"strategy,omitempty"`
	Detour   string `json:"detour,omitempty"`
}

// Новая секция маршрутизации (Route)
type Route struct {
	Auto_detect_interface bool        `json:"auto_detect_interface,omitempty"`
	Rules                 []RouteRule `json:"rules,omitempty"`
	Final                 string      `json:"final,omitempty"`
}

type RouteRule struct {
	Protocol      string      `json:"protocol,omitempty"`
	Outbound      string      `json:"outbound,omitempty"`
	Ip_is_private bool        `json:"ip_is_private,omitempty"`
	Ip_cidr       []string    `json:"ip_cidr,omitempty"`
	Network       string      `json:"network,omitempty"`
	Port          interface{} `json:"port,omitempty"` // Может быть числом или массивом
}

// ReadJSON читает и форматирует конфигурацию из файла.
func ReadJSON(path string) []byte {
	file, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}

	var data Config
	err = json.Unmarshal(file, &data)
	if err != nil {
		log.Fatal(err)
	}

	formattedData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		log.Fatal(err)
	}

	return formattedData
}

// WriteJSON записывает данные в файл.
func WriteJSON(path string, data []byte) {
	file, err := os.Create(path)
	if err != nil {
		log.Fatal(err)
	}
	_, err = file.Write(data)
	if err != nil {
		log.Fatal(err)
	}
}

// MergeConfigs объединяет несколько конфигурационных профилей в один итоговый объект.
// Для массивов (Inbounds, Outbounds) выполняется конкатенация,
// для секций DNS и Route выбирается последний ненулевой.
func MergeConfigs(configs ...Config) (Config, error) {
	var merged Config

	// Объединяем логирование – выбираем последний уровень, если указан.
	for _, cfg := range configs {
		if cfg.Log.Level != "" {
			merged.Log.Level = cfg.Log.Level
		}
	}

	// Конкатенация Inbounds.
	for _, cfg := range configs {
		merged.Inbounds = append(merged.Inbounds, cfg.Inbounds...)
	}

	// Конкатенация Outbounds.
	for _, cfg := range configs {
		merged.Outbounds = append(merged.Outbounds, cfg.Outbounds...)
	}

	// DNS: если есть хотя бы один ненулевой, выбираем последний.
	for _, cfg := range configs {
		if cfg.DNS != nil {
			merged.DNS = cfg.DNS
		}
	}

	// Route: аналогично, выбираем последний ненулевой.
	for _, cfg := range configs {
		if cfg.Route != nil {
			merged.Route = cfg.Route
		}
	}

	return merged, nil
}

// EnableSystemProxy включает системный прокси.
func EnableSystemProxy() error {
	switch runtime.GOOS {
	case "windows":
		return enableWindowsProxy()
	case "linux":
		return enableLinuxProxy()
	default:
		return errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// DisableSystemProxy отключает системный прокси.
func DisableSystemProxy() error {
	switch runtime.GOOS {
	case "windows":
		return disableWindowsProxy()
	case "linux":
		return disableLinuxProxy()
	default:
		return errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// enableWindowsProxy использует реестр для включения прокси.
func enableWindowsProxy() error {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.SET_VALUE)
	if err != nil {
		return errorf("failed to open registry key: %v", err)
	}
	defer k.Close()

	if err := k.SetDWordValue("ProxyEnable", 1); err != nil {
		return errorf("failed to set ProxyEnable: %v", err)
	}

	proxy := proxyAddress + ":" + proxyPort
	if err := k.SetStringValue("ProxyServer", proxy); err != nil {
		return errorf("failed to set ProxyServer: %v", err)
	}

	log.Printf("Windows proxy enabled with %s", proxy)
	return nil
}

// disableWindowsProxy использует реестр для отключения прокси.
func disableWindowsProxy() error {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.SET_VALUE)
	if err != nil {
		return errorf("failed to open registry key: %v", err)
	}
	defer k.Close()

	if err := k.SetDWordValue("ProxyEnable", 0); err != nil {
		return errorf("failed to disable proxy: %v", err)
	}

	log.Println("Windows proxy disabled")
	return nil
}

// enableLinuxProxy включает прокси для Linux (GNOME) с помощью gsettings.
func enableLinuxProxy() error {
	commands := [][]string{
		{"gsettings", "set", "org.gnome.system.proxy", "mode", "manual"},
		{"gsettings", "set", "org.gnome.system.proxy.http", "host", proxyAddress},
		{"gsettings", "set", "org.gnome.system.proxy.http", "port", proxyPort},
		{"gsettings", "set", "org.gnome.system.proxy.https", "host", proxyAddress},
		{"gsettings", "set", "org.gnome.system.proxy.https", "port", proxyPort},
	}
	for _, args := range commands {
		cmd := exec.Command(args[0], args[1:]...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return errorf("failed to run %v: %v, output: %s", args, err, out)
		}
	}
	log.Println("Linux GNOME proxy enabled")
	return nil
}

// disableLinuxProxy отключает прокси для Linux (GNOME) с помощью gsettings.
func disableLinuxProxy() error {
	cmd := exec.Command("gsettings", "set", "org.gnome.system.proxy", "mode", "none")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return errorf("failed to disable proxy on Linux: %v, output: %s", err, out)
	}
	log.Println("Linux GNOME proxy disabled")
	return nil
}

// errorf форматирует сообщение об ошибке.
func errorf(format string, args ...interface{}) error {
	return errors.New(fmt.Sprintf(format, args...))
}
