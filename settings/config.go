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

type Config struct {
	Log       Log        `json:"log,omitempty"`
	Inbounds  []Inbounds `json:"inbounds,omitempty"`
	Outbounds []Outbound `json:"outbounds,omitempty"`
	// Если нужно добавить route, то можно его также определить с omitempty:
	// Route     *Route     `json:"route,omitempty"`
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
	Utils       *Utils   `json:"utls,omitempty"` // используем "utls" согласно входящему JSON
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

// EnableSystemProxy включает системный прокси
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

// DisableSystemProxy отключает системный прокси
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

// enableWindowsProxy использует реестр для включения прокси
func enableWindowsProxy() error {
	// Открываем ключ реестра Internet Settings
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.SET_VALUE)
	if err != nil {
		return errorf("failed to open registry key: %v", err)
	}
	defer k.Close()

	// Включаем прокси (ProxyEnable = 1)
	if err := k.SetDWordValue("ProxyEnable", 1); err != nil {
		return errorf("failed to set ProxyEnable: %v", err)
	}

	// Задаём прокси-сервер (ProxyServer = "127.0.0.1:2080")
	proxy := proxyAddress + ":" + proxyPort
	if err := k.SetStringValue("ProxyServer", proxy); err != nil {
		return errorf("failed to set ProxyServer: %v", err)
	}

	log.Printf("Windows proxy enabled with %s", proxy)
	return nil
}

// disableWindowsProxy использует реестр для отключения прокси
func disableWindowsProxy() error {
	// Открываем ключ реестра Internet Settings
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.SET_VALUE)
	if err != nil {
		return errorf("failed to open registry key: %v", err)
	}
	defer k.Close()

	// Отключаем прокси (ProxyEnable = 0)
	if err := k.SetDWordValue("ProxyEnable", 0); err != nil {
		return errorf("failed to disable proxy: %v", err)
	}

	log.Println("Windows proxy disabled")
	return nil
}

// enableLinuxProxy включает прокси для Linux (GNOME) с помощью gsettings
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

// disableLinuxProxy отключает прокси для Linux (GNOME) с помощью gsettings
func disableLinuxProxy() error {
	cmd := exec.Command("gsettings", "set", "org.gnome.system.proxy", "mode", "none")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return errorf("failed to disable proxy on Linux: %v, output: %s", err, out)
	}
	log.Println("Linux GNOME proxy disabled")
	return nil
}

// errorf форматирует сообщение об ошибке, используя fmt.Sprintf
func errorf(format string, args ...interface{}) error {
	return errors.New(fmt.Sprintf(format, args...))
}
