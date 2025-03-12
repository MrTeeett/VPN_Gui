package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/getlantern/systray"

	"main/settings"
)

func cleanup() {
	fmt.Println("Выполняется очистка: останавливаем proxy-core и отключаем системный прокси (если используется)")
	stopConfig()
	if currentMode != "vpn" {
		if err := settings.DisableSystemProxy(); err != nil {
			fmt.Println("Ошибка при отключении системного прокси:", err)
		} else {
			fmt.Println("Системный прокси успешно отключён")
		}
	}
}

func init() {
	if err := os.MkdirAll("profiles", 0755); err != nil {
		fmt.Println("Error creating profiles folder:", err)
	}
}

var (
	mainContent   *fyne.Container
	currentCmd    *exec.Cmd
	currentConfig string
	defaultConfig string
	cmdMutex      sync.Mutex
	mainWindow    fyne.Window
	currentMode   string // "vpn" или "proxy"
)

func main() {
	// Обработка сигналов для корректного завершения
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		s := <-sigChan
		fmt.Println("Получен сигнал завершения:", s)
		cleanup()
		os.Exit(1)
	}()

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Паника:", r)
			cleanup()
			os.Exit(1)
		}
	}()

	go systray.Run(onReady, onExit)

	a := app.New()
	mainWindow = a.NewWindow("VPN UI")

	defaultConfig = loadDefaultProfile()
	currentMode = loadDefaultMode()
	applyModeToConfig(currentMode)

	sidePanel := container.NewVBox(
		widget.NewButtonWithIcon("Profiles", theme.DocumentCreateIcon(), func() {
			mainContent.Objects = []fyne.CanvasObject{createProfilesList()}
			mainContent.Refresh()
		}),
		widget.NewButtonWithIcon("Settings", theme.SettingsIcon(), func() {}),
		widget.NewButtonWithIcon("Scripts", theme.MediaPlayIcon(), func() {
			mainContent.Objects = []fyne.CanvasObject{createScriptsTab(a)}
			mainContent.Refresh()
		}),
		widget.NewSeparator(),
		widget.NewLabel("Current Version: alpha 1"),
	)

	mainContent = container.NewVBox(createProfilesList())
	hamburger := widget.NewButtonWithIcon("", theme.MenuIcon(), nil)
	topBar := container.NewBorder(nil, nil, hamburger, nil, widget.NewLabel("Profiles"))

	var modeSelect *widget.Select
	c := cases.Title(language.English)
	modeSelect = widget.NewSelect([]string{"Proxy", "VPN"}, func(choice string) {
		newMode := strings.ToLower(choice)
		if newMode != currentMode {
			if newMode == "vpn" && !isAdmin() {
				dialog.ShowConfirm("Предупреждение", "VPN-режим требует запуска от администратора...", func(confirmed bool) {
					if confirmed {
						applyMode(newMode)
						modeSelect.SetSelected(c.String(newMode)) // Теперь modeSelect доступен
					} else {
						modeSelect.SetSelected(c.String(currentMode))
					}
				}, mainWindow)
			} else {
				applyMode(newMode)
			}
		}
	})
	modeSelect.SetSelected(c.String(currentMode))

	plusBtn := widget.NewButtonWithIcon("", theme.ContentAddIcon(), func() {
		showCreateConfigDialog(a)
	})
	linkImportBtn := widget.NewButtonWithIcon("Import by Link", theme.ContentPasteIcon(), func() {
		showImportProfileDialog(a)
	})
	bottomBar := container.NewBorder(nil, nil, nil,
		container.NewHBox(layout.NewSpacer(), modeSelect, plusBtn, linkImportBtn), nil)

	content := container.NewBorder(topBar, bottomBar, sidePanel, nil, mainContent)
	mainWindow.SetContent(content)

	hamburger.OnTapped = func() {
		if content.Objects[0] == sidePanel {
			content = container.NewBorder(topBar, bottomBar, nil, nil, mainContent)
		} else {
			content = container.NewBorder(topBar, bottomBar, sidePanel, nil, mainContent)
		}
		mainWindow.SetContent(content)
	}

	mainWindow.SetCloseIntercept(func() {
		mainWindow.Hide()
	})

	mainWindow.Resize(fyne.NewSize(700, 400))
	mainWindow.ShowAndRun()
}

func loadDefaultProfile() string {
	data, err := os.ReadFile("default_profile.txt")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func saveDefaultProfile(profile string) {
	if err := os.WriteFile("default_profile.txt", []byte(profile), 0600); err != nil {
		fmt.Println("Error saving default profile:", err)
	}
}

func loadDefaultMode() string {
	data, err := os.ReadFile("default_mode.txt")
	if err != nil {
		return "proxy"
	}
	return strings.TrimSpace(string(data))
}

func saveDefaultMode(mode string) {
	if err := os.WriteFile("default_mode.txt", []byte(mode), 0600); err != nil {
		fmt.Println("Error saving default mode:", err)
	}
}

func generateVlessLink(path, baseName string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Println("Error reading config for link generation:", err)
		return ""
	}
	var cfg settings.Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		fmt.Println("Error unmarshaling config:", err)
		return ""
	}
	var vless settings.Outbound
	for _, o := range cfg.Outbounds {
		if o.Tag == "vless-out" {
			vless = o
			break
		}
	}
	if vless.Server == "" || vless.Uuid == "" {
		fmt.Println("Недостаточно данных для генерации ссылки")
		return ""
	}
	security := "none"
	if vless.Tls != nil && vless.Tls.Enabled {
		if vless.Tls.Reality != nil && vless.Tls.Reality.Enabled {
			security = "reality"
		} else {
			security = "tls"
		}
	}
	q := url.Values{}
	q.Set("security", security)
	if vless.Tls != nil {
		if vless.Tls.Server_name != "" {
			q.Set("sni", vless.Tls.Server_name)
		}
		if len(vless.Tls.Alpn) > 0 {
			q.Set("alpn", vless.Tls.Alpn[0])
		}
		if vless.Tls.Utils != nil && vless.Tls.Utils.Enabled && vless.Tls.Utils.Fingerprint != "" {
			q.Set("fp", vless.Tls.Utils.Fingerprint)
		}
		if vless.Tls.Reality != nil && vless.Tls.Reality.Enabled {
			q.Set("pbk", vless.Tls.Reality.Public_key)
			q.Set("sid", vless.Tls.Reality.Short_id)
		}
	}
	q.Set("type", vless.Network)
	q.Set("flow", vless.Flow)
	q.Set("encryption", "none")
	return fmt.Sprintf("vless://%s@%s:%d?%s#%s", vless.Uuid, vless.Server, vless.Server_port, q.Encode(), baseName)
}

func parseVlessURI(link string) (settings.Config, string, error) {
	u, err := url.Parse(link)
	if err != nil {
		return settings.Config{}, "", err
	}
	if u.Scheme != "vless" {
		return settings.Config{}, "", fmt.Errorf("неверная схема: %s", u.Scheme)
	}
	uuid := u.User.Username()
	host := u.Host
	var server string
	var port uint
	if strings.Contains(host, ":") {
		parts := strings.Split(host, ":")
		server = parts[0]
		p, err := strconv.Atoi(parts[1])
		if err != nil {
			return settings.Config{}, "", err
		}
		port = uint(p)
	} else {
		server = host
		port = 443
	}
	q := u.Query()
	security := q.Get("security")
	sni := q.Get("sni")
	alpn := q.Get("alpn")
	fp := q.Get("fp")
	pbk := q.Get("pbk")
	sid := q.Get("sid")
	netType := q.Get("type")
	flow := q.Get("flow")
	tlsEnabled := security != "" && security != "none"
	realityEnabled := security == "reality"

	cfg := settings.Config{}
	cfg.Log.Level = "info"
	inbound := settings.Inbounds{
		Type:                       "mixed",
		Tag:                        "mixed-in",
		Listen:                     "127.0.0.1",
		Listen_port:                2080,
		Sniff:                      true,
		Sniff_override_destination: true,
	}
	cfg.Inbounds = []settings.Inbounds{inbound}
	vlessOutbound := settings.Outbound{
		Type:        "vless",
		Tag:         "vless-out",
		Server:      server,
		Server_port: port,
		Uuid:        uuid,
		Flow:        flow,
		Network:     netType,
	}
	if tlsEnabled {
		vlessOutbound.Tls = &settings.TLS{
			Enabled:     true,
			Server_name: sni,
			Alpn:        []string{alpn},
		}
		if fp != "" {
			vlessOutbound.Tls.Utils = &settings.Utils{
				Enabled:     true,
				Fingerprint: fp,
			}
		}
		if realityEnabled {
			vlessOutbound.Tls.Reality = &settings.Reality{
				Enabled:    true,
				Public_key: pbk,
				Short_id:   sid,
			}
		}
	}
	directOutbound := settings.Outbound{
		Type: "direct",
		Tag:  "direct-out",
	}
	cfg.Outbounds = []settings.Outbound{vlessOutbound, directOutbound}
	profileName := u.Fragment
	if profileName == "" {
		profileName = "profile"
	}
	return cfg, profileName, nil
}

func applyModeToConfig(mode string) {
	var cfg settings.Config
	data, err := os.ReadFile(defaultConfig)
	if err != nil {
		cfg = settings.Config{
			Log: settings.Log{Level: "info"},
			Inbounds: []settings.Inbounds{{
				Type:                       "mixed",
				Tag:                        "mixed-in",
				Listen:                     "127.0.0.1",
				Listen_port:                2080,
				Sniff:                      true,
				Sniff_override_destination: true,
			}},
			Outbounds: []settings.Outbound{{
				Type:        "vless",
				Tag:         "vless-out",
				Server:      "193.32.178.80",
				Server_port: 443,
				Uuid:        "887e27c6-cb6f-4200-95a5-ee1bbf383d0f",
				Flow:        "xtls-rprx-vision",
				Network:     "tcp",
				Tls: &settings.TLS{
					Enabled:     true,
					Server_name: "www.nvidia.com",
					Alpn:        []string{"h2"},
					Utils: &settings.Utils{
						Enabled:     true,
						Fingerprint: "chrome",
					},
					Reality: &settings.Reality{
						Enabled:    true,
						Public_key: "Bvu2NigYahtp1YHyVJvE3yknCqLmNUJi0RAwdQPWKF4",
						Short_id:   "4054b202f9223bdb",
					},
				},
			}, {
				Type: "direct",
				Tag:  "direct-out",
			}},
		}
	} else {
		if err := json.Unmarshal(data, &cfg); err != nil {
			fmt.Println("Error parsing config:", err)
			return
		}
	}

	if mode == "vpn" {
		if len(cfg.Inbounds) > 0 {
			cfg.Inbounds[0].Type = "tun"
			cfg.Inbounds[0].Tag = "tun-in"
			cfg.Inbounds[0].Listen = ""
			cfg.Inbounds[0].Listen_port = 0
			cfg.Inbounds[0].Interface_name = "proxycoretun"
			cfg.Inbounds[0].Address = []string{"10.10.0.1/30"}
			cfg.Inbounds[0].Mtu = 1500
			cfg.Inbounds[0].Auto_route = true
			cfg.Inbounds[0].Strict_route = true
			cfg.Inbounds[0].Stack = "system"
		} else {
			cfg.Inbounds = []settings.Inbounds{{
				Type:                       "tun",
				Tag:                        "tun-in",
				Sniff:                      true,
				Sniff_override_destination: false,
				Interface_name:             "proxycoretun",
				Address:                    []string{"10.10.0.1/30"},
				Mtu:                        1500,
				Auto_route:                 true,
				Strict_route:               true,
				Stack:                      "system",
			}}
		}
		cfg.DNS = &settings.DNS{
			Servers: []settings.DNSServer{
				{Tag: "proxy_dns", Address: "https://1.1.1.1/dns-query", Strategy: "ipv4_only", Detour: "vless-out"},
				{Tag: "fallback_dns", Address: "8.8.8.8", Strategy: "ipv4_only", Detour: "direct-out"},
			},
			Final: "proxy_dns",
		}
		cfg.Route = &settings.Route{
			Auto_detect_interface: true,
			Rules: []settings.RouteRule{
				{Protocol: "udp", Outbound: "direct-out"},
				{Protocol: "dns", Outbound: "dns-out"},
				{Ip_is_private: true, Outbound: "direct-out"},
			},
		}
		hasDNS, hasBlock := false, false
		for _, o := range cfg.Outbounds {
			if o.Type == "dns" {
				hasDNS = true
			}
			if o.Type == "block" {
				hasBlock = true
			}
		}
		if !hasDNS {
			cfg.Outbounds = append(cfg.Outbounds, settings.Outbound{Type: "dns", Tag: "dns-out"})
		}
		if !hasBlock {
			cfg.Outbounds = append(cfg.Outbounds, settings.Outbound{Type: "block", Tag: "block"})
		}
	} else {
		if len(cfg.Inbounds) > 0 {
			cfg.Inbounds[0].Type = "mixed"
			cfg.Inbounds[0].Tag = "mixed-in"
			cfg.Inbounds[0].Listen = "127.0.0.1"
			cfg.Inbounds[0].Listen_port = 2080
			cfg.Inbounds[0].Interface_name = ""
			cfg.Inbounds[0].Address = nil
			cfg.Inbounds[0].Mtu = 0
			cfg.Inbounds[0].Auto_route = false
			cfg.Inbounds[0].Strict_route = false
			cfg.Inbounds[0].Stack = ""
		} else {
			cfg.Inbounds = []settings.Inbounds{{
				Type:                       "mixed",
				Tag:                        "mixed-in",
				Listen:                     "127.0.0.1",
				Listen_port:                2080,
				Sniff:                      true,
				Sniff_override_destination: true,
			}}
		}
		cfg.DNS = nil
		cfg.Route = nil
		var newOutbounds []settings.Outbound
		for _, o := range cfg.Outbounds {
			if o.Type != "dns" && o.Type != "block" {
				newOutbounds = append(newOutbounds, o)
			}
		}
		cfg.Outbounds = newOutbounds
	}

	newData, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		fmt.Println("Error marshaling updated config:", err)
		return
	}
	if err := os.WriteFile(defaultConfig, newData, 0600); err != nil {
		fmt.Println("Error writing updated config:", err)
		return
	}
	fmt.Println("Config updated to mode:", mode)
}

func applyMode(mode string) {
	currentMode = mode
	saveDefaultMode(mode)
	applyModeToConfig(mode)
	caser := cases.Title(language.English)
	mainWindow.SetTitle(fmt.Sprintf("VPN UI - %s", caser.String(mode)))
	fmt.Println("Режим изменён на:", mode)
	if currentCmd != nil && defaultConfig != "" {
		stopConfig()
		runConfig(defaultConfig)
	}
}

func isAdmin() bool {
	cmd := exec.Command("net", "session")
	return cmd.Run() == nil
}

func onReady() {
	systray.SetIcon(iconData())
	systray.SetTitle("VPN UI")
	systray.SetTooltip("VPN UI Tray")

	mProfiles := systray.AddMenuItem("Profiles", "Сменить профиль")
	mRun := systray.AddMenuItem("Run", "Запустить VPN")
	mStop := systray.AddMenuItem("Stop", "Остановить VPN")
	mShow := systray.AddMenuItem("Show", "Показать окно")
	systray.AddSeparator()
	mQuit := systray.AddMenuItem("Quit", "Закрыть приложение")

	go func() {
		for {
			select {
			case <-mProfiles.ClickedCh:
				mainWindow.Show()
				mainContent.Objects = []fyne.CanvasObject{createProfilesList()}
				mainContent.Refresh()
			case <-mRun.ClickedCh:
				if defaultConfig != "" {
					runConfig(defaultConfig)
				}
			case <-mStop.ClickedCh:
				stopConfig()
			case <-mShow.ClickedCh:
				mainWindow.Show()
			case <-mQuit.ClickedCh:
				stopConfig()
				systray.Quit()
				os.Exit(0)
			}
		}
	}()
}

func onExit() {}

func iconData() []byte {
	return []byte{
		137, 80, 78, 71, 13, 10, 26, 10,
		0, 0, 0, 13, 73, 72, 68, 82,
		0, 0, 0, 1, 0, 0, 0, 1,
		8, 6, 0, 0, 0, 31, 21, 196,
		137, 0, 0, 0, 10, 73, 68, 65,
		84, 120, 218, 99, 100, 248, 255, 255,
		63, 0, 5, 254, 2, 254, 65, 226,
		206, 242, 0, 0, 0, 0, 73, 69,
		78, 68, 174, 66, 96, 130,
	}
}

func createProfilesList() fyne.CanvasObject {
	files, err := os.ReadDir("profiles")
	if err != nil {
		return widget.NewLabel("Error reading profiles folder: " + err.Error())
	}

	list := container.NewVBox()
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		fileName := f.Name()
		ext := filepath.Ext(fileName)
		baseName := strings.TrimSuffix(fileName, ext)
		fullPath := filepath.Join("profiles", fileName)

		runStopBtn := widget.NewButton("Run", func(path string) func() {
			return func() {
				cmdMutex.Lock()
				processRunning := currentCmd != nil
				currentProcess := currentConfig
				cmdMutex.Unlock()

				if processRunning {
					stopConfig()
					if currentProcess != path {
						runConfig(path)
					}
				} else {
					runConfig(path)
				}
				mainContent.Objects = []fyne.CanvasObject{createProfilesList()}
				mainContent.Refresh()
			}
		}(fullPath))

		cmdMutex.Lock()
		if currentCmd != nil && currentConfig == fullPath {
			runStopBtn.SetText("Stop")
		} else {
			runStopBtn.SetText("Run")
		}
		cmdMutex.Unlock()

		updateBtn := widget.NewButton("Update", func(path string) func() {
			return func() {
				showUpdateConfigDialog(filepath.Base(path))
			}
		}(fullPath))

		deleteBtn := widget.NewButton("Delete", func(path string) func() {
			return func() {
				if err := os.Remove(path); err != nil {
					fmt.Println("Error removing file:", err)
					return
				}
				mainContent.Objects = []fyne.CanvasObject{createProfilesList()}
				mainContent.Refresh()
			}
		}(fullPath))

		copyBtn := widget.NewButton("Copy", func(path, baseName string) func() {
			return func() {
				link := generateVlessLink(path, baseName)
				if link == "" {
					dialog.ShowInformation("Ошибка", "Не удалось сгенерировать ссылку", mainWindow)
					return
				}
				clip := fyne.CurrentApp().Driver().AllWindows()[0].Clipboard()
				clip.SetContent(link)
				dialog.ShowInformation("Успех", "Ссылка скопирована в буфер обмена", mainWindow)
			}
		}(fullPath, baseName))

		row := container.NewHBox(
			widget.NewLabel(baseName),
			layout.NewSpacer(),
			runStopBtn,
			updateBtn,
			deleteBtn,
			copyBtn,
		)
		list.Add(row)
	}
	return list
}

func createScriptsTab(a fyne.App) fyne.CanvasObject {
	btn := widget.NewButton("Server Setup", func() {
		showServerSetupDialog(a)
	})
	return container.NewVBox(widget.NewLabel("Скрипты"), btn)
}

func showServerSetupDialog(a fyne.App) {
	win := a.NewWindow("Server Setup")

	fileNameEntry := widget.NewEntry()
	fileNameEntry.SetPlaceHolder("Name")
	ipEntry := widget.NewEntry()
	ipEntry.SetPlaceHolder("IP-address")
	passEntry := widget.NewPasswordEntry()
	passEntry.SetPlaceHolder("password")
	sshPortEntry := widget.NewEntry()
	sshPortEntry.SetText("22")
	userPortEntry := widget.NewEntry()
	userPortEntry.SetPlaceHolder("Configuration port on server (preferably 443)")
	serverNamesEntry := widget.NewEntry()
	serverNamesEntry.SetPlaceHolder("disguised site (www.nvidia.com)")

	form := widget.NewForm(
		widget.NewFormItem("Name", fileNameEntry),
		widget.NewFormItem("IP-address", ipEntry),
		widget.NewFormItem("Password", passEntry),
		widget.NewFormItem("SSH port", sshPortEntry),
		widget.NewFormItem("User Port", userPortEntry),
		widget.NewFormItem("Server Names", serverNamesEntry),
	)

	okBtn := widget.NewButton("OK", func() {
		ip := strings.TrimSpace(ipEntry.Text)
		pass := strings.TrimSpace(passEntry.Text)
		sshPort := strings.TrimSpace(sshPortEntry.Text)
		userPort := strings.TrimSpace(userPortEntry.Text)
		serverNames := strings.TrimSpace(serverNamesEntry.Text)
		fileName := strings.TrimSpace(fileNameEntry.Text)

		if ip == "" || pass == "" || userPort == "" || serverNames == "" || fileName == "" {
			win.SetContent(container.NewVBox(form, widget.NewLabel("Пожалуйста, заполните все обязательные поля.")))
			return
		}

		args := []string{
			"-ip", ip,
			"-p", pass,
			"--port", sshPort,
			"-uport", userPort,
			"-s", serverNames,
			"-l", "profiles",
			"-f", fileName,
		}

		logBinding := binding.NewString()
		logBinding.Set("Запуск процесса...\n")
		progressText := widget.NewMultiLineEntry()
		progressText.Wrapping = fyne.TextWrapWord
		progressText.Bind(logBinding)
		progressWin := a.NewWindow("Server Setup Progress")
		progressWin.SetContent(container.NewScroll(progressText))
		progressWin.Resize(fyne.NewSize(500, 400))
		progressWin.Show()

		cmd := exec.Command("scripts/script", args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

		stdoutPipe, err := cmd.StdoutPipe()
		if err != nil {
			logBinding.Set(fmt.Sprintf("Ошибка получения stdout: %v\n", err))
			return
		}
		stderrPipe, err := cmd.StderrPipe()
		if err != nil {
			logBinding.Set(fmt.Sprintf("Ошибка получения stderr: %v\n", err))
			return
		}

		if err := cmd.Start(); err != nil {
			logBinding.Set(fmt.Sprintf("Ошибка запуска server setup: %v\n", err))
			return
		}

		appendLog := func(text string) {
			old, _ := logBinding.Get()
			logBinding.Set(old + text)
		}

		go func() {
			reader := bufio.NewReader(stdoutPipe)
			for {
				line, err := reader.ReadString('\n')
				if len(line) > 0 {
					appendLog(line)
				}
				if err != nil {
					break
				}
			}
		}()

		go func() {
			reader := bufio.NewReader(stderrPipe)
			for {
				line, err := reader.ReadString('\n')
				if len(line) > 0 {
					appendLog("ERROR: " + line)
				}
				if err != nil {
					break
				}
			}
		}()

		go func() {
			err := cmd.Wait()
			if err != nil {
				appendLog(fmt.Sprintf("\nПроцесс завершился с ошибкой: %v\n", err))
			} else {
				appendLog("\nПроцесс завершился успешно.\n")
			}
		}()

		win.Close()
	})

	cancelBtn := widget.NewButton("Cancel", func() {
		win.Close()
	})

	buttons := container.NewHBox(layout.NewSpacer(), okBtn, cancelBtn)
	dialogContent := container.NewBorder(nil, buttons, nil, nil, form)
	win.SetContent(dialogContent)
	win.Resize(fyne.NewSize(500, 400))
	win.Show()
}

func ensureConfigMode(path, mode string) {
	var cfg settings.Config
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Println("Error reading config:", err)
		return
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		fmt.Println("Error parsing config:", err)
		return
	}

	if mode == "vpn" {
		if len(cfg.Inbounds) == 0 || cfg.Inbounds[0].Type != "tun" {
			if len(cfg.Inbounds) > 0 {
				cfg.Inbounds[0].Type = "tun"
				cfg.Inbounds[0].Tag = "tun-in"
				cfg.Inbounds[0].Listen = ""
				cfg.Inbounds[0].Listen_port = 0
				cfg.Inbounds[0].Interface_name = "proxycoretun"
				cfg.Inbounds[0].Address = []string{"10.10.0.1/30"}
				cfg.Inbounds[0].Mtu = 1500
				cfg.Inbounds[0].Auto_route = true
				cfg.Inbounds[0].Strict_route = true
				cfg.Inbounds[0].Stack = "system"
			} else {
				cfg.Inbounds = []settings.Inbounds{{
					Type:                       "tun",
					Tag:                        "tun-in",
					Sniff:                      true,
					Sniff_override_destination: false,
					Interface_name:             "proxycoretun",
					Address:                    []string{"10.10.0.1/30"},
					Mtu:                        1500,
					Auto_route:                 true,
					Strict_route:               true,
					Stack:                      "system",
				}}
			}
			cfg.DNS = &settings.DNS{
				Servers: []settings.DNSServer{
					{Tag: "proxy_dns", Address: "https://1.1.1.1/dns-query", Strategy: "ipv4_only", Detour: "vless-out"},
					{Tag: "fallback_dns", Address: "8.8.8.8", Strategy: "ipv4_only", Detour: "direct-out"},
				},
				Final: "proxy_dns",
			}
			cfg.Route = &settings.Route{
				Auto_detect_interface: true,
				Rules: []settings.RouteRule{
					{Protocol: "udp", Outbound: "direct-out"},
					{Protocol: "dns", Outbound: "dns-out"},
					{Ip_is_private: true, Outbound: "direct-out"},
				},
			}
			hasDNS, hasBlock := false, false
			for _, o := range cfg.Outbounds {
				if o.Type == "dns" {
					hasDNS = true
				}
				if o.Type == "block" {
					hasBlock = true
				}
			}
			if !hasDNS {
				cfg.Outbounds = append(cfg.Outbounds, settings.Outbound{Type: "dns", Tag: "dns-out"})
			}
			if !hasBlock {
				cfg.Outbounds = append(cfg.Outbounds, settings.Outbound{Type: "block", Tag: "block"})
			}
		}
	} else {
		if len(cfg.Inbounds) == 0 || cfg.Inbounds[0].Type != "mixed" {
			if len(cfg.Inbounds) > 0 {
				cfg.Inbounds[0].Type = "mixed"
				cfg.Inbounds[0].Tag = "mixed-in"
				cfg.Inbounds[0].Listen = "127.0.0.1"
				cfg.Inbounds[0].Listen_port = 2080
				cfg.Inbounds[0].Interface_name = ""
				cfg.Inbounds[0].Address = nil
				cfg.Inbounds[0].Mtu = 0
				cfg.Inbounds[0].Auto_route = false
				cfg.Inbounds[0].Strict_route = false
				cfg.Inbounds[0].Stack = ""
			} else {
				cfg.Inbounds = []settings.Inbounds{{
					Type:                       "mixed",
					Tag:                        "mixed-in",
					Listen:                     "127.0.0.1",
					Listen_port:                2080,
					Sniff:                      true,
					Sniff_override_destination: true,
				}}
			}
			cfg.DNS = nil
			cfg.Route = nil
			var newOutbounds []settings.Outbound
			for _, o := range cfg.Outbounds {
				if o.Type != "dns" && o.Type != "block" {
					newOutbounds = append(newOutbounds, o)
				}
			}
			cfg.Outbounds = newOutbounds
		}
	}

	newData, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		fmt.Println("Error marshaling updated config:", err)
		return
	}
	if err := os.WriteFile(defaultConfig, newData, 0600); err != nil {
		fmt.Println("Error writing updated config:", err)
		return
	}
	fmt.Println("Configuration at", defaultConfig, "updated to mode:", mode)
}

func runConfig(configPath string) {
	ensureConfigMode(configPath, currentMode)
	stopConfig()

	if currentMode != "vpn" {
		if err := settings.EnableSystemProxy(); err != nil {
			fmt.Println("Error enabling system proxy:", err)
			return
		}
	}

	cmdMutex.Lock()
	currentConfig = configPath
	defaultConfig = configPath
	saveDefaultProfile(defaultConfig)
	cmdMutex.Unlock()

	cmd := exec.Command(".\\proxy-core", "-c", ".\\"+configPath, "run")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Start(); err != nil {
		fmt.Println("Error starting proxy-core:", err)
		return
	}

	if err := assignToJobObject(cmd.Process); err != nil {
		fmt.Println("Error assigning process to job object:", err)
	}

	cmdMutex.Lock()
	currentCmd = cmd
	cmdMutex.Unlock()

	go func() {
		err := cmd.Wait()
		cmdMutex.Lock()
		defer cmdMutex.Unlock()
		if err != nil {
			fmt.Println("proxy-core process ended with error:", err)
		} else {
			fmt.Println("proxy-core process ended normally")
		}
		currentCmd = nil
		currentConfig = ""
	}()

	fmt.Println("Started proxy-core with config:", configPath)
}

var globalJob windows.Handle

func assignToJobObject(proc *os.Process) error {
	if globalJob == 0 {
		hJob, err := windows.CreateJobObject(nil, nil)
		if err != nil {
			return fmt.Errorf("CreateJobObject failed: %v", err)
		}
		var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
		info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
		size := uint32(unsafe.Sizeof(info))
		_, err = windows.SetInformationJobObject(hJob, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), size)
		if err != nil {
			return fmt.Errorf("SetInformationJobObject failed: %v", err)
		}
		globalJob = hJob
	}

	hProc, err := windows.OpenProcess(windows.PROCESS_ALL_ACCESS, false, uint32(proc.Pid))
	if err != nil {
		return fmt.Errorf("OpenProcess failed: %v", err)
	}
	defer windows.CloseHandle(hProc)

	if err = windows.AssignProcessToJobObject(globalJob, hProc); err != nil {
		return fmt.Errorf("AssignProcessToJobObject failed: %v", err)
	}
	return nil
}

func stopConfig() {
	cmdMutex.Lock()
	cmd := currentCmd
	cmdMutex.Unlock()

	if cmd == nil {
		return
	}

	fmt.Println("Killing process with pid:", cmd.Process.Pid)
	if err := cmd.Process.Kill(); err != nil {
		fmt.Println("Error killing process:", err)
	} else {
		fmt.Println("Process kill signal sent.")
	}
	if err := cmd.Wait(); err != nil {
		fmt.Println("Error waiting for process exit:", err)
	} else {
		fmt.Println("Process exited successfully.")
	}

	cmdMutex.Lock()
	currentCmd = nil
	currentConfig = ""
	cmdMutex.Unlock()

	if currentMode != "vpn" {
		if err := settings.DisableSystemProxy(); err != nil {
			fmt.Println("Error disabling system proxy:", err)
		}
	}
	fmt.Println("Stopped proxy-core")
}

func showImportProfileDialog(a fyne.App) {
	win := a.NewWindow("Import Profile from Link")
	linkEntry := widget.NewEntry()
	linkEntry.SetPlaceHolder("vless://...")
	form := widget.NewForm(widget.NewFormItem("VLESS-ссылка", linkEntry))
	okBtn := widget.NewButton("OK", func() {
		link := strings.TrimSpace(linkEntry.Text)
		if link == "" {
			dialog.ShowInformation("Ошибка", "Ссылка не может быть пустой", win)
			return
		}
		cfg, profileName, err := parseVlessURI(link)
		if err != nil {
			dialog.ShowInformation("Ошибка", fmt.Sprintf("Неверный формат ссылки: %v", err), win)
			return
		}
		if err = saveConfig(profileName, cfg); err != nil {
			dialog.ShowInformation("Ошибка", fmt.Sprintf("Не удалось сохранить конфиг: %v", err), win)
			return
		}
		dialog.ShowInformation("Успех", "Профиль успешно импортирован", mainWindow)
		win.Close()
		mainContent.Objects = []fyne.CanvasObject{createProfilesList()}
		mainContent.Refresh()
	})
	cancelBtn := widget.NewButton("Cancel", func() { win.Close() })
	buttons := container.NewHBox(layout.NewSpacer(), okBtn, cancelBtn)
	content := container.NewBorder(nil, buttons, nil, nil, form)
	win.SetContent(content)
	win.Resize(fyne.NewSize(500, 150))
	win.Show()
}

func showCreateConfigDialog(a fyne.App) {
	newWin := a.NewWindow("Создать новый конфиг")
	configNameEntry := widget.NewEntry()
	configNameEntry.SetPlaceHolder("Имя файла (без .json)")
	serverEntry := widget.NewEntry()
	serverEntry.SetText("193.32.178.80")
	serverPortEntry := widget.NewEntry()
	serverPortEntry.SetText("443")
	uuidEntry := widget.NewEntry()
	uuidEntry.SetText("887e27c6-cb6f-4200-95a5-ee1bbf383d0f")
	flowSelect := widget.NewSelect([]string{"xtls-rprx-vision", "xtls-rprx-splice", "xtls-rprx-origin"}, func(string) {})
	flowSelect.SetSelected("xtls-rprx-vision")
	networkSelect := widget.NewSelect([]string{"tcp", "kcp", "ws"}, func(string) {})
	networkSelect.SetSelected("tcp")
	tlsEnabledCheck := widget.NewCheck("TLS Enabled", nil)
	tlsEnabledCheck.SetChecked(true)
	serverNameEntry := widget.NewEntry()
	serverNameEntry.SetText("www.nvidia.com")
	alpnEntry := widget.NewEntry()
	alpnEntry.SetText("h2")
	utlsEnabledCheck := widget.NewCheck("uTLS Enabled", nil)
	utlsEnabledCheck.SetChecked(true)
	fingerprintEntry := widget.NewEntry()
	fingerprintEntry.SetText("chrome")
	realityEnabledCheck := widget.NewCheck("Reality Enabled", nil)
	realityEnabledCheck.SetChecked(true)
	publicKeyEntry := widget.NewEntry()
	publicKeyEntry.SetText("Bvu2NigYahtp1YHyVJvE3yknCqLmNUJi0RAwdQPWKF4")
	shortIDEntry := widget.NewEntry()
	shortIDEntry.SetText("4054b202f9223bdb")

	form := widget.NewForm(
		widget.NewFormItem("Имя файла", configNameEntry),
		widget.NewFormItem("Server", serverEntry),
		widget.NewFormItem("Server Port", serverPortEntry),
		widget.NewFormItem("UUID", uuidEntry),
		widget.NewFormItem("Flow", flowSelect),
		widget.NewFormItem("Network", networkSelect),
		widget.NewFormItem("", tlsEnabledCheck),
		widget.NewFormItem("Server Name", serverNameEntry),
		widget.NewFormItem("ALPN", alpnEntry),
		widget.NewFormItem("", utlsEnabledCheck),
		widget.NewFormItem("Fingerprint", fingerprintEntry),
		widget.NewFormItem("", realityEnabledCheck),
		widget.NewFormItem("Public Key", publicKeyEntry),
		widget.NewFormItem("Short ID", shortIDEntry),
	)

	okBtn := widget.NewButton("OK", func() {
		cfgName := strings.TrimSpace(configNameEntry.Text)
		if cfgName == "" {
			fmt.Println("Имя файла не заполнено")
			return
		}
		cfg := buildConfigFromForm(
			serverEntry.Text,
			serverPortEntry.Text,
			uuidEntry.Text,
			flowSelect.Selected,
			networkSelect.Selected,
			tlsEnabledCheck.Checked,
			serverNameEntry.Text,
			alpnEntry.Text,
			utlsEnabledCheck.Checked,
			fingerprintEntry.Text,
			realityEnabledCheck.Checked,
			publicKeyEntry.Text,
			shortIDEntry.Text,
		)
		if err := saveConfig(cfgName, cfg); err != nil {
			fmt.Println("Error saving config:", err)
			return
		}
		newWin.Close()
		mainContent.Objects = []fyne.CanvasObject{createProfilesList()}
		mainContent.Refresh()
	})

	cancelBtn := widget.NewButton("Cancel", func() { newWin.Close() })
	buttons := container.NewHBox(layout.NewSpacer(), okBtn, cancelBtn)
	dialogContent := container.NewBorder(nil, buttons, nil, nil, form)
	newWin.SetContent(dialogContent)
	newWin.Resize(fyne.NewSize(500, 550))
	newWin.Show()
}

func showUpdateConfigDialog(fileName string) {
	newWin := fyne.CurrentApp().NewWindow("Update Config: " + fileName)
	filePath := filepath.Join("profiles", fileName)
	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}
	var cfg settings.Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		fmt.Println("Error unmarshal JSON:", err)
		return
	}

	var vlessOut *settings.Outbound
	var directOut *settings.Outbound
	for i := range cfg.Outbounds {
		switch cfg.Outbounds[i].Tag {
		case "vless-out":
			vlessOut = &cfg.Outbounds[i]
		case "direct-out":
			directOut = &cfg.Outbounds[i]
		}
	}
	if vlessOut == nil {
		cfg.Outbounds = append(cfg.Outbounds, settings.Outbound{Tag: "vless-out", Type: "vless"})
		vlessOut = &cfg.Outbounds[len(cfg.Outbounds)-1]
	}
	if directOut == nil {
		cfg.Outbounds = append(cfg.Outbounds, settings.Outbound{Tag: "direct-out", Type: "direct"})
		directOut = &cfg.Outbounds[len(cfg.Outbounds)-1]
	}

	serverEntry := widget.NewEntry()
	serverEntry.SetText(vlessOut.Server)
	serverPortEntry := widget.NewEntry()
	serverPortEntry.SetText(fmt.Sprintf("%d", vlessOut.Server_port))
	uuidEntry := widget.NewEntry()
	uuidEntry.SetText(vlessOut.Uuid)
	flowSelect := widget.NewSelect([]string{"xtls-rprx-vision", "xtls-rprx-splice", "xtls-rprx-origin"}, func(string) {})
	flowSelect.SetSelected(vlessOut.Flow)
	networkSelect := widget.NewSelect([]string{"tcp", "kcp", "ws"}, func(string) {})
	if vlessOut.Network != "" {
		networkSelect.SetSelected(vlessOut.Network)
	} else {
		networkSelect.SetSelected("tcp")
	}

	var tlsEnabled bool
	var serverName, alpn string
	var utlsEnabled bool
	var fingerprint string
	var realityEnabled bool
	var publicKey, shortID string
	if vlessOut.Tls != nil {
		tlsEnabled = vlessOut.Tls.Enabled
		serverName = vlessOut.Tls.Server_name
		if len(vlessOut.Tls.Alpn) > 0 {
			alpn = vlessOut.Tls.Alpn[0]
		}
		if vlessOut.Tls.Utils != nil {
			utlsEnabled = vlessOut.Tls.Utils.Enabled
			fingerprint = vlessOut.Tls.Utils.Fingerprint
		}
		if vlessOut.Tls.Reality != nil {
			realityEnabled = vlessOut.Tls.Reality.Enabled
			publicKey = vlessOut.Tls.Reality.Public_key
			shortID = vlessOut.Tls.Reality.Short_id
		}
	}
	tlsEnabledCheck := widget.NewCheck("TLS Enabled", nil)
	tlsEnabledCheck.SetChecked(tlsEnabled)
	serverNameEntry := widget.NewEntry()
	serverNameEntry.SetText(serverName)
	alpnEntry := widget.NewEntry()
	alpnEntry.SetText(alpn)
	utlsEnabledCheck := widget.NewCheck("uTLS Enabled", nil)
	utlsEnabledCheck.SetChecked(utlsEnabled)
	fingerprintEntry := widget.NewEntry()
	fingerprintEntry.SetText(fingerprint)
	realityEnabledCheck := widget.NewCheck("Reality Enabled", nil)
	realityEnabledCheck.SetChecked(realityEnabled)
	publicKeyEntry := widget.NewEntry()
	publicKeyEntry.SetText(publicKey)
	shortIDEntry := widget.NewEntry()
	shortIDEntry.SetText(shortID)

	form := widget.NewForm(
		widget.NewFormItem("Server", serverEntry),
		widget.NewFormItem("Server Port", serverPortEntry),
		widget.NewFormItem("UUID", uuidEntry),
		widget.NewFormItem("Flow", flowSelect),
		widget.NewFormItem("Network", networkSelect),
		widget.NewFormItem("", tlsEnabledCheck),
		widget.NewFormItem("Server Name", serverNameEntry),
		widget.NewFormItem("ALPN", alpnEntry),
		widget.NewFormItem("", utlsEnabledCheck),
		widget.NewFormItem("Fingerprint", fingerprintEntry),
		widget.NewFormItem("", realityEnabledCheck),
		widget.NewFormItem("Public Key", publicKeyEntry),
		widget.NewFormItem("Short ID", shortIDEntry),
	)

	okBtn := widget.NewButton("OK", func() {
		vlessOut.Server = serverEntry.Text
		vlessOut.Server_port = parseUint(serverPortEntry.Text)
		vlessOut.Uuid = uuidEntry.Text
		vlessOut.Flow = flowSelect.Selected
		vlessOut.Network = networkSelect.Selected
		vlessOut.Type = "vless"
		vlessOut.Tag = "vless-out"

		if tlsEnabledCheck.Checked {
			if vlessOut.Tls == nil {
				vlessOut.Tls = &settings.TLS{}
			}
			vlessOut.Tls.Enabled = true
			vlessOut.Tls.Server_name = serverNameEntry.Text
			vlessOut.Tls.Alpn = []string{alpnEntry.Text}
			if utlsEnabledCheck.Checked {
				if vlessOut.Tls.Utils == nil {
					vlessOut.Tls.Utils = &settings.Utils{}
				}
				vlessOut.Tls.Utils.Enabled = true
				vlessOut.Tls.Utils.Fingerprint = fingerprintEntry.Text
			} else {
				vlessOut.Tls.Utils = nil
			}
			if realityEnabledCheck.Checked {
				if vlessOut.Tls.Reality == nil {
					vlessOut.Tls.Reality = &settings.Reality{}
				}
				vlessOut.Tls.Reality.Enabled = true
				vlessOut.Tls.Reality.Public_key = publicKeyEntry.Text
				vlessOut.Tls.Reality.Short_id = shortIDEntry.Text
			} else {
				vlessOut.Tls.Reality = nil
			}
		} else {
			vlessOut.Tls = nil
		}

		if len(cfg.Inbounds) == 0 {
			cfg.Inbounds = []settings.Inbounds{{
				Type:                       "mixed",
				Tag:                        "mixed-in",
				Listen:                     "127.0.0.1",
				Listen_port:                2080,
				Sniff:                      true,
				Sniff_override_destination: true,
			}}
		} else {
			cfg.Inbounds[0].Type = "mixed"
			cfg.Inbounds[0].Tag = "mixed-in"
			cfg.Inbounds[0].Listen = "127.0.0.1"
			cfg.Inbounds[0].Listen_port = 2080
			cfg.Inbounds[0].Sniff = true
			cfg.Inbounds[0].Sniff_override_destination = true
		}
		if directOut != nil {
			directOut.Type = "direct"
			directOut.Tag = "direct-out"
		}

		cfg.Log.Level = "info"

		newData, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			fmt.Println("Error marshaling updated config:", err)
			return
		}
		settings.WriteJSON(filePath, newData)
		fmt.Println("Updated config saved to:", filePath)
		newWin.Close()
		mainContent.Objects = []fyne.CanvasObject{createProfilesList()}
		mainContent.Refresh()
	})

	cancelBtn := widget.NewButton("Cancel", func() { newWin.Close() })
	buttons := container.NewHBox(layout.NewSpacer(), okBtn, cancelBtn)
	dialogContent := container.NewBorder(nil, buttons, nil, nil, form)
	newWin.SetContent(dialogContent)
	newWin.Resize(fyne.NewSize(500, 550))
	newWin.Show()
}

func buildConfigFromForm(
	server, port, uuid, flow, network string,
	tlsEnabled bool,
	serverName, alpn string,
	utlsEnabled bool,
	fingerprint string,
	realityEnabled bool,
	publicKey, shortID string,
) settings.Config {
	inbound := settings.Inbounds{
		Type:                       "mixed",
		Tag:                        "mixed-in",
		Listen:                     "127.0.0.1",
		Listen_port:                2080,
		Tcp_fast_open:              false,
		Sniff:                      true,
		Sniff_override_destination: true,
		Set_system_proxy:           false,
	}

	vlessOutbound := settings.Outbound{
		Type:        "vless",
		Tag:         "vless-out",
		Server:      server,
		Server_port: parseUint(port),
		Uuid:        uuid,
		Flow:        flow,
		Network:     network,
	}
	if tlsEnabled {
		vlessOutbound.Tls = &settings.TLS{
			Enabled:     true,
			Server_name: serverName,
			Alpn:        []string{alpn},
		}
		if utlsEnabled {
			vlessOutbound.Tls.Utils = &settings.Utils{
				Enabled:     true,
				Fingerprint: fingerprint,
			}
		}
		if realityEnabled {
			vlessOutbound.Tls.Reality = &settings.Reality{
				Enabled:    true,
				Public_key: publicKey,
				Short_id:   shortID,
			}
		}
	}

	directOutbound := settings.Outbound{
		Type: "direct",
		Tag:  "direct-out",
	}

	var cfg settings.Config
	cfg.Log.Level = "info"
	cfg.Inbounds = []settings.Inbounds{inbound}
	cfg.Outbounds = []settings.Outbound{vlessOutbound, directOutbound}
	return cfg
}

func saveConfig(cfgName string, cfg settings.Config) error {
	if err := os.MkdirAll("profiles", 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	filePath := filepath.Join("profiles", cfgName+".json")
	settings.WriteJSON(filePath, data)
	return nil
}

func parseUint(s string) uint {
	var val uint
	_, err := fmt.Sscanf(s, "%d", &val)
	if err != nil {
		fmt.Println("Error parsing uint:", err)
		return 0
	}
	return val
}
