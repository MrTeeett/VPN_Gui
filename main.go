package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/getlantern/systray"

	"main/settings"
)

func init() {
	if err := os.MkdirAll("profiles", 0755); err != nil {
		fmt.Println("Error creating profiles folder:", err)
	}
}

var (
	mainContent   *fyne.Container
	currentCmd    *exec.Cmd   // текущий запущенный процесс proxy-core
	currentConfig string      // путь к запущенному конфигу
	defaultConfig string      // последний запущенный файл для запуска по умолчанию
	cmdMutex      sync.Mutex  // защита currentCmd/currentConfig
	mainWindow    fyne.Window // главное окно для доступа из трей-меню
)

func main() {
	// Запускаем системный трей в отдельной горутине.
	go systray.Run(onReady, onExit)

	a := app.New()
	mainWindow = a.NewWindow("VPN UI")

	// Читаем сохранённый профиль по умолчанию.
	defaultConfig = loadDefaultProfile()

	// Боковая панель – добавляем кнопки для Profiles, Settings и Скриптов.
	sidePanel := container.NewVBox(
		widget.NewButtonWithIcon("Profiles", theme.DocumentCreateIcon(), func() {
			mainContent.Objects = []fyne.CanvasObject{createProfilesList()}
			mainContent.Refresh()
		}),
		widget.NewButtonWithIcon("Settings", theme.SettingsIcon(), func() {
			// Обработка настроек
		}),
		widget.NewButtonWithIcon("Скрипты", theme.MediaPlayIcon(), func() {
			mainContent.Objects = []fyne.CanvasObject{createScriptsTab(a)}
			mainContent.Refresh()
		}),
		widget.NewSeparator(),
		widget.NewLabel("Current Version: alpha 1"),
	)

	// Главный контейнер – изначально отображаем список профилей.
	mainContent = container.NewVBox(createProfilesList())

	// Верхняя панель (гамбургер + заголовок)
	hamburger := widget.NewButtonWithIcon("", theme.MenuIcon(), nil)
	topBar := container.NewBorder(nil, nil, hamburger, nil, widget.NewLabel("Profiles"))

	// Кнопка "+" для создания нового конфига
	plusBtn := widget.NewButtonWithIcon("", theme.ContentAddIcon(), func() {
		showCreateConfigDialog(a)
	})
	bottomBar := container.NewBorder(nil, nil, nil,
		container.NewHBox(layout.NewSpacer(), plusBtn),
		nil,
	)

	// Итоговый контейнер
	content := container.NewBorder(topBar, bottomBar, sidePanel, nil, mainContent)
	mainWindow.SetContent(content)

	// Логика открытия/скрытия боковой панели
	var panelOpen = true
	hamburger.OnTapped = func() {
		panelOpen = !panelOpen
		if panelOpen {
			content = container.NewBorder(topBar, bottomBar, sidePanel, nil, mainContent)
		} else {
			content = container.NewBorder(topBar, bottomBar, nil, nil, mainContent)
		}
		mainWindow.SetContent(content)
	}

	// При закрытии окна оно скрывается в трей.
	mainWindow.SetCloseIntercept(func() {
		mainWindow.Hide()
	})

	mainWindow.Resize(fyne.NewSize(700, 400))
	mainWindow.ShowAndRun()
}

// loadDefaultProfile читает сохранённый профиль из файла.
func loadDefaultProfile() string {
	data, err := os.ReadFile("default_profile.txt")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// saveDefaultProfile сохраняет профиль в файл.
func saveDefaultProfile(profile string) {
	err := os.WriteFile("default_profile.txt", []byte(profile), 0644)
	if err != nil {
		fmt.Println("Error saving default profile:", err)
	}
}

// onReady вызывается при инициализации трей-иконки.
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

// onExit вызывается при выходе из трей.
func onExit() {
	// Очистка при необходимости.
}

// iconData возвращает байты иконки (1x1 прозрачный PNG).
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

// createProfilesList читает файлы из папки "profiles" и отображает их списком.
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

		runStopBtn := widget.NewButton("Run", nil)
		runStopBtn.OnTapped = func(path string) func() {
			return func() {
				cmdMutex.Lock()
				processRunning := currentCmd != nil
				currentProcess := currentConfig
				cmdMutex.Unlock()

				if processRunning {
					// Если процесс уже запущен, останавливаем его.
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
		}(fullPath)

		// Обновляем текст кнопки в зависимости от запущенного конфига.
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

		row := container.NewHBox(
			widget.NewLabel(baseName),
			layout.NewSpacer(),
			runStopBtn,
			updateBtn,
			deleteBtn,
		)
		list.Add(row)
	}
	return list
}

// createScriptsTab создаёт содержимое вкладки "Скрипты" с кнопкой Server Setup.
func createScriptsTab(a fyne.App) fyne.CanvasObject {
	btn := widget.NewButton("Server Setup", func() {
		showServerSetupDialog(a)
	})
	// Можно добавить дополнительные элементы, если потребуется.
	return container.NewVBox(
		widget.NewLabel("Скрипты"),
		btn,
	)
}

// showServerSetupDialog открывает окно для ввода данных, запускает внешний скрипт,
// отображает ход выполнения и сохраняет получившийся конфиг.
func showServerSetupDialog(a fyne.App) {
	win := a.NewWindow("Server Setup")

	// Поля ввода для параметров подключения и настроек.
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
		// Получаем значения из полей.
		ip := strings.TrimSpace(ipEntry.Text)
		pass := strings.TrimSpace(passEntry.Text)
		sshPort := strings.TrimSpace(sshPortEntry.Text)
		userPort := strings.TrimSpace(userPortEntry.Text)
		serverNames := strings.TrimSpace(serverNamesEntry.Text)
		fileName := strings.TrimSpace(fileNameEntry.Text)

		if ip == "" || pass == "" || userPort == "" || serverNames == "" || fileName == "" {
			win.SetContent(container.NewVBox(
				form,
				widget.NewLabel("Пожалуйста, заполните все обязательные поля."),
			))
			return
		}

		// Формируем аргументы для запуска внешнего скрипта.
		// Локальная папка передаётся как "profiles", куда скрипт сохранит config.json
		args := []string{
			"-ip", ip,
			"-p", pass,
			"--port", sshPort,
			"-uport", userPort,
			"-s", serverNames,
			"-l", "profiles",
			"-f", fileName,
		}

		// Создаем окно для отображения хода выполнения.
		progressWin := a.NewWindow("Server Setup Progress")
		progressText := widget.NewMultiLineEntry()
		progressText.Wrapping = fyne.TextWrapWord
		progressText.SetText("Запуск процесса...\n")
		progressWin.SetContent(container.NewScroll(progressText))
		progressWin.Resize(fyne.NewSize(500, 400))
		progressWin.Show()

		// Запускаем внешний исполняемый файл server_setup (scripts/script).
		cmd := exec.Command("scripts/script", args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

		stdoutPipe, err := cmd.StdoutPipe()
		if err != nil {
			progressText.SetText(progressText.Text + fmt.Sprintf("Ошибка получения stdout: %v\n", err))
			return
		}
		stderrPipe, err := cmd.StderrPipe()
		if err != nil {
			progressText.SetText(progressText.Text + fmt.Sprintf("Ошибка получения stderr: %v\n", err))
			return
		}

		if err := cmd.Start(); err != nil {
			progressText.SetText(progressText.Text + fmt.Sprintf("Ошибка запуска server setup: %v\n", err))
			return
		}

		// Чтение stdout (построчно)
		go func() {
			reader := bufio.NewReader(stdoutPipe)
			for {
				line, err := reader.ReadString('\n')
				if len(line) > 0 {
					progressText.SetText(progressText.Text + line)
				}
				if err != nil {
					break
				}
			}
		}()

		// Чтение stderr (построчно)
		go func() {
			reader := bufio.NewReader(stderrPipe)
			for {
				line, err := reader.ReadString('\n')
				if len(line) > 0 {
					progressText.SetText(progressText.Text + "ERROR: " + line)
				}
				if err != nil {
					break
				}
			}
		}()

		// Ожидание завершения процесса в отдельной горутине.
		go func() {
			err := cmd.Wait()
			if err != nil {
				progressText.SetText(progressText.Text + fmt.Sprintf("\nПроцесс завершился с ошибкой: %v\n", err))
			} else {
				progressText.SetText(progressText.Text + "\nПроцесс завершился успешно.\n")
			}
		}()

		win.Close()
		// Обновляем список профилей.
		mainContent.Objects = []fyne.CanvasObject{createProfilesList()}
		mainContent.Refresh()
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

// runConfig запускает proxy-core с указанным конфигом.
// Если уже запущен процесс, он будет остановлен перед запуском нового.
func runConfig(configPath string) {
	// Завершаем любой ранее запущенный процесс.
	stopConfig()

	if err := settings.EnableSystemProxy(); err != nil {
		fmt.Println("Error enabling system proxy:", err)
		return
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

// stopConfig останавливает процесс proxy-core и отключает системный прокси.
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
	// Дожидаемся завершения процесса.
	if err := cmd.Wait(); err != nil {
		fmt.Println("Error waiting for process exit:", err)
	} else {
		fmt.Println("Process exited successfully.")
	}

	cmdMutex.Lock()
	currentCmd = nil
	currentConfig = ""
	cmdMutex.Unlock()

	if err := settings.DisableSystemProxy(); err != nil {
		fmt.Println("Error disabling system proxy:", err)
	}
	fmt.Println("Stopped proxy-core")
}

// showCreateConfigDialog открывает окно для создания нового конфига.
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

	flowSelect := widget.NewSelect(
		[]string{"xtls-rprx-vision", "xtls-rprx-splice", "xtls-rprx-origin"},
		func(string) {},
	)
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

	cancelBtn := widget.NewButton("Cancel", func() {
		newWin.Close()
	})

	buttons := container.NewHBox(layout.NewSpacer(), okBtn, cancelBtn)
	dialogContent := container.NewBorder(nil, buttons, nil, nil, form)

	newWin.SetContent(dialogContent)
	newWin.Resize(fyne.NewSize(500, 550))
	newWin.Show()
}

// showUpdateConfigDialog открывает окно для обновления существующего конфига.
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
	flowSelect := widget.NewSelect(
		[]string{"xtls-rprx-vision", "xtls-rprx-splice", "xtls-rprx-origin"},
		func(string) {},
	)
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
				Type: "mixed", Tag: "mixed-in", Listen: "127.0.0.1", Listen_port: 2080,
				Sniff: true, Sniff_override_destination: true,
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

	cancelBtn := widget.NewButton("Cancel", func() {
		newWin.Close()
	})

	buttons := container.NewHBox(layout.NewSpacer(), okBtn, cancelBtn)
	dialogContent := container.NewBorder(nil, buttons, nil, nil, form)
	newWin.SetContent(dialogContent)
	newWin.Resize(fyne.NewSize(500, 550))
	newWin.Show()
}

// buildConfigFromForm создаёт новый Config на основе введённых данных.
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

// saveConfig сохраняет Config под именем cfgName (без .json) в папку profiles.
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

// parseUint преобразует строку в uint.
func parseUint(s string) uint {
	var val uint
	_, err := fmt.Sscanf(s, "%d", &val)
	if err != nil {
		fmt.Println("Error parsing uint:", err)
		return 0
	}
	return val
}
