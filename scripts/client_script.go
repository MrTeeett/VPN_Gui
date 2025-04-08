package scripts

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// ServerConfig описывает конфигурацию для xray.
type ServerConfig struct {
	Log       map[string]string        `json:"log"`
	Routing   map[string]interface{}   `json:"routing"`
	Inbounds  []map[string]interface{} `json:"inbounds"`
	Outbounds []map[string]interface{} `json:"outbounds"`
}

// runRemoteCommand выполняет команду на сервере с заданным таймаутом через pty.
func runRemoteCommand(client *ssh.Client, command string, timeout time.Duration) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	if err := session.RequestPty("xterm", 80, 40, ssh.TerminalModes{}); err != nil {
		return "", err
	}

	var outputBuf bytes.Buffer
	session.Stdout = &outputBuf
	session.Stderr = &outputBuf

	if err := session.Start(command); err != nil {
		return "", err
	}

	done := make(chan error, 1)
	go func() {
		done <- session.Wait()
	}()

	select {
	case err := <-done:
		return outputBuf.String(), err
	case <-time.After(timeout):
		_ = session.Signal(ssh.SIGKILL)
		return outputBuf.String() + "\nTimeout reached, assuming command completed.", nil
	}
}

// ConnectToServer устанавливает SSH-соединение.
func ConnectToServer(host string, port int, username, password string) (*ssh.Client, error) {
	config := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, err
	}
	fmt.Printf("Connected to server %s.\n", host)
	return client, nil
}

// runRemoteCommandNoPTY выполняет команду без выделения pty.
func runRemoteCommandNoPTY(client *ssh.Client, command string, timeout time.Duration) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	output, err := session.CombinedOutput(command)
	return string(output), err
}

// runRemoteCommandStream выполняет команду и передаёт потоковый вывод через logFunc.
func runRemoteCommandStream(client *ssh.Client, command string, timeout time.Duration, logFunc func(string)) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	if err := session.RequestPty("xterm", 80, 40, ssh.TerminalModes{}); err != nil {
		return "", err
	}

	stdoutPipe, err := session.StdoutPipe()
	if err != nil {
		return "", err
	}
	stderrPipe, err := session.StderrPipe()
	if err != nil {
		return "", err
	}

	if err := session.Start(command); err != nil {
		return "", err
	}

	outputBuf := new(bytes.Buffer)
	done := make(chan error, 1)

	go func() {
		multiR := io.MultiReader(stdoutPipe, stderrPipe)
		scanner := bufio.NewScanner(multiR)
		for scanner.Scan() {
			line := scanner.Text() + "\n"
			outputBuf.WriteString(line)
			if logFunc != nil {
				logFunc(line)
			}
		}
		done <- session.Wait()
	}()

	select {
	case err := <-done:
		return outputBuf.String(), err
	case <-time.After(timeout):
		_ = session.Signal(ssh.SIGKILL)
		return outputBuf.String() + "\nTimeout reached, assuming command completed.", nil
	}
}

// detectOS определяет тип операционной системы, выполняя "cat /etc/os-release".
func detectOS(client *ssh.Client, timeout time.Duration) (string, error) {
	output, err := runRemoteCommandNoPTY(client, "cat /etc/os-release", timeout)
	if err != nil {
		return "", err
	}
	// Если присутствует ID=arch - Arch Linux
	if strings.Contains(output, "ID=arch") {
		return "arch", nil
	}
	// Если присутствует ID=debian или ID=ubuntu - считаем это debian-подобной системой
	if strings.Contains(output, "ID=debian") || strings.Contains(output, "ID=ubuntu") {
		return "debian", nil
	}
	return "unknown", nil
}

// createServerConfig получает данные с сервера и формирует конфигурацию.
func createServerConfig(client *ssh.Client, userPort string, serverNames string) (ServerConfig, string, string, string, string, string, error) {
	timeout := 2 * time.Second

	uuid, err := runRemoteCommandNoPTY(client, "/usr/local/bin/xray uuid", timeout)
	if err != nil || strings.TrimSpace(uuid) == "" {
		return ServerConfig{}, "", "", "", "", "", fmt.Errorf("failed to obtain uuid")
	}
	uuid = strings.TrimSpace(uuid)

	shortID, err := runRemoteCommandNoPTY(client, "openssl rand -hex 8", timeout)
	if err != nil || strings.TrimSpace(shortID) == "" {
		return ServerConfig{}, "", "", "", "", "", fmt.Errorf("failed to obtain shortID")
	}
	shortID = strings.TrimSpace(shortID)

	x25519Keys, err := runRemoteCommandNoPTY(client, "/usr/local/bin/xray x25519", timeout)
	if err != nil || strings.TrimSpace(x25519Keys) == "" {
		return ServerConfig{}, "", "", "", "", "", fmt.Errorf("failed to obtain x25519 keys")
	}

	var privateKey, publicKey string
	scanner := bufio.NewScanner(strings.NewReader(x25519Keys))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Private") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				privateKey = strings.TrimSpace(parts[len(parts)-1])
			}
		}
		if strings.Contains(line, "Public") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				publicKey = strings.TrimSpace(parts[len(parts)-1])
			}
		}
	}
	if privateKey == "" || publicKey == "" {
		return ServerConfig{}, "", "", "", "", "", fmt.Errorf("failed to parse x25519 keys")
	}

	dest := fmt.Sprintf("%s:%s", strings.Split(serverNames, ",")[0], userPort)

	serverConfig := ServerConfig{
		Log: map[string]string{
			"loglevel": "info",
		},
		Routing: map[string]interface{}{
			"rules":          []interface{}{},
			"domainStrategy": "AsIs",
		},
		Inbounds: []map[string]interface{}{
			{
				"port":     23,
				"tag":      "ss",
				"protocol": "shadowsocks",
				"settings": map[string]interface{}{
					"method":   "2022-blake3-aes-128-gcm",
					"password": "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb",
					"network":  "tcp,udp",
				},
			},
			{
				"port":     stringToInt(userPort),
				"protocol": "vless",
				"tag":      "vless_tls",
				"settings": map[string]interface{}{
					"clients": []map[string]interface{}{
						{
							"id":    uuid,
							"email": "user1@myserver",
							"flow":  "xtls-rprx-vision",
						},
					},
					"decryption": "none",
				},
				"streamSettings": map[string]interface{}{
					"network":  "tcp",
					"security": "reality",
					"realitySettings": map[string]interface{}{
						"show":         false,
						"dest":         dest,
						"xver":         0,
						"serverNames":  strings.Split(serverNames, ","),
						"privateKey":   privateKey,
						"minClientVer": "",
						"maxClientVer": "",
						"maxTimeDiff":  0,
						"shortIds":     []string{shortID},
					},
				},
				"sniffing": map[string]interface{}{
					"enabled":      true,
					"destOverride": []string{"http", "tls"},
				},
			},
		},
		Outbounds: []map[string]interface{}{
			{
				"protocol": "freedom",
				"tag":      "direct",
			},
			{
				"protocol": "blackhole",
				"tag":      "block",
			},
		},
	}
	return serverConfig, uuid, privateKey, shortID, dest, publicKey, nil
}

func stringToInt(s string) int {
	i, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return i
}

// uploadConfigToServer загружает конфигурацию на сервер и перезапускает сервис.
func uploadConfigToServer(client *ssh.Client, serverConfig ServerConfig, uuid, privateKey, shortID, dest, publicKey string) error {
	configJSON, err := json.MarshalIndent(serverConfig, "", "  ")
	if err != nil {
		return err
	}
	remotePath := "/usr/local/etc/xray/config.json"

	// Передадим конфиг через временный файл.
	tmpFile := "temp_config.json"
	if err := os.WriteFile(tmpFile, configJSON, 0644); err != nil {
		return err
	}
	defer os.Remove(tmpFile)

	scpCmd := fmt.Sprintf("cat > %s", remotePath)
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	fileContent, err := os.ReadFile(tmpFile)
	if err != nil {
		return err
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		return err
	}
	go func() {
		defer stdin.Close()
		io.Copy(stdin, bytes.NewReader(fileContent))
	}()

	if err := session.Run(scpCmd); err != nil {
		return err
	}
	_, err = runRemoteCommand(client, "systemctl restart xray", 2*time.Second)
	if err != nil {
		return err
	}
	fmt.Printf("Configuration successfully uploaded to %s\n", remotePath)
	fmt.Printf("UUID: %s\nPrivate Key: %s\nShort ID: %s\nDest: %s\nPublic Key: %s\n", uuid, privateKey, shortID, dest, publicKey)
	return nil
}

// createClientConfig формирует клиентскую конфигурацию в виде map.
func createClientConfig(hostname, serverNames, uuid, publicKey, shortID string) map[string]interface{} {
	return map[string]interface{}{
		"log": map[string]interface{}{
			"level": "info",
		},
		"inbounds": []map[string]interface{}{
			{
				"type":                       "mixed",
				"tag":                        "mixed-in",
				"listen":                     "127.0.0.1",
				"listen_port":                2080,
				"tcp_fast_open":              false,
				"sniff":                      true,
				"sniff_override_destination": true,
				"set_system_proxy":           false,
			},
		},
		"outbounds": []map[string]interface{}{
			{
				"type":        "vless",
				"tag":         "vless-out",
				"server":      hostname,
				"server_port": 443,
				"uuid":        uuid,
				"flow":        "xtls-rprx-vision",
				"network":     "tcp",
				"tls": map[string]interface{}{
					"enabled":     true,
					"server_name": strings.Split(serverNames, ",")[0],
					"alpn":        []string{"h2"},
					"utls": map[string]interface{}{
						"enabled":     true,
						"fingerprint": "chrome",
					},
					"reality": map[string]interface{}{
						"enabled":    true,
						"public_key": publicKey,
						"short_id":   shortID,
					},
				},
			},
		},
	}
}

// saveClientConfig сохраняет клиентский конфиг в указанный файл.
func saveClientConfig(localFolder string, clientConfig map[string]interface{}, filename string) error {
	if _, err := os.Stat(localFolder); os.IsNotExist(err) {
		if err := os.MkdirAll(localFolder, 0755); err != nil {
			return fmt.Errorf("Error creating folder: %v", err)
		}
		fmt.Printf("Folder %s created.\n", localFolder)
	}
	if !strings.HasSuffix(filename, ".json") {
		filename += ".json"
	}
	localConfigPath := localFolder + "/" + filename
	configJSON, err := json.MarshalIndent(clientConfig, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(localConfigPath, configJSON, 0644); err != nil {
		return err
	}
	fmt.Printf("Configuration file saved: %s\n", localConfigPath)
	return nil
}

// checkXrayInstallation проверяет наличие xray на сервере.
func checkXrayInstallation(client *ssh.Client) bool {
	output, err := runRemoteCommand(client, "command -v xray", 2*time.Second)
	if err != nil {
		return false
	}
	return strings.TrimSpace(output) != ""
}

// installXray устанавливает xray, если он не установлен, с учетом типа системы.
func installXray(client *ssh.Client, osType string, logFunc func(string)) error {
	if osType == "arch" {
		logFunc("Running pacman update...\n")
		output, err := runRemoteCommandStream(client, "pacman -Syu --noconfirm", 60*time.Second, logFunc)
		if err != nil {
			logFunc("error executing pacman update.\n")
		} else {
			if strings.Contains(strings.ToLower(output), "error") || strings.Contains(strings.ToLower(output), "failed") {
				logFunc("pacman update completed with errors. Please resolve them manually.\n")
			} else {
				logFunc("pacman update executed successfully.\n")
			}
		}

		// Устанавливаем зависимости для xray
		logFunc("Installing dependencies (unzip, wget, ca-certificates)...\n")
		depCmd := "pacman -S --noconfirm unzip wget ca-certificates"
		depOut, depErr := runRemoteCommandStream(client, depCmd, 60*time.Second, logFunc)
		if depErr != nil {
			logFunc("error installing dependencies: " + depOut)
			return fmt.Errorf("error installing dependencies: %v", depErr)
		} else {
			logFunc("Dependencies installed successfully.\n")
		}
	} else {
		logFunc("Running apt upgrade...\n")
		output, err := runRemoteCommandStream(client, "apt upgrade -y", 60*time.Second, logFunc)
		if err == nil {
			if strings.Contains(output, "Waiting for cache lock:") {
				logFunc("cache lock detected. Please resolve the issue manually.\n")
			} else {
				logFunc("apt upgrade executed successfully.\n")
			}
		} else {
			logFunc("error executing apt upgrade.\n")
		}
	}

	installCommand := `bash -c "$(curl -L https://raw.githubusercontent.com/XTLS/Xray-install/046d9aa2432b3a6241d73c3684ef4e512974b594/install-release.sh)" @ install`
	logFunc("Installing Xray using the installation script...\n")
	installOutput, err := runRemoteCommandStream(client, installCommand, 120*time.Second, logFunc)
	if err != nil || strings.TrimSpace(installOutput) == "" {
		logFunc("error executing xray installation script\n")
		return fmt.Errorf("error executing xray installation script")
	}
	logFunc("Xray installation executed successfully.\n")
	return nil
}

// ServerSetup объединяет все шаги настройки сервера. Он автоматически определяет операционную систему.
func ServerSetup(ip, pass, sshPort, userPort, serverNames, localFolder, fileName string, logFunc func(string)) error {
	port, _ := strconv.Atoi(sshPort)
	client, err := ConnectToServer(ip, port, "root", pass)
	if err != nil {
		return fmt.Errorf("connection error: %v", err)
	}
	defer client.Close()
	logFunc("Connected to server.\n")

	// Автоматическое определение ОС
	logFunc("Detecting operating system...\n")
	osType, err := detectOS(client, 5*time.Second)
	if err != nil {
		logFunc("Error detecting OS, defaulting to debian.\n")
		osType = "debian"
	} else {
		logFunc(fmt.Sprintf("Detected OS: %s\n", osType))
	}

	logFunc("Checking Xray installation...\n")
	if checkXrayInstallation(client) {
		logFunc("Xray is already installed, skipping installation.\n")
	} else {
		logFunc("Xray is not installed. Installing...\n")
		if err := installXray(client, osType, logFunc); err != nil {
			return fmt.Errorf("installation error: %v", err)
		}
	}

	logFunc("Creating server configuration...\n")
	serverConfig, uuid, privateKey, shortID, dest, publicKey, err := createServerConfig(client, userPort, serverNames)
	if err != nil {
		return fmt.Errorf("error creating server config: %v", err)
	}

	logFunc("Uploading configuration to server...\n")
	if err := uploadConfigToServer(client, serverConfig, uuid, privateKey, shortID, dest, publicKey); err != nil {
		return fmt.Errorf("error uploading config: %v", err)
	}

	clientConfig := createClientConfig(ip, serverNames, uuid, publicKey, shortID)
	logFunc("Saving client configuration locally...\n")
	if err := saveClientConfig(localFolder, clientConfig, fileName); err != nil {
		return fmt.Errorf("error saving client config: %v", err)
	}
	logFunc("Server setup completed successfully.\n")
	return nil
}
