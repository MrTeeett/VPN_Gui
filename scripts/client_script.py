import argparse
import paramiko
import json
import os
import select
import time
import re  # для работы с регулярными выражениями

def run_remote_command(command, client, timeout=2000):
	stdin, stdout, stderr = client.exec_command(command, get_pty=True)
	out_lines = []
	err_lines = []
	start_time = time.time()

	while True:
		# Используем select для ожидания данных в stdout или stderr с таймаутом
		if stdout.channel.exit_status_ready() and not stdout.channel.recv_ready() and not stderr.channel.recv_stderr_ready():
			break

		r, _, _ = select.select([stdout.channel], [], [], 1)
		if r:
			output = stdout.channel.recv(1024).decode("utf-8")
			if output:
				print(output, end="")
				out_lines.append(output)
				start_time = time.time()  # сброс таймаута при получении данных
		else:
			# Если данные не получены, проверяем таймаут
			if time.time() - start_time > timeout:
				print("\nTimeout reached, assuming command completed.")
				break

	remaining_output = ""
	while stdout.channel.recv_ready():
		chunk = stdout.channel.recv(1024).decode("utf-8")
		if not chunk:
			break
		remaining_output += chunk

	remaining_error = ""
	while stderr.channel.recv_stderr_ready():
		chunk = stderr.channel.recv_stderr(1024).decode("utf-8")
		if not chunk:
			break
		remaining_error += chunk

	if remaining_output:
		print(remaining_output, end="")
		out_lines.append(remaining_output)
	if remaining_error:
		print(remaining_error, end="")
		err_lines.append(remaining_error)

	return "".join(out_lines).strip() if out_lines else None

# Функция подключения к серверу
def connect_to_server(hostname, port, username, password):
	try:
		client = paramiko.SSHClient()
		client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		client.connect(hostname, port=int(port), username=username, password=password)
		print(f"Connected to server {hostname}.")
		return client
	except Exception as e:
		print(f"Connection error: {e}")
		return None

# Функция создания конфига для сервера
def create_server_config(client, user_port, server_names):
	uuid = run_remote_command("/usr/local/bin/xray uuid", client)
	short_id = run_remote_command("openssl rand -hex 8", client)
	x25519_keys = run_remote_command("/usr/local/bin/xray x25519", client)

	if not all([uuid, short_id, x25519_keys]):
		print("Error: Failed to obtain all necessary data from the server.")
		return None

	private_key, public_key = "", ""
	for line in x25519_keys.split("\n"):
		if "Private" in line:
			private_key = line.split(":")[-1].strip()
		if "Public" in line:
			public_key = line.split(":")[-1].strip()

	dest = f"{server_names.split(',')[0]}:{user_port}"

	return {
		"log": {"loglevel": "info"},
		"routing": {"rules": [], "domainStrategy": "AsIs"},
		"inbounds": [
			{
				"port": 23,
				"tag": "ss",
				"protocol": "shadowsocks",
				"settings": {
					"method": "2022-blake3-aes-128-gcm",
					"password": "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb",
					"network": "tcp,udp"
				}
			},
			{
				"port": int(user_port),
				"protocol": "vless",
				"tag": "vless_tls",
				"settings": {
					"clients": [{"id": uuid, "email": "user1@myserver", "flow": "xtls-rprx-vision"}],
					"decryption": "none"
				},
				"streamSettings": {
					"network": "tcp",
					"security": "reality",
					"realitySettings": {
						"show": False,
						"dest": dest,
						"xver": 0,
						"serverNames": server_names.split(','),
						"privateKey": private_key,
						"minClientVer": "",
						"maxClientVer": "",
						"maxTimeDiff": 0,
						"shortIds": [short_id]
					}
				},
				"sniffing": {"enabled": True, "destOverride": ["http", "tls"]}
			}
		],
		"outbounds": [
			{"protocol": "freedom", "tag": "direct"},
			{"protocol": "blackhole", "tag": "block"}
		]
	}, uuid, private_key, short_id, dest, public_key

# Функция загрузки конфига на сервер
def upload_config_to_server(client, server_config, uuid, private_key, short_id, dest, public_key):
	try:
		remote_config_path = "/usr/local/etc/xray/config.json"
		sftp = client.open_sftp()
		with sftp.file(remote_config_path, "w") as remote_file:
			remote_file.write(json.dumps(server_config, indent=2))
		sftp.close()
		run_remote_command("systemctl restart xray", client)

		print(f"Configuration successfully uploaded to the server and saved at {remote_config_path}")
		print("UUID:", uuid)
		print("Private Key:", private_key)
		print("Short ID:", short_id)
		print("Dest:", dest)
		print("Public Key:", public_key)

	except Exception as e:
		print(f"Error uploading config to server: {e}")

# Функция создания клиентского конфига
def create_client_config(hostname, server_names, uuid, public_key, short_id):
	return {
		"log": {"level": "info"},
		"inbounds": [
			{
				"type": "mixed",
				"tag": "mixed-in",
				"listen": "127.0.0.1",
				"listen_port": 2080,
				"tcp_fast_open": False,
				"sniff": True,
				"sniff_override_destination": True,
				"set_system_proxy": False
			}
		],
		"outbounds": [
			{
				"type": "vless",
				"tag": "vless-out",
				"server": hostname,
				"server_port": 443,
				"uuid": uuid,
				"flow": "xtls-rprx-vision",
				"network": "tcp",
				"tls": {
					"enabled": True,
					"server_name": server_names.split(',')[0],
					"alpn": ["h2"],
					"utls": {
						"enabled": True,
						"fingerprint": "chrome"
					},
					"reality": {
						"enabled": True,
						"public_key": public_key,
						"short_id": short_id
					}
				}
			}
		]
	}

# Функция сохранения клиентского конфига в файл с заданным именем
def save_client_config(local_folder, client_config, filename):
	if not os.path.exists(local_folder):
		try:
			os.makedirs(local_folder)
			print(f"Folder {local_folder} created.")
		except Exception as e:
			print(f"Error creating folder: {e}")
			return

	if not filename.endswith(".json"):
		filename += ".json"
	local_config_path = os.path.join(local_folder, filename)

	try:
		with open(local_config_path, "w") as file:
			json.dump(client_config, file, indent=2)
		print(f"Configuration file saved: {local_config_path}")
	except Exception as e:
		print(f"Error saving file: {e}")

def main():
	parser = argparse.ArgumentParser(description="Utility for configuring Xray on the server")
	parser.add_argument("-ip", "--ipaddress", required=True, help="Server IP address")
	parser.add_argument("-p", "--password", required=True, help="Server password")
	parser.add_argument("--port", default=22, help="Server SSH port (default 22)")
	parser.add_argument("-uport", "--user_port", required=True, help="Port for creating the server configuration")
	parser.add_argument("-s", "--server_names", required=True, help="Comma-separated list of serverNames (e.g., www.example.com,www.google.com)")
	parser.add_argument("-l", "--local_folder", required=True, help="Path to folder for saving the client config")
	parser.add_argument("-f", "--filename", required=True, help="Filename for saving the client config (without extension)")
	
	args = parser.parse_args()

	hostname = args.ipaddress
	port = args.port
	username = "root"
	password = args.password

	client = connect_to_server(hostname, port, username, password)
	if not client:
		return

	# Проверка установки Xray
	print("Checking Xray installation...")
	xray_check = run_remote_command("command -v xray", client)
	if xray_check:
		print("Xray is already installed, skipping installation.")
	else:
		print("Xray is not installed. Proceeding with installation...")
		print("Running command: apt upgrade")
		update_output = run_remote_command("apt upgrade -y", client)
		if update_output is not None:
			# Если в выводе присутствует сообщение об ожидании блокировки
			if "Waiting for cache lock:" in update_output:
				match = re.search(r"lock-frontend\. It is held by process (\d+)", update_output)
				if match:
					pid = match.group(1)
					print(f"Detected apt-get process with PID {pid}. Attempting to kill it...")
					kill_output = run_remote_command(f"sudo kill -9 {pid}", client)
					print("apt-get process killed.")
				else:
					print("Cache lock message detected, but failed to parse process ID.")
			else:
				print("apt upgrade executed successfully.")
		else:
			print("Error executing apt upgrade.")
		
		install_command = 'bash -c "$(curl -L https://raw.githubusercontent.com/XTLS/Xray-install/046d9aa2432b3a6241d73c3684ef4e512974b594/install-release.sh)" @ install --version 1.8.24'
		print("Installing Xray using the installation script...")
		install_output = run_remote_command(install_command, client)
		if install_output is not None:
			print("Xray installation script executed successfully.")
		else:
			print("Error executing Xray installation script.")

	user_port = args.user_port
	server_names = args.server_names

	result = create_server_config(client, user_port, server_names)
	if not result:
		client.close()
		return

	server_config, uuid, private_key, short_id, dest, public_key = result
	upload_config_to_server(client, server_config, uuid, private_key, short_id, dest, public_key)

	client_config = create_client_config(hostname, server_names, uuid, public_key, short_id)
	save_client_config(args.local_folder, client_config, args.filename)

	client.close()

if __name__ == "__main__":
	main()
