import argparse
import paramiko
import json
import os

# Функция выполнения команды на сервере
def run_remote_command(command, client):
    stdin, stdout, stderr = client.exec_command(command, get_pty=True)
    output = stdout.read().decode().strip()
    error = stderr.read().decode().strip()

    if error:
        print(f"Ошибка при выполнении {command}: {error}")
        return None
    return output

# Функция подключения к серверу
def connect_to_server(hostname, port, username, password):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname, port=int(port), username=username, password=password)
        print(f"Подключено к серверу {hostname}.")
        return client
    except Exception as e:
        print(f"Ошибка подключения: {e}")
        return None

# Функция создания конфига для сервера
def create_server_config(client, user_port, server_names):
    uuid = run_remote_command("/usr/local/bin/xray uuid", client)
    short_id = run_remote_command("openssl rand -hex 8", client)
    x25519_keys = run_remote_command("/usr/local/bin/xray x25519", client)

    if not all([uuid, short_id, x25519_keys]):
        print("Ошибка: не удалось получить все необходимые данные с сервера.")
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

        print(f"Конфигурация успешно загружена на сервер и сохранена в {remote_config_path}")
        print("UUID:", uuid)
        print("Private Key:", private_key)
        print("Short ID:", short_id)
        print("Dest:", dest)
        print("Public Key:", public_key)

    except Exception as e:
        print(f"Ошибка загрузки конфига на сервер: {e}")

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

# Функция сохранения клиентского конфига с выбором имени файла
def save_client_config(local_folder, client_config, filename):
    if not os.path.exists(local_folder):
        try:
            os.makedirs(local_folder)
            print(f"Папка {local_folder} создана.")
        except Exception as e:
            print(f"Ошибка при создании папки: {e}")
            return

    # Если имя файла не оканчивается на .json, добавляем расширение
    if not filename.endswith(".json"):
        filename += ".json"
    local_config_path = os.path.join(local_folder, filename)

    try:
        with open(local_config_path, "w") as file:
            json.dump(client_config, file, indent=2)
        print(f"Файл конфигурации сохранен: {local_config_path}")
    except Exception as e:
        print(f"Ошибка при сохранении файла: {e}")

def main():
    parser = argparse.ArgumentParser(description="Утилита для настройки Xray на сервере")
    parser.add_argument("-ip", "--ipaddress", required=True, help="IP-адрес сервера")
    parser.add_argument("-p", "--password", required=True, help="Пароль для сервера")
    parser.add_argument("--port", default=22, help="SSH порт сервера (по умолчанию 22)")
    parser.add_argument("-uport", "--user_port", required=True, help="Порт для создания конфигурации на сервере")
    parser.add_argument("-s", "--server_names", required=True, help="Список serverNames через запятую (например, www.example.com,www.google.com)")
    parser.add_argument("-l", "--local_folder", required=True, help="Путь к папке для сохранения client config")
    parser.add_argument("-f", "--filename", required=True, help="Имя файла для сохранения client config (без расширения)")
    
    args = parser.parse_args()

    hostname = args.ipaddress
    port = args.port
    username = "root"
    password = args.password

    client = connect_to_server(hostname, port, username, password)
    if not client:
        return

    # Выполняем необходимые команды перед начальной настройкой
    print("Выполняется команда: sudo apt-get update")
    update_output = run_remote_command("sudo apt-get update", client)
    if update_output is not None:
        print("apt-get update выполнена успешно.")
    else:
        print("Ошибка при выполнении apt-get update.")

    install_command = 'bash -c "$(curl -L https://raw.githubusercontent.com/XTLS/Xray-install/046d9aa2432b3a6241d73c3684ef4e512974b594/install-release.sh)" @ install --version 1.8.24'
    print("Выполняется установка Xray через инсталляционный скрипт...")
    install_output = run_remote_command(install_command, client)
    if install_output is not None:
        print("Скрипт установки Xray выполнен успешно.")
    else:
        print("Ошибка при выполнении скрипта установки Xray.")

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
