.PHONY: all build build-main build-proxy-core build-scripts clean

BUILD_DIR := builds
APP_NAME := vpnui.exe
PROXY_CORE_NAME := proxy-core.exe
PROXY_CORE_DIR := proxy-core
SCRIPT_NAME := scripts/client_script.py
# Имя exe-файла для скрипта (замените, если нужно)
SCRIPT_EXE := script.exe

all: build

build: build-main build-proxy-core build-scripts
	@echo "Copy $(PROXY_CORE_NAME) в $(BUILD_DIR)..."
	copy /Y $(PROXY_CORE_DIR)\$(PROXY_CORE_NAME) $(BUILD_DIR)\$(PROXY_CORE_NAME)

build-main:
	@echo "Build main application (Release)..."
	if not exist $(BUILD_DIR) mkdir $(BUILD_DIR)
	go build -ldflags="-s -w -H=windowsgui" -o $(BUILD_DIR)\$(APP_NAME) .

build-proxy-core:
	@echo "Build proxy core..."
	rem Если proxy-core.exe существует в каталоге $(PROXY_CORE_DIR), копируем его в текущий каталог
	if exist "$(PROXY_CORE_DIR)\$(PROXY_CORE_NAME)" ( \
		copy /Y "$(PROXY_CORE_DIR)\$(PROXY_CORE_NAME)" . \
	) else ( \
		echo "Ошибка: $(PROXY_CORE_NAME) не найден в $(PROXY_CORE_DIR)" \
	)

build-scripts:
	@echo "Compile Python-script in exe..."
	if not exist $(BUILD_DIR)\scripts mkdir $(BUILD_DIR)\scripts
	pyinstaller --onefile --name $(SCRIPT_EXE:.exe=) --distpath $(BUILD_DIR)\scripts --workpath build\pyinstaller_temp --specpath build\pyinstaller_temp $(SCRIPT_NAME)

clean:
	if exist $(BUILD_DIR) rd /S /Q $(BUILD_DIR)
	del /Q $(APP_NAME)
	del /Q $(PROXY_CORE_NAME)
	if exist build\pyinstaller_temp rd /S /Q build\pyinstaller_temp
	if exist __pycache__ rd /S /Q __pycache__
