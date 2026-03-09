#!/usr/bin/env bash
set -e

clear

cat << "EOF"




  █████████    █████████   ██████   ██████ ███████████                              ███  █████████                                                    ███
 ███░░░░░███  ███░░░░░███ ░░██████ ██████ ░░███░░░░░░█                             ███  ███░░░░░███                                                  ░░███
░███    ░░░  ░███    ░███  ░███░█████░███  ░███   █ ░     ████████  █████ ████    ███  ░███    ░░░   ██████  ████████  █████ █████  ██████  ████████  ░░███
░░█████████  ░███████████  ░███░░███ ░███  ░███████      ░░███░░███░░███ ░███    ░███  ░░█████████  ███░░███░░███░░███░░███ ░░███  ███░░███░░███░░███  ░███
 ░░░░░░░░███ ░███░░░░░███  ░███ ░░░  ░███  ░███░░░█       ░███ ░███ ░███ ░███    ░███   ░░░░░░░░███░███████  ░███ ░░░  ░███  ░███ ░███████  ░███ ░░░   ░███
 ███    ░███ ░███    ░███  ░███      ░███  ░███  ░        ░███ ░███ ░███ ░███    ░░███  ███    ░███░███░░░   ░███      ░░███ ███  ░███░░░   ░███       ███
░░█████████  █████   █████ █████     █████ █████       ██ ░███████  ░░███████     ░░███░░█████████ ░░██████  █████      ░░█████   ░░██████  █████     ██░
 ░░░░░░░░░  ░░░░░   ░░░░░ ░░░░░     ░░░░░ ░░░░░       ░░  ░███░░░    ░░░░░███      ░░░  ░░░░░░░░░   ░░░░░░  ░░░░░        ░░░░░     ░░░░░░  ░░░░░     ░░░
                                                          ░███       ███ ░███
                                                          █████     ░░██████
                                                         ░░░░░       ░░░░░░




EOF

APP="samfpy-server"
REPO="https://github.com/Harrylevesque/SAMFpy-Server.git"
BRANCH="main"
DIR="$HOME/$APP"
PORT=8189

echo "Installing dependencies..."

if command -v apt >/dev/null; then
    sudo apt update
    sudo apt install -y git python3 python3-venv python3-pip
elif command -v dnf >/dev/null; then
    sudo dnf install -y git python3 python3-pip
elif command -v pacman >/dev/null; then
    sudo pacman -Sy git python python-pip
else
    echo "Unsupported package manager"
    exit 1
fi

echo "Cloning SAMFpy Server..."

if [ ! -d "$DIR" ]; then
    git clone -b "$BRANCH" "$REPO" "$DIR"
fi

cd "$DIR"

echo "Creating Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt

echo "Creating runner script run.sh..."

cat <<EOL > run.sh
#!/usr/bin/env bash

cd "$DIR"

echo "Updating SAMFpy..."
git pull

source venv/bin/activate
pip install -r requirements.txt --upgrade

echo "Starting SAMFpy Server..."
exec uvicorn main:app --host 0.0.0.0 --port $PORT
EOL

chmod +x run.sh

echo "Creating systemd service..."

sudo tee /etc/systemd/system/$APP.service > /dev/null <<EOL
[Unit]
Description=SAMFpy Server
After=network.target

[Service]
User=$USER
WorkingDirectory=$DIR
ExecStart=$DIR/run.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOL

sudo systemctl daemon-reload
sudo systemctl enable $APP
sudo systemctl restart $APP

echo ""
echo "SAMFpy Server installed successfully!"
echo "Server running on port $PORT"
echo ""
echo "Check status with:"
echo "sudo systemctl status $APP"