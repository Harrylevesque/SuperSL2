#!/usr/bin/env bash
set -e

APP="samfpy-server"
DIR="$HOME/$APP"

echo "Stopping and disabling $APP service..."
if systemctl list-units --full -all | grep -q "$APP.service"; then
    sudo systemctl stop $APP
    sudo systemctl disable $APP
    sudo rm -f /etc/systemd/system/$APP.service
    sudo systemctl daemon-reload
    echo "Service $APP removed."
else
    echo "Service $APP not found, skipping."
fi

echo "Removing application directory at $DIR..."
if [ -d "$DIR" ]; then
    rm -rf "$DIR"
    echo "Directory removed."
else
    echo "Directory $DIR not found, skipping."
fi

echo ""
echo "$APP has been successfully uninstalled."