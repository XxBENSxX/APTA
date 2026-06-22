#!/bin/bash
set -e
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "  ================================="
echo "   APTA — Installation"
echo "  ================================="
echo -e "${NC}"

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR] Please run as root: sudo ./install.sh${NC}"
    exit 1
fi

echo -e "${YELLOW}[*] Updating packages...${NC}"
apt-get update -qq

echo -e "${YELLOW}[*] Installing system tools...${NC}"
apt-get install -y nmap nikto whatweb python3 python3-pip curl

echo -e "${YELLOW}[*] Installing Python dependencies...${NC}"
pip3 install -r requirements.txt --break-system-packages --quiet

mkdir -p reports cache

if [ ! -f .env ]; then
    cp .env.example .env
    echo -e "${YELLOW}[*] Created .env — add your Anthropic API key inside${NC}"
fi

chmod +x apta.py

echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  Installation complete!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo "  Next steps:"
echo "  1. nano .env  → add your API key"
echo "  2. python3 apta.py --target <IP>"
echo ""
echo -e "${RED}  Only scan systems you have permission to test.${NC}"
