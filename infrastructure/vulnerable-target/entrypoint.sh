#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Vulnerable Target Entrypoint
# ═══════════════════════════════════════════════════════════════

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║           RAGLOX v3.0 - Vulnerable Target                      ║"
echo "║         ⚠️  FOR TESTING PURPOSES ONLY! ⚠️                      ║"
echo "╚═══════════════════════════════════════════════════════════════╝"

# Generate SSH host keys if not exist
if [ ! -f /etc/ssh/ssh_host_rsa_key ]; then
    echo "[*] Generating SSH host keys..."
    ssh-keygen -A
fi

# Start SSH server
echo "[*] Starting SSH server on port 22..."
/usr/sbin/sshd

# Start Nginx
echo "[*] Starting Nginx on port 80..."
nginx

echo "[+] Services started successfully!"
echo "[+] Available users:"
echo "    - testuser:password123 (standard user)"
echo "    - admin:admin123 (sudo user)"
echo "    - backup:backup (service account)"
echo "    - root:toor (root access)"
echo ""
echo "[+] Container is ready for testing!"

# Keep container running
tail -f /var/log/nginx/access.log /var/log/nginx/error.log
