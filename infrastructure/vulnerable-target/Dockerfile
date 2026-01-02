# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Vulnerable Target for E2E Testing
# A deliberately vulnerable Ubuntu container for penetration testing
# ═══════════════════════════════════════════════════════════════
#
# ⚠️  WARNING: This container is INTENTIONALLY INSECURE!
# ⚠️  DO NOT expose to untrusted networks!
# ⚠️  FOR TESTING PURPOSES ONLY!
#
# Features:
# - SSH with weak password authentication
# - Simple HTTP server with exposed info
# - Deliberately misconfigured services
# ═══════════════════════════════════════════════════════════════

FROM ubuntu:22.04

LABEL maintainer="RAGLOX Team"
LABEL description="Vulnerable target for E2E testing"
LABEL version="1.0"

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# ═══════════════════════════════════════════════════════════════
# Install required packages
# ═══════════════════════════════════════════════════════════════
RUN apt-get update && apt-get install -y \
    openssh-server \
    nginx \
    python3 \
    python3-pip \
    curl \
    wget \
    net-tools \
    iputils-ping \
    vim \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# ═══════════════════════════════════════════════════════════════
# Configure SSH Server (Deliberately Weak)
# ═══════════════════════════════════════════════════════════════
RUN mkdir /var/run/sshd

# Enable password authentication (insecure for testing)
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Create vulnerable users with weak passwords
# User 1: testuser:password123 (standard user)
RUN useradd -m -s /bin/bash testuser && \
    echo 'testuser:password123' | chpasswd

# User 2: admin:admin123 (admin user with sudo)
RUN useradd -m -s /bin/bash admin && \
    echo 'admin:admin123' | chpasswd && \
    usermod -aG sudo admin

# User 3: backup:backup (weak service account)
RUN useradd -m -s /bin/bash backup && \
    echo 'backup:backup' | chpasswd

# Set root password (very weak for testing)
RUN echo 'root:toor' | chpasswd

# ═══════════════════════════════════════════════════════════════
# Configure Nginx (Simple Web Server)
# ═══════════════════════════════════════════════════════════════
COPY nginx-default.conf /etc/nginx/sites-available/default
COPY index.html /var/www/html/index.html

# Create some "interesting" files for discovery
RUN mkdir -p /var/www/html/admin /var/www/html/backup
COPY admin.html /var/www/html/admin/index.html
RUN echo "backup_password=secret123" > /var/www/html/backup/config.bak

# ═══════════════════════════════════════════════════════════════
# Create vulnerable files and configurations
# ═══════════════════════════════════════════════════════════════

# Fake credentials file (for credential harvesting tests)
RUN mkdir -p /home/testuser/.ssh /home/admin/.ssh
RUN echo "# Database credentials (DO NOT SHARE)" > /home/testuser/.db_creds && \
    echo "DB_USER=dbadmin" >> /home/testuser/.db_creds && \
    echo "DB_PASS=super_secret_db_password" >> /home/testuser/.db_creds

# Fake SSH key (for lateral movement tests)
RUN echo "-----BEGIN FAKE PRIVATE KEY-----" > /home/admin/.ssh/id_rsa_backup && \
    echo "This is a fake key for testing" >> /home/admin/.ssh/id_rsa_backup && \
    echo "-----END FAKE PRIVATE KEY-----" >> /home/admin/.ssh/id_rsa_backup

# History file with "sensitive" commands
RUN echo "mysql -u root -p'db_root_password'" > /home/testuser/.bash_history && \
    echo "scp backup@192.168.1.100:/data/secrets.tar.gz ." >> /home/testuser/.bash_history

# Set permissions
RUN chown -R testuser:testuser /home/testuser
RUN chown -R admin:admin /home/admin

# ═══════════════════════════════════════════════════════════════
# Create system info script (for enumeration)
# ═══════════════════════════════════════════════════════════════
RUN echo '#!/bin/bash' > /usr/local/bin/system-info && \
    echo 'echo "=== System Information ==="' >> /usr/local/bin/system-info && \
    echo 'echo "Hostname: $(hostname)"' >> /usr/local/bin/system-info && \
    echo 'echo "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2)"' >> /usr/local/bin/system-info && \
    echo 'echo "Kernel: $(uname -r)"' >> /usr/local/bin/system-info && \
    echo 'echo "Users: $(cat /etc/passwd | grep bash | cut -d: -f1 | tr "\n" " ")"' >> /usr/local/bin/system-info && \
    chmod +x /usr/local/bin/system-info

# ═══════════════════════════════════════════════════════════════
# Startup script
# ═══════════════════════════════════════════════════════════════
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Expose ports
EXPOSE 22 80

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost/ && ssh-keygen -F localhost || exit 1

ENTRYPOINT ["/entrypoint.sh"]
