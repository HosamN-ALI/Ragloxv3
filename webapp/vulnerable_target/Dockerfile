# ═══════════════════════════════════════════════════════════════════════════════
# RAGLOX Vulnerable Target - Red Team Testing Container
# ═══════════════════════════════════════════════════════════════════════════════
# This container is intentionally vulnerable for testing RAGLOX capabilities.
# DO NOT deploy in production!
#
# Included Vulnerabilities:
# - Web: SQLi, XSS, RCE, LFI, SSRF, XXE, Command Injection
# - System: SUID binaries, Weak permissions, Sudo misconfigs
# - Services: SSH with weak creds, Exposed MySQL, Redis noauth
# - Network: Open ports, Banner disclosure
# ═══════════════════════════════════════════════════════════════════════════════

FROM ubuntu:22.04

LABEL maintainer="RAGLOX Red Team"
LABEL description="Intentionally Vulnerable Container for Security Testing"
LABEL version="1.0"

# Avoid prompts during installation
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Install base packages
RUN apt-get update && apt-get install -y \
    apache2 \
    libapache2-mod-php \
    php \
    php-mysql \
    php-curl \
    php-xml \
    mysql-server \
    redis-server \
    openssh-server \
    sudo \
    curl \
    wget \
    netcat-openbsd \
    nmap \
    vim \
    python3 \
    python3-pip \
    cron \
    gcc \
    make \
    && rm -rf /var/lib/apt/lists/*

# ═══════════════════════════════════════════════════════════════════════════════
# WEB VULNERABILITIES
# ═══════════════════════════════════════════════════════════════════════════════

# Create web directory
RUN mkdir -p /var/www/html/uploads && \
    chmod 777 /var/www/html/uploads

# Vulnerable PHP Application - SQL Injection
RUN cat > /var/www/html/login.php << 'VULNPHP'
<?php
// VULNERABLE: SQL Injection
$servername = "localhost";
$username = "root";
$password = "toor";
$dbname = "vulndb";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $conn = new mysqli($servername, $username, $password, $dbname);
    $user = $_POST['username'];
    $pass = $_POST['password'];
    
    // VULNERABLE: No prepared statements
    $sql = "SELECT * FROM users WHERE username='$user' AND password='$pass'";
    $result = $conn->query($sql);
    
    if ($result && $result->num_rows > 0) {
        echo "Welcome " . htmlspecialchars($user) . "!";
        echo "<br>Session Token: " . md5(time());
    } else {
        echo "Invalid credentials";
    }
}
?>
<html>
<body>
<h1>Login Portal</h1>
<form method="POST">
    Username: <input name="username"><br>
    Password: <input name="password" type="password"><br>
    <input type="submit" value="Login">
</form>
</body>
</html>
VULNPHP

# Vulnerable PHP - Command Injection
RUN cat > /var/www/html/ping.php << 'VULNPHP'
<?php
// VULNERABLE: Command Injection
if (isset($_GET['host'])) {
    $host = $_GET['host'];
    // VULNERABLE: No input sanitization
    $output = shell_exec("ping -c 2 " . $host);
    echo "<pre>$output</pre>";
}
?>
<html>
<body>
<h1>Network Ping Tool</h1>
<form method="GET">
    Host: <input name="host" value="127.0.0.1">
    <input type="submit" value="Ping">
</form>
</body>
</html>
VULNPHP

# Vulnerable PHP - Local File Inclusion
RUN cat > /var/www/html/include.php << 'VULNPHP'
<?php
// VULNERABLE: Local File Inclusion (LFI)
if (isset($_GET['page'])) {
    $page = $_GET['page'];
    // VULNERABLE: No path validation
    include($page);
} else {
    echo "Usage: ?page=home.php";
}
?>
VULNPHP

# Vulnerable PHP - Remote Code Execution (File Upload)
RUN cat > /var/www/html/upload.php << 'VULNPHP'
<?php
// VULNERABLE: Unrestricted File Upload
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_FILES["file"])) {
    $target_dir = "uploads/";
    $target_file = $target_dir . basename($_FILES["file"]["name"]);
    
    // VULNERABLE: No file type validation
    if (move_uploaded_file($_FILES["file"]["tmp_name"], $target_file)) {
        echo "File uploaded: <a href='$target_file'>$target_file</a>";
    } else {
        echo "Upload failed";
    }
}
?>
<html>
<body>
<h1>File Upload</h1>
<form method="POST" enctype="multipart/form-data">
    <input type="file" name="file">
    <input type="submit" value="Upload">
</form>
</body>
</html>
VULNPHP

# Vulnerable PHP - Server-Side Request Forgery (SSRF)
RUN cat > /var/www/html/fetch.php << 'VULNPHP'
<?php
// VULNERABLE: Server-Side Request Forgery (SSRF)
if (isset($_GET['url'])) {
    $url = $_GET['url'];
    // VULNERABLE: No URL validation
    $content = file_get_contents($url);
    echo "<pre>" . htmlspecialchars($content) . "</pre>";
}
?>
<html>
<body>
<h1>URL Fetcher</h1>
<form method="GET">
    URL: <input name="url" value="http://example.com" size="50">
    <input type="submit" value="Fetch">
</form>
</body>
</html>
VULNPHP

# Vulnerable PHP - Cross-Site Scripting (XSS)
RUN cat > /var/www/html/search.php << 'VULNPHP'
<?php
// VULNERABLE: Reflected XSS
if (isset($_GET['q'])) {
    $query = $_GET['q'];
    // VULNERABLE: No output encoding
    echo "<h2>Results for: $query</h2>";
}
?>
<html>
<body>
<h1>Search</h1>
<form method="GET">
    <input name="q" value="">
    <input type="submit" value="Search">
</form>
</body>
</html>
VULNPHP

# Vulnerable PHP - XML External Entity (XXE)
RUN cat > /var/www/html/xml.php << 'VULNPHP'
<?php
// VULNERABLE: XXE (XML External Entity)
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $xml_data = file_get_contents("php://input");
    
    // VULNERABLE: External entities enabled
    libxml_disable_entity_loader(false);
    $doc = new DOMDocument();
    $doc->loadXML($xml_data, LIBXML_NOENT | LIBXML_DTDLOAD);
    
    echo "Processed XML: <pre>" . htmlspecialchars($doc->textContent) . "</pre>";
}
?>
<html>
<body>
<h1>XML Parser</h1>
<form method="POST">
    <textarea name="xml" rows="10" cols="50">&lt;?xml version="1.0"?&gt;
&lt;data&gt;
&lt;name&gt;test&lt;/name&gt;
&lt;/data&gt;</textarea>
    <br><input type="submit" value="Parse">
</form>
</body>
</html>
VULNPHP

# Index page
RUN cat > /var/www/html/index.php << 'VULNPHP'
<?php
phpinfo();
// VULNERABLE: Information disclosure
?>
<html>
<body>
<h1>Vulnerable Web Application</h1>
<ul>
    <li><a href="login.php">Login (SQL Injection)</a></li>
    <li><a href="ping.php">Ping Tool (Command Injection)</a></li>
    <li><a href="include.php">Include (LFI)</a></li>
    <li><a href="upload.php">Upload (RCE)</a></li>
    <li><a href="fetch.php">Fetch (SSRF)</a></li>
    <li><a href="search.php">Search (XSS)</a></li>
    <li><a href="xml.php">XML (XXE)</a></li>
    <li><a href="api/users">API (REST Endpoints)</a></li>
    <li><a href="admin/">Admin Panel</a></li>
    <li><a href="backup/">Backup Files</a></li>
</ul>
<!-- TODO: Remove debug credentials admin:admin123 -->
</body>
</html>
VULNPHP

# Vulnerable API endpoint
RUN mkdir -p /var/www/html/api && \
    cat > /var/www/html/api/users.php << 'VULNPHP'
<?php
// VULNERABLE: No authentication, SQL Injection
header('Content-Type: application/json');

$conn = new mysqli("localhost", "root", "toor", "vulndb");

if (isset($_GET['id'])) {
    $id = $_GET['id'];
    // VULNERABLE: SQL Injection in API
    $result = $conn->query("SELECT * FROM users WHERE id=$id");
    echo json_encode($result->fetch_all(MYSQLI_ASSOC));
} else {
    $result = $conn->query("SELECT id, username FROM users");
    echo json_encode($result->fetch_all(MYSQLI_ASSOC));
}
?>
VULNPHP

# Create backup directory with sensitive files
RUN mkdir -p /var/www/html/backup && \
    echo "db_host=localhost" > /var/www/html/backup/config.bak && \
    echo "db_user=root" >> /var/www/html/backup/config.bak && \
    echo "db_pass=toor" >> /var/www/html/backup/config.bak && \
    echo "admin_key=SuperSecretKey123" >> /var/www/html/backup/config.bak

# Admin panel with hardcoded credentials
RUN mkdir -p /var/www/html/admin && \
    cat > /var/www/html/admin/index.php << 'VULNPHP'
<?php
// VULNERABLE: Hardcoded credentials
$admin_user = "admin";
$admin_pass = "admin123";

session_start();
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if ($_POST['user'] == $admin_user && $_POST['pass'] == $admin_pass) {
        $_SESSION['admin'] = true;
        echo "<h1>Welcome Admin!</h1>";
        echo "<p>Server: " . php_uname() . "</p>";
        echo "<p>Document Root: " . $_SERVER['DOCUMENT_ROOT'] . "</p>";
    }
}
?>
<html>
<body>
<h1>Admin Login</h1>
<form method="POST">
    User: <input name="user"><br>
    Pass: <input name="pass" type="password"><br>
    <input type="submit" value="Login">
</form>
</body>
</html>
VULNPHP

# ═══════════════════════════════════════════════════════════════════════════════
# DATABASE VULNERABILITIES
# ═══════════════════════════════════════════════════════════════════════════════

# MySQL setup script
RUN cat > /tmp/mysql_setup.sql << 'SQLSETUP'
CREATE DATABASE IF NOT EXISTS vulndb;
USE vulndb;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50),
    password VARCHAR(50),
    email VARCHAR(100),
    role VARCHAR(20),
    credit_card VARCHAR(20)
);

INSERT INTO users (username, password, email, role, credit_card) VALUES
('admin', 'admin123', 'admin@company.local', 'admin', '4111111111111111'),
('john', 'password123', 'john@company.local', 'user', '4222222222222222'),
('alice', 'alice2024', 'alice@company.local', 'user', '4333333333333333'),
('bob', 'bob_secure', 'bob@company.local', 'manager', '4444444444444444'),
('service_account', 'svc_P@ssw0rd!', 'svc@company.local', 'service', NULL);

CREATE TABLE IF NOT EXISTS secrets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    key_name VARCHAR(50),
    key_value VARCHAR(200)
);

INSERT INTO secrets (key_name, key_value) VALUES
('aws_access_key', 'AKIAIOSFODNN7EXAMPLE'),
('aws_secret_key', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'),
('api_key', 'sk-proj-abcdef123456789'),
('jwt_secret', 'super_secret_jwt_key_2024');

GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' IDENTIFIED BY 'toor';
FLUSH PRIVILEGES;
SQLSETUP

# ═══════════════════════════════════════════════════════════════════════════════
# SYSTEM VULNERABILITIES
# ═══════════════════════════════════════════════════════════════════════════════

# Create vulnerable users with weak passwords
RUN useradd -m -s /bin/bash victim 2>/dev/null || true && echo "victim:victim123" | chpasswd && \
    useradd -m -s /bin/bash developer 2>/dev/null || true && echo "developer:dev2024" | chpasswd && \
    useradd -m -s /bin/bash backupuser 2>/dev/null || true && echo "backupuser:backup" | chpasswd

# SUID Binary vulnerability (for privilege escalation)
RUN cat > /tmp/vuln_suid.c << 'CCODE'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    // VULNERABLE: SUID binary that can execute arbitrary commands
    if (argc > 1) {
        setuid(0);
        system(argv[1]);
    } else {
        printf("Usage: %s <command>\n", argv[0]);
    }
    return 0;
}
CCODE
RUN gcc -o /usr/local/bin/vuln_suid /tmp/vuln_suid.c && \
    chmod u+s /usr/local/bin/vuln_suid && \
    rm /tmp/vuln_suid.c

# Weak sudo configuration
RUN echo "victim ALL=(ALL) NOPASSWD: /usr/bin/find" >> /etc/sudoers && \
    echo "developer ALL=(ALL) NOPASSWD: /usr/bin/vim" >> /etc/sudoers && \
    echo "backupuser ALL=(ALL) NOPASSWD: /bin/tar" >> /etc/sudoers

# World-writable sensitive files
RUN chmod 777 /etc/passwd.bak 2>/dev/null || cp /etc/passwd /etc/passwd.bak && chmod 666 /etc/passwd.bak
RUN echo "root:x:0:0:root:/root:/bin/bash" > /etc/passwd.bak

# Exposed SSH private key
RUN mkdir -p /home/victim/.ssh && \
    ssh-keygen -t rsa -b 2048 -f /home/victim/.ssh/id_rsa -N "" && \
    chmod 644 /home/victim/.ssh/id_rsa && \
    chown -R victim:victim /home/victim/.ssh

# Cron job vulnerability
RUN echo "* * * * * root /tmp/backup.sh" >> /etc/crontab && \
    echo "#!/bin/bash" > /tmp/backup.sh && \
    echo "# Backup script - runs as root" >> /tmp/backup.sh && \
    chmod 777 /tmp/backup.sh

# Sensitive files in predictable locations
RUN echo "DB_PASSWORD=production_db_secret_2024" > /var/www/html/.env && \
    echo "API_SECRET=sk-live-9f8e7d6c5b4a3210" >> /var/www/html/.env

# History files with credentials
RUN echo "mysql -u root -ptoor" > /home/victim/.bash_history && \
    echo "ssh admin@192.168.1.100" >> /home/victim/.bash_history && \
    echo "export AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG" >> /home/victim/.bash_history

# ═══════════════════════════════════════════════════════════════════════════════
# SERVICE CONFIGURATIONS
# ═══════════════════════════════════════════════════════════════════════════════

# SSH Configuration (weak settings)
RUN mkdir -p /var/run/sshd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:toor" | chpasswd

# Redis without authentication
RUN sed -i 's/bind 127.0.0.1/bind 0.0.0.0/' /etc/redis/redis.conf && \
    sed -i 's/protected-mode yes/protected-mode no/' /etc/redis/redis.conf

# Apache configuration
RUN a2enmod php8.1 && \
    echo "ServerSignature On" >> /etc/apache2/apache2.conf && \
    echo "ServerTokens Full" >> /etc/apache2/apache2.conf

# ═══════════════════════════════════════════════════════════════════════════════
# STARTUP SCRIPT
# ═══════════════════════════════════════════════════════════════════════════════

RUN cat > /start.sh << 'STARTUP'
#!/bin/bash
echo "=========================================="
echo "RAGLOX Vulnerable Target Starting..."
echo "=========================================="

# Start MySQL
service mysql start
sleep 3

# Initialize database
mysql < /tmp/mysql_setup.sql 2>/dev/null || true

# Start Redis
redis-server --daemonize yes

# Start SSH
service ssh start

# Start Apache
apache2ctl -D FOREGROUND
STARTUP

RUN chmod +x /start.sh

# Expose ports
EXPOSE 80 22 3306 6379

# Health check
HEALTHCHECK --interval=30s --timeout=3s \
    CMD curl -f http://localhost/ || exit 1

CMD ["/start.sh"]
