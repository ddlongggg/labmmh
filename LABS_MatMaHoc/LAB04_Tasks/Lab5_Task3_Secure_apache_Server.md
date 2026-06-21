## 4. Secure Web Server Setup with Apache and TLS

Securing web communications is paramount in today's digital landscape. This section guides you through the process of setting up the Apache HTTP Server, a widely used web server, and configuring it to use Transport Layer Security (TLS), the successor to Secure Sockets Layer (SSL), to enable secure HTTPS connections. We will cover the installation of Apache on both Ubuntu Linux and Windows operating systems, the generation of necessary cryptographic keys and certificates using OpenSSL, and the detailed configuration steps required to enable TLS, including specifying secure protocols and cipher suites. While we will use self-signed certificates for this lab environment, the principles apply directly to using certificates issued by trusted Certificate Authorities (CAs) in production settings.

### 4.1 Introduction to TLS/SSL and HTTPS

Transport Layer Security (TLS), and its predecessor SSL, are cryptographic protocols designed to provide secure communication over a computer network. When used with the Hypertext Transfer Protocol (HTTP), it forms HTTPS (HTTP Secure). HTTPS ensures three key security goals: Confidentiality (preventing eavesdropping by encrypting the data exchanged between the client browser and the web server), Integrity (ensuring that the data has not been tampered with during transit using message authentication codes), and Authentication (verifying the identity of the web server, and optionally the client, typically through digital certificates). The core components enabling TLS include asymmetric key pairs (a public key and a private key), digital certificates (which bind a public key to an identity, like a domain name, and are usually signed by a trusted CA), and a handshake process where the client and server negotiate cryptographic algorithms and establish shared secret keys for the session.

### 4.2 Setting up Apache Web Server

Before configuring TLS, you need a working Apache installation. The installation process differs slightly between Ubuntu and Windows.

**4.2.1 Apache Installation on Ubuntu:**
Ubuntu's package manager, `apt`, makes installing Apache straightforward. Open a terminal and run the following commands:

```bash
# Update the package list
sudo apt update

# Install the apache2 package
sudo apt install apache2 -y
```

Once installed, the Apache service usually starts automatically. You can verify its status:

```bash
systemctl status apache2
```

Look for output indicating the service is "active (running)". If it's not running, you can start it with `sudo systemctl start apache2`. To ensure Apache runs on boot, use `sudo systemctl enable apache2`.

To perform a basic test, open a web browser and navigate to `http://<your_server_ip>`. You should see the default Apache Ubuntu page. You can find your server's IP address using the command `ip addr show`.

**4.2.2 Apache Installation on Windows:**
Installing Apache on Windows can be done using pre-packaged distributions that include Apache, MySQL/MariaDB, and PHP (like XAMPP, WampServer, Laragon), or by downloading the official Apache binaries from the Apache Lounge or Apache Haus websites (as the Apache Foundation itself doesn't provide official binaries for Windows).

*   **Using a Package (e.g., XAMPP):** Download the XAMPP installer from the Apache Friends website. Run the installer, following the on-screen prompts. Choose the components you need (Apache is essential). Once installed, use the XAMPP Control Panel to start the Apache module.
*   **Using Official Binaries (e.g., from Apache Lounge):** Download the appropriate Zip archive (e.g., Win64) for the latest Apache version. Extract the `Apache24` directory to a suitable location, like `C:\Apache24`. Configure Apache by editing `C:\Apache24\conf\httpd.conf` (at minimum, check the `ServerRoot` and `Listen` directives). Install Apache as a Windows service by opening a command prompt as Administrator, navigating to `C:\Apache24\bin`, and running `httpd.exe -k install`. Start the service using the Services management console (`services.msc`) or via `httpd.exe -k start`.

To perform a basic test, open a web browser and navigate to `http://localhost` or `http://127.0.0.1`. You should see the default Apache test page (it might say "It works!").

### 4.3 Generating Keys and Self-Signed Certificates with OpenSSL

To enable TLS, the server needs a private key and a corresponding public key embedded within a digital certificate. For production, you'd obtain a certificate from a trusted CA. For this lab, we'll generate a self-signed certificate using OpenSSL. OpenSSL is typically pre-installed on Linux; on Windows, it's included with Git for Windows, XAMPP, or can be installed separately.

Execute the following OpenSSL commands in your terminal or command prompt. It's good practice to create a dedicated directory for these files, for example, `/etc/ssl/private` for the key and `/etc/ssl/certs` for the certificate on Linux, or `C:\Apache24\conf\ssl` on Windows.

**Step 1: Generate a Private Key**
This command creates a 2048-bit RSA private key and saves it to `server.key`. Keep this file secure and confidential.

```bash
# On Linux (adjust path as needed, use sudo if writing to /etc/ssl/private)
sudo openssl genpkey -algorithm RSA -out /etc/ssl/private/server.key -pkeyopt rsa_keygen_bits:2048

# On Windows (adjust path as needed)
openssl genpkey -algorithm RSA -out C:/Apache24/conf/ssl/server.key -pkeyopt rsa_keygen_bits:2048 
# Ensure the output directory (e.g., C:/Apache24/conf/ssl) exists first.
```
*(Older command using `genrsa`: `openssl genrsa -out server.key 2048`)*

**Step 2: Generate a Certificate Signing Request (CSR)**
The CSR contains information about your server (like domain name) and your public key. It's what you would normally send to a CA.

```bash
# On Linux (use the key generated above)
sudo openssl req -new -key /etc/ssl/private/server.key -out /etc/ssl/certs/server.csr

# On Windows (use the key generated above)
openssl req -new -key C:/Apache24/conf/ssl/server.key -out C:/Apache24/conf/ssl/server.csr
```
You will be prompted to enter information for the certificate. For a self-signed certificate, most fields aren't critical, but the "Common Name (e.g. server FQDN or YOUR name)" is important. Enter the domain name or IP address that users will use to access your server (e.g., `localhost`, `your.server.ip`). Leave the challenge password blank.

**Step 3: Generate a Self-Signed Certificate**
This command takes your private key and CSR to create a certificate (`server.crt`) valid for 365 days. Since we are signing it ourselves (using our own private key), it's "self-signed".

```bash
# On Linux
sudo openssl x509 -req -days 365 -in /etc/ssl/certs/server.csr -signkey /etc/ssl/private/server.key -out /etc/ssl/certs/server.crt

# On Windows
openssl x509 -req -days 365 -in C:/Apache24/conf/ssl/server.csr -signkey C:/Apache24/conf/ssl/server.key -out C:/Apache24/conf/ssl/server.crt
```

You now have `server.key` (private key) and `server.crt` (self-signed certificate). The `server.csr` file is no longer needed for this process.

### 4.4 Configuring Apache for TLS on Ubuntu

Configuration involves enabling the SSL module, setting up an SSL-enabled virtual host, and pointing Apache to your key and certificate files.

**Step 1: Enable SSL Module**
```bash
sudo a2enmod ssl
```
This creates a symbolic link enabling the SSL module. You'll need to restart Apache later for this to take effect.

**Step 2: Configure SSL Virtual Host**
Apache on Ubuntu typically comes with a default SSL virtual host configuration file. Let's edit it:

```bash
sudo nano /etc/apache2/sites-available/default-ssl.conf
```

Inside this file, locate and modify (or add if missing) the following key directives within the `<VirtualHost _default_:443>` block:

*   Ensure `SSLEngine on` is present and uncommented.
*   Point `SSLCertificateFile` to your certificate file:
    `SSLCertificateFile /etc/ssl/certs/server.crt`
*   Point `SSLCertificateKeyFile` to your private key file:
    `SSLCertificateKeyFile /etc/ssl/private/server.key`

**Step 3: Configure Secure Protocols and Ciphers (Important!)**
Within the same `<VirtualHost _default_:443>` block (or globally in `/etc/apache2/mods-available/ssl.conf`), configure the allowed protocols and cipher suites. It's crucial to disable outdated, insecure protocols like SSLv3, TLSv1.0, and TLSv1.1.

```apache
# Example: Allow only TLSv1.2 and TLSv1.3
SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1

# Example: A reasonably strong cipher suite (refer to Mozilla SSL Config Generator for up-to-date recommendations)
SSLCipherSuite HIGH:!aNULL:!MD5:!ADH:!RC4
SSLHonorCipherOrder on
SSLSessionTickets off # Consider security implications
```

Using a tool like the [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/) is highly recommended for generating robust, up-to-date configurations based on your Apache version and desired compatibility level.

Save and close the configuration file (Ctrl+X, then Y, then Enter in nano).

**Step 4: Enable the SSL Site**
```bash
sudo a2ensite default-ssl.conf
```

**Step 5: Test Configuration and Restart Apache**
Always test your Apache configuration before restarting:
```bash
sudo apache2ctl configtest
```
If it reports "Syntax OK", restart Apache to apply all changes:
```bash
sudo systemctl restart apache2
```

**Step 6: Test HTTPS Access**
Open your browser and navigate to `https://<your_server_ip>` or `https://localhost` (if testing locally). You will likely see a browser warning ("Your connection is not private", "Warning: Potential Security Risk Ahead", etc.) because the certificate is self-signed and not trusted by your browser's built-in list of CAs. This is expected in a lab environment. You can usually proceed by accepting the risk (look for an "Advanced" or "Accept the Risk and Continue" option).

### 4.5 Configuring Apache for TLS on Windows

The process on Windows is conceptually similar but involves different file paths and potentially different configuration file structures depending on your installation method.

**Step 1: Locate Configuration Files**
The main configuration file is typically `C:\Apache24\conf\httpd.conf`. The SSL-specific configuration is often in `C:\Apache24\conf\extra\httpd-ssl.conf`.

**Step 2: Ensure SSL Module is Loaded**
Open `httpd.conf` in a text editor. Search for the line `LoadModule ssl_module modules/mod_ssl.so`. Ensure it is present and not commented out (does not start with `#`).

**Step 3: Include SSL Configuration File**
Still in `httpd.conf`, search for the line `Include conf/extra/httpd-ssl.conf`. Ensure it is uncommented so that the SSL virtual host settings are loaded.

**Step 4: Edit SSL Virtual Host Configuration**
Open `C:\Apache24\conf\extra\httpd-ssl.conf` in a text editor. Locate the `<VirtualHost _default_:443>` block (or a similar one).

*   Ensure `SSLEngine on` is present and uncommented.
*   Point `SSLCertificateFile` to your certificate file (use Windows-style paths or forward slashes):
    `SSLCertificateFile "C:/Apache24/conf/ssl/server.crt"`
*   Point `SSLCertificateKeyFile` to your private key file:
    `SSLCertificateKeyFile "C:/Apache24/conf/ssl/server.key"`

**Step 5: Configure Secure Protocols and Ciphers**
Similar to Ubuntu, add or modify the `SSLProtocol` and `SSLCipherSuite` directives within the `<VirtualHost _default_:443>` block or globally in `httpd-ssl.conf` or `httpd.conf`. Use the same secure settings as recommended for Ubuntu (disabling old protocols, using strong ciphers).

```apache
# Example: Allow only TLSv1.2 and TLSv1.3
SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1

# Example: A reasonably strong cipher suite
SSLCipherSuite HIGH:!aNULL:!MD5:!ADH:!RC4
SSLHonorCipherOrder on
SSLSessionTickets off
```
Again, consult the Mozilla SSL Configuration Generator for best practices.

Save the configuration file(s).

**Step 6: Test Configuration and Restart Apache**
Open a command prompt as Administrator, navigate to `C:\Apache24\bin`, and test the configuration:
```cmd
httpd.exe -t
```
If it reports "Syntax OK", restart the Apache service. You can do this via the Services management console (`services.msc`, find the Apache service, and click Restart) or using the command line:
```cmd
httpd.exe -k restart
```
If using XAMPP or similar, use its control panel to stop and restart the Apache module.

**Step 7: Test HTTPS Access**
Open your browser and navigate to `https://localhost` or `https://127.0.0.1`. As with Ubuntu, expect a security warning due to the self-signed certificate. Proceed past the warning to verify that the secure connection is established and your Apache server is serving content over HTTPS.

This completes the setup of Apache with basic TLS configuration using a self-signed certificate on both Ubuntu and Windows platforms.
