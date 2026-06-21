# Lab 5 Guide Outline: Hash Functions, Cryptanalysis, and Secure Web Server Setup

## 1. Introduction

    *   Lab Objectives
    *   Overview of Topics (Hashing, Cryptanalysis, TLS/Apache)
    *   Prerequisites (Software, Basic Knowledge)

## 2. Hash Functions with OpenSSL and BIO

    *   **2.1 Introduction to Hash Functions**
        *   Definition and Purpose
        *   Key Properties (Pre-image resistance, Second pre-image resistance, Collision resistance)
        *   Common Algorithms (MD5, SHA-1, SHA-2, SHA-3)
    *   **2.2 Introduction to OpenSSL**
        *   Overview of the OpenSSL Toolkit (Command Line vs. Library)
    *   **2.3 Introduction to OpenSSL BIO (Basic Input/Output)**
        *   Concept of BIOs
        *   Types of BIOs (Source/Sink, Filter)
        *   BIO Chains
    *   **2.4 Lab Task: Hashing with OpenSSL Command Line**
        *   Using `openssl dgst` for hashing strings and files.
        *   Examples: MD5, SHA-1, SHA-2, SHA-3.
        *   Verifying output.
    *   **2.5 Lab Task: Hashing Programmatically with OpenSSL BIO (C/C++)**
        *   Environment Setup (Compiler, OpenSSL Development Libraries)
        *   Core Concepts: Creating BIOs (Memory, File, Digest), Linking BIOs, Writing Data, Reading Digest.
        *   Detailed C/C++ Code Example:
            *   Include Headers
            *   Initialize OpenSSL
            *   Get Digest Algorithm (e.g., `EVP_sha256()`)
            *   Create Digest BIO (`BIO_f_md()`)
            *   Create Source BIO (e.g., `BIO_s_mem()` or `BIO_new_file()`)
            *   Push Digest BIO onto Source BIO (`BIO_push()`)
            *   Write data through the BIO chain (`BIO_write()`)
            *   Retrieve the hash digest (`BIO_gets()` or `BIO_ctrl()` with `BIO_C_GET_MD_CTX`)
            *   Cleanup (`BIO_free_all()`)
        *   Compilation Instructions (using `gcc`/`g++` with `-lssl -lcrypto`)
        *   Running the Example and Explanation.

## 3. Cryptanalysis of Hash Functions

    *   **3.1 Introduction to Hash Function Attacks**
        *   Motivation for Attacks
        *   Attack Types Overview (Collision, Pre-image, Length Extension)
    *   **3.2 Collision Attacks**
        *   Definition and Impact
        *   MD5 Collisions: Background, significance, demonstration with known colliding inputs/files.
        *   SHA-1 Collisions: Background (SHAttered), complexity, mention resources.
    *   **3.3 Lab Task: Observing MD5 Collisions**
        *   Using provided example pairs (files/messages) that produce the same MD5 hash.
        *   Verifying the collision using `openssl dgst -md5`.
    *   **3.4 Length Extension Attacks**
        *   Explanation: Exploiting Merkle–Damgård structure (MD5, SHA-1, SHA-256).
        *   Scenario: Appending to a message hashed with a secret prefix.
        *   Requirements: Original hash, length of the secret, original message.
    *   **3.5 Lab Task: Performing a Length Extension Attack**
        *   **3.5.1 Using Python:**
            *   Conceptual Python code demonstrating the padding and state manipulation (may require a library that exposes internal hash states or a custom implementation for educational purposes).
            *   Focus on the logic rather than a full practical exploit if library support is limited.
        *   **3.5.2 Using HashPump:**
            *   Installation (`sudo apt-get install hashpump` or build from source).
            *   Command Syntax: `hashpump -s <signature> -d <original_data> -k <key_length> -a <data_to_add>`.
            *   Example Walkthrough: Input parameters and interpreting the output (new signature, new data).
            *   Verification: Hashing the forged message (secret || original_data || padding || added_data) independently to match the generated signature (requires knowing the secret for verification only).

## 4. Secure Web Server Setup with Apache and TLS

    *   **4.1 Introduction to TLS/SSL and HTTPS**
        *   Purpose: Confidentiality, Integrity, Authentication on the Web.
        *   Key Components: Certificates, Public/Private Keys, Certificate Authorities (CAs), Handshake Process.
    *   **4.2 Setting up Apache Web Server**
        *   **4.2.1 Ubuntu:**
            *   Installation: `sudo apt update && sudo apt install apache2`
            *   Checking Status: `systemctl status apache2`
            *   Basic Test: Accessing server IP via HTTP.
        *   **4.2.2 Windows:**
            *   Options: XAMPP, WAMP, Laragon, Official Apache binaries.
            *   Installation Steps (General guide, may vary slightly by package).
            *   Starting Apache Service.
            *   Basic Test: Accessing `http://localhost`.
    *   **4.3 Generating Keys and Self-Signed Certificates with OpenSSL**
        *   Step 1: Generate Private Key (`openssl genpkey ...` or `openssl genrsa ...`)
        *   Step 2: Generate Certificate Signing Request (CSR) (`openssl req -new ...`)
        *   Step 3: Generate Self-Signed Certificate (`openssl x509 -req -signkey ...`)
        *   Explanation of Certificate Fields.
        *   Storing the key (`.key`) and certificate (`.crt`) files securely.
    *   **4.4 Configuring Apache for TLS on Ubuntu**
        *   Enable SSL Module: `sudo a2enmod ssl`
        *   Apache Configuration Structure (`/etc/apache2/`)
        *   Create/Edit SSL Virtual Host (`/etc/apache2/sites-available/default-ssl.conf` or a custom file).
        *   Key Directives:
            *   `SSLEngine on`
            *   `SSLCertificateFile /path/to/your/server.crt`
            *   `SSLCertificateKeyFile /path/to/your/server.key`
        *   Configure Secure Protocols/Ciphers:
            *   `SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1` (Allow TLSv1.2 and TLSv1.3)
            *   `SSLCipherSuite HIGH:!aNULL:!MD5` (Example, refer to Mozilla SSL Config Generator for better defaults)
        *   Enable the Site: `sudo a2ensite default-ssl` (or your custom site file)
        *   Test Configuration: `sudo apache2ctl configtest`
        *   Restart Apache: `sudo systemctl restart apache2`
        *   Test HTTPS Access (expect browser warning for self-signed cert).
    *   **4.5 Configuring Apache for TLS on Windows**
        *   Locate Configuration Files (e.g., `httpd.conf`, `extra/httpd-ssl.conf`).
        *   Ensure SSL Module is Loaded (`LoadModule ssl_module modules/mod_ssl.so`).
        *   Uncomment or include the SSL config file (`Include conf/extra/httpd-ssl.conf`).
        *   Edit the SSL Virtual Host (`<VirtualHost _default_:443>` in `httpd-ssl.conf`).
        *   Key Directives (use Windows paths):
            *   `SSLEngine on`
            *   `SSLCertificateFile 
