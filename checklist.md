# Checklist for web application penetration testing

# Recon

## Horizontal Mapping

- [ ]  Finding related domains via **`WhoisXMLAPI`**
- [ ]  Crunchbase
- [ ]  ChatGPT
- [ ]  Security trails

```jsx
cat roots.txt | haktrails associateddomains
echo "tesla.com" | haktrails associateddomains
```

## IP space

- [ ]  Bgp.he.net

```jsx
apt-get install whois
whois -h whois.radb.net  -- '-i origin AS714' | grep -Eo "([0-9.]+){4}/[0-9]+" | uniq -u
```

- [ ]  PTR records Reverse DNS

```jsx
echo 17.0.0.0/16 | mapcidr -silent | dnsx -ptr -resp-only -o output.txt
```

- [ ]  Favicon search

```jsx
#Installation
git clone https://github.com/pielco11/fav-up.git
cd fav-up/
pip3 install -r requirements.txt
apt-get install jq

#Initializing Shodan API key
shodan init A5TCTEH78E6Zhjdva6X2fls6Oob9F2hL

#Running the tool
python3 favUp.py -w www.github.com -sc -o output.json

#Parsing the output
cat output.json | jq -r 'try .found_ips' | sed "s/|/\n/g"
```

## Vertical Mapping

- [ ]  Passive subdomain enumeration
- [ ]  Active subdomain enumeration
- [ ]  permutation subdomain enumeration
- [ ]  resolving them
- [ ]  Port scanning - Top 3000
- [ ]  probing for alive servers with httpx
- [ ]  Crawling with Burp suite and katana & wayback urls
- [ ]  ffuf ( directory and file fuzzing)
- [ ]  Vhost enumeration
- [ ]  Parsing javascript files - endpoints,secrets,client side vulnerabilities

## Manual checking

- [ ]  Shodan
- [ ]  censys
- [ ]  github
- [ ]  google dork
- [ ]  FOFA
- [ ]  Zoomeye

# Information gathering

- [ ]  Manually exploring the site
- [ ]  Spider/crawl for missed or hidden content
- [ ]  Check for files that expose content, such as robots.txt, sitemap.xml, .DS_Store
- [ ]  Check the caches of major search engines for publicly accessible sites
- [ ]  Check for differences in content based on User Agent (eg, Mobile sites, access as a Search engine Crawler)
- [ ]  Perform Web Application Fingerprinting
- [ ]  Identify technologies used
- [ ]  Identify user roles
- [ ]  Identify application entry points
- [ ]  Identify client-side code
- [ ]  Identify multiple versions/channels (e.g. web, mobile web, mobile app, web services)
- [ ]  Identify co-hosted and related applications
- [ ]  Identify all hostnames and ports
- [ ]  Identify third-party hosted content
- [ ]  Identify Debug parameters

## **Configuration Management**

- [ ]  Check for commonly used application and administrative URLs
- [ ]  Check for old, backup and unreferenced files
- [ ]  Check HTTP methods supported and Cross Site Tracing (XST)
- [ ]  Test file extensions handling
- [ ]  Test for security HTTP headers (e.g. CSP, X-Frame-Options, HSTS)
- [ ]  Test for policies (e.g. Flash, Silverlight, robots)
- [ ]  Test for non-production data in live environment, and vice-versa
- [ ]  Check for sensitive data in client-side code (e.g. API keys, credentials)
- [ ]  Dependency confusion
- [ ]  Subdomain takeover
- [ ]  EXIF Geolocation Data Not Stripped From Uploaded Images

## **Secure Transmission**

- [ ]  Check SSL Version, Algorithms, Key length
- [ ]  Check for Digital Certificate Validity (Duration, Signature and CN)
- [ ]  Check credentials only delivered over HTTPS
- [ ]  Check that the login form is delivered over HTTPS
- [ ]  Check session tokens only delivered over HTTPS
- [ ]  Check if HTTP Strict Transport Security (HSTS) in use

## Authentication

- [ ]  Test for user enumeration
- [ ]  Test for authentication bypass
- [ ]  Test for bruteforce protection
- [ ]  Test password quality rules
- [ ]  Test remember me functionality
- [ ]  Test for autocomplete on password forms/input
- [ ]  Test password reset and/or recovery
- [ ]  Test password change process
- [ ]  Test CAPTCHA
- [ ]  Test multi factor authentication
- [ ]  Test for logout functionality presence
- [ ]  Test for cache management on HTTP (eg Pragma, Expires, Max-age)
- [ ]  Test for default logins
- [ ]  Test for user-accessible authentication history
- [ ]  Test for out-of channel notification of account lockouts and successful password changes
- [ ]  Test for consistent authentication across applications with shared authentication schema / SSO

## **Session Management**

- [ ]  Establish how session management is handled in the application (eg, tokens in cookies, token in URL)
- [ ]  Check session tokens for cookie flags (httpOnly and secure)
- [ ]  Check session cookie scope (path and domain)
- [ ]  Check session cookie duration (expires and max-age)
- [ ]  Check session termination after a maximum lifetime
- [ ]  Check session termination after relative timeout
- [ ]  Check session termination after logout
- [ ]  Test to see if users can have multiple simultaneous sessions
- [ ]  Test session cookies for randomness
- [ ]  Confirm that new session tokens are issued on login, role change and logout
- [ ]  Test for consistent session management across applications with shared session management
- [ ]  Test for session puzzling
- [ ]  Test for CSRF and clickjacking

## **Authorization**

- [ ]  Test for bypassing authorization schema
- [ ]  Test for vertical Access control problems (a.k.a. Privilege Escalation)
- [ ]  Test for horizontal Access control problems (between two users at the same privilege level)
- [ ]  Test for missing authorization
- [ ]  Test for bypassing authorization schema

## **Data Validation**

- [ ]  Test for Reflected Cross Site Scripting
- [ ]  Test for Stored Cross Site Scripting
- [ ]  Test for DOM based Cross Site Scripting
- [ ]  Test for Cross Site Flashing
- [ ]  Test for HTML Injection
- [ ]  Test for path traversal
- [ ]  Test for SQL Injection
- [ ]  Test for LDAP Injection
- [ ]  Test for ORM Injection
- [ ]  Test for XML Injection
- [ ]  Test for XXE Injection
- [ ]  Test for SSI Injection
- [ ]  Test for XPath Injection
- [ ]  Test for XQuery Injection
- [ ]  Test for IMAP/SMTP Injection
- [ ]  Test for Code Injection
- [ ]  Test for Expression Language Injection
- [ ]  Test for Command Injection
- [ ]  Test for Overflow (Stack, Heap and Integer)
- [ ]  Test for Format String
- [ ]  Test for HTTP Splitting/Smuggling
- [ ]  Test for HTTP Verb Tampering
- [ ]  Test for Open Redirection
- [ ]  Test for Local File Inclusion
- [ ]  Test for Remote File Inclusion
- [ ]  Compare client-side and server-side validation rules
- [ ]  Test for NoSQL injection
- [ ]  Test for HTTP parameter pollution
- [ ]  Test for Mass Assignment
- [ ]  Test for NULL/Invalid Session Cookie
- [ ]  Test for Deserlization vulnerability
- [ ]  client side prototype pollution
- [ ]  secondary context path traversal
- [ ]  Server side request forgery
- [ ]  Graphql API
- [ ]  Host header attacks
- [ ]  Iframe injection

## **Denial of Service**

- [ ]  Test for anti-automation
- [ ]  Test for account lockout
- [ ]  Test for HTTP protocol DoS
- [ ]  Test for SQL wildcard DoS

## Bussiness Logics

- [ ]  Test for feature misuse
- [ ]  Test for lack of non-repudiation
- [ ]  Test for trust relationships
- [ ]  Test for integrity of data
- [ ]  Test segregation of duties
- [ ]  Race conditions

## **Cryptography**

- [ ]  Check if data which should be encrypted is not
- [ ]  Check for wrong algorithms usage depending on context
- [ ]  Check for weak algorithms usage
- [ ]  Check for proper use of salting
- [ ]  Check for randomness functions

## File Uploads

- [ ]  Test that acceptable file types are whitelisted
- [ ]  Test that file size limits, upload frequency and total file counts are defined and are enforced
- [ ]  Test that file contents match the defined file type
- [ ]  Test that all file uploads have Anti-Virus scanning in-place.
- [ ]  Test that unsafe filenames are sanitised
- [ ]  Test that uploaded files are not directly accessible within the web root
- [ ]  Test that uploaded files are not served on the same hostname/port
- [ ]  Test that files and other media are integrated with the authentication and authorisation schemas

## Functionality tests

- [ ]  Test for known vulnerabilities and configuration issues on Web Server and Web Application
- [ ]  Test for default or guessable password
- [ ]  Test for non-production data in live environment, and vice-versa
- [ ]  Test for Injection vulnerabilities
- [ ]  Test for Buffer Overflows
- [ ]  Test for Insecure Cryptographic Storage
- [ ]  Test for Insufficient Transport Layer Protection
- [ ]  Test for Improper Error Handling
- [ ]  Test for all vulnerabilities with a CVSS v2 score > 4.0
- [ ]  Test for Authentication and Authorization issues
- [ ]  Test for CSRF
- [ ]  Test for CORS
- [ ]  JWT attacks

# SANS

- [ ]  Out-of-bounds Write
- [ ]  Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- [ ]  Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
- [ ]  Use After Free
- [ ]  Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
- [ ]  Improper Input Validation
- [ ]  Out-of-bounds Read
- [ ]  Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
- [ ]  Cross-Site Request Forgery (CSRF)
- [ ]  Unrestricted Upload of File with Dangerous Type
- [ ]  Missing Authorization
- [ ]  NULL Pointer Dereference
- [ ]  Improper Authentication
- [ ]  Integer Overflow or Wraparound
- [ ]  Deserialization of Untrusted Data
- [ ]  Improper Neutralization of Special Elements used in a Command ('Command Injection')
- [ ]  Improper Restriction of Operations within the Bounds of a Memory Buffer
- [ ]  Use of Hard-coded Credentials
- [ ]  Server-Side Request Forgery (SSRF)
- [ ]  Missing Authentication for Critical Function
- [ ]  Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
- [ ]  Improper Privilege Management
- [ ]  Improper Control of Generation of Code ('Code Injection')
- [ ]  Incorrect Authorization
- [ ]  Incorrect Default Permissions

# SAST/White Box Testing

- [ ]  CodeQl Analysis
- [ ]  Semgrep Analysis
- [ ]  source code review for xss
- [ ]  source code review for code injection
- [ ]  source code review for Broken Authentication
- [ ]  source code review for Cryptographic failure
- [ ]  source code review for Sensitive Data Exposure
- [ ]  Source code review for input validation

# DAST/BlackBox Testing

- [ ]  Burp suite
- [ ]  acunetix
- [ ]  nessus
- [ ]  Nuclei

# Network Penetration testing

- [ ]  Firewall configuration testing
- [ ]  Firewall bypass testing
- [ ]  IPS deception
- [ ]  DNS attacks
- [ ]  Full portscan
- [ ]  pentesting java debug wire protocol
- [ ]  pentesting printers
- [ ]  pentesting sap
- [ ]  Pentesting Voip
- [ ]  Pentesting Remote Gdbserver
- [ ]  Pentesting Echo
- [ ]  Pentesting FTP
- [ ]  Pentesting SSH
- [ ]  Pentesting Telnet
- [ ]  Pentesting SMTP
- [ ]  Pentesting WHOIS
- [ ]  Pentesting TACACS+
- [ ]  Pnetesting DNS
- [ ]  80,443 web methodology commom service exploiting
- [ ]  Pentesting kerberos
- [ ]  Pentesting POP
- [ ]  Pentesting Portmapper
- [ ]  Pentesting ident
- [ ]  Pentesting NTP
- [ ]  Pentesting MSRPC
- [ ]  Pentesting Netbois
- [ ]  Pentesting SMB
- [ ]  Pentesting IMAP
- [ ]  Pentesting SNMP
- [ ]  Pentesting IRC
- [ ]  Pentesting Checkpoint firewall
- [ ]  Pentesting LDAP
- [ ]  Pentesting Docker
- [ ]  Pentesting kibana
- [ ]  Pentesting Databases
- [ ]  Pentesting Elasticsearch
- [ ]  Pentesting RabbitMQ
- [ ]  Pentesting Redis
- [ ]  Pentesting DHCPv6
- [ ]  pentesting EIGRP Attacks
- [ ]  pentesting GLBP & HSRP Attacks
- [ ]  pentesting Lateral VLAN Segmentation Bypass
- [ ]  pentesting Spoofing LLMNR, NBT-NS, mDNS/DNS and WPAD and Relay Attacks
- [ ]  Pentesting VNC
- [ ]  pentesting  SSDP and UPnP Devices with EvilSSDP