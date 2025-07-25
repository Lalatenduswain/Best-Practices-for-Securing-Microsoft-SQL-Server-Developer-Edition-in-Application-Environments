# Best Practices for Securing Microsoft SQL Server (Developer Edition) on Ubuntu 24.04

**Version**: 1.2  
**Last Revised**: 25 July 2025  
**Prepared by**: Lalatendu Swain  

## Objective
This document provides step-by-step instructions to secure **Microsoft SQL Server 2022 Developer Edition (16.0.4195.2)** on **Ubuntu 24.04.2 LTS**, ensuring protection of sensitive data and restricting unauthorized access in a production-like environment.

## Environment
- **Database Engine**: Microsoft SQL Server 2022 Developer Edition (16.0.4195.2)  
- **OS Platform**: Ubuntu 24.04.2 LTS  
- **Deployment**: On-premises or AWS EC2  
- **Client Access**: Internal applications via VPN or specific internal IP ranges  

---

## 1. Create Application-Specific Database User
**Purpose**: Use least-privilege accounts for application access instead of high-privilege accounts like `sa`.  

**Steps**:  
1. Connect to SQL Server using `sqlcmd` or SQL Server Management Studio (SSMS) with an admin account:  
   ```bash
   sqlcmd -S localhost -U sa -P 'YourStrongSAPassword'
   ```
2. Create a dedicated login and user:  
   ```sql
   CREATE LOGIN app_user WITH PASSWORD = 'ComplexP@ssw0rd2025!';
   USE your_database;
   CREATE USER app_user FOR LOGIN app_user;
   ```
3. Grant minimal permissions (e.g., `SELECT`, `INSERT`, `UPDATE`):  
   ```sql
   GRANT SELECT, INSERT, UPDATE ON dbo.YourTable TO app_user;
   ```
4. Optionally, use a database role for scalable permission management:  
   ```sql
   CREATE ROLE AppRole;
   GRANT SELECT, INSERT, UPDATE ON dbo.YourTable TO AppRole;
   ALTER ROLE AppRole ADD MEMBER app_user;
   ```

**Best Practice**:  
- Use strong passwords (minimum 12 characters, mixed case, numbers, special characters).  
- Avoid granting `EXECUTE` permissions unless necessary.  

---

## 2. Restrict Database Server Network Access
**Purpose**: Limit SQL Server exposure to trusted IPs, preventing public access.  

**Steps**:  
1. **Configure UFW (Uncomplicated Firewall)**:  
   - Block all inbound traffic to port 1433 (default SQL Server port):  
     ```bash
     sudo ufw deny 1433
     ```
   - Allow specific IPs (e.g., application server or VPN range):  
     ```bash
     sudo ufw allow from 192.168.50.3 to any port 1433
     sudo ufw allow from 192.168.50.0/24 to any port 1433
     ```
   - Enable UFW if not already enabled:  
     ```bash
     sudo ufw enable
     ```
2. **SQL Server Network Configuration**:  
   - Edit the SQL Server configuration file to bind to specific IPs:  
     ```bash
     sudo nano /var/opt/mssql/mssql.conf
     ```
     Add or modify:  
     ```ini
     [network]
     tcpport = 1433
     ipaddress = 127.0.0.1,192.168.50.3
     ```
   - Restart SQL Server:  
     ```bash
     sudo systemctl restart mssql-server
     ```
3. **AWS EC2 Security Groups (if applicable)**:  
   - Restrict inbound traffic on port 1433 to specific IPs or security groups:  
     ```bash
     aws ec2 authorize-security-group-ingress --group-id sg-12345678 --protocol tcp --port 1433 --cidr 192.168.50.0/24
     ```

**Best Practice**:  
- Use network segmentation (e.g., private subnet in AWS VPC).  
- Regularly audit UFW rules and security groups.  

---

## 3. Disable the `sa` Login
**Purpose**: Reduce risk by disabling the default `sa` account.  

**Steps**:  
1. Disable the `sa` login:  
   ```sql
   ALTER LOGIN sa DISABLE;
   ```
2. Create an alternative admin account:  
   ```sql
   CREATE LOGIN db_admin WITH PASSWORD = 'Adm1nP@ssw0rd2025!';
   ALTER SERVER ROLE sysadmin ADD MEMBER db_admin;
   ```

**Best Practice**:  
- Store admin credentials in a secure vault (e.g., AWS Secrets Manager).  
- Use group-based access control if integrating with an identity provider.  

---

## 4. Enforce Strong Authentication and Password Policies
**Purpose**: Strengthen authentication to prevent unauthorized access.  

**Steps**:  
1. Enable password complexity and expiration:  
   ```sql
   ALTER LOGIN app_user WITH CHECK_POLICY = ON, CHECK_EXPIRATION = ON;
   ```
2. Configure encrypted connections:  
   - Generate or install an SSL/TLS certificate:  
     ```bash
     sudo openssl req -x509 -nodes -newkey rsa:2048 -keyout /var/opt/mssql/mssql.key -out /var/opt/mssql/mssql.pem -days 365
     sudo chown mssql:mssql /var/opt/mssql/mssql.key /var/opt/mssql/mssql.pem
     sudo chmod 600 /var/opt/mssql/mssql.key /var/opt/mssql/mssql.pem
     ```
   - Update `mssql.conf` to enable encryption:  
     ```ini
     [network]
     tcpcert = /var/opt/mssql/mssql.pem
     forceencryption = true
     ```
   - Restart SQL Server:  
     ```bash
     sudo systemctl restart mssql-server
     ```
3. Update the application connection string:  
   ```plaintext
   Server=192.168.50.3;Database=your_database;User Id=app_user;Password=ComplexP@ssw0rd2025!;Encrypt=True;TrustServerCertificate=False;
   ```

**Best Practice**:  
- Use certificates from a trusted CA for production.  
- Regularly rotate certificates and monitor expiration.  

---

## 5. Audit and Monitor Database Access
**Purpose**: Track access attempts to detect suspicious activity.  

**Steps**:  
1. Enable SQL Server Audit:  
   ```sql
   CREATE SERVER AUDIT Security_Audit
   TO FILE (FILEPATH = '/var/opt/mssql/audit/', MAXSIZE = 100 MB);
   ALTER SERVER AUDIT Security_Audit WITH (STATE = ON);
   CREATE SERVER AUDIT SPECIFICATION FailedLogins
   FOR SERVER AUDIT Security_Audit
   ADD (FAILED_LOGIN_GROUP);
   ALTER SERVER AUDIT SPECIFICATION FailedLogins WITH (STATE = ON);
   ```
2. Enable Extended Events for login tracking:  
   ```sql
   CREATE EVENT SESSION LoginTracking ON SERVER
   ADD EVENT sqlserver.login (
       ACTION (sqlserver.client_app_name, sqlserver.client_hostname, sqlserver.username)
   )
   ADD TARGET package0.event_file (SET filename = '/var/opt/mssql/audit/LoginTracking.xel');
   ALTER EVENT SESSION LoginTracking ON SERVER STATE = START;
   ```
3. Monitor audit logs:  
   ```bash
   sudo tail -f /var/opt/mssql/audit/*.sqlaudit
   ```

**Best Practice**:  
- Forward logs to a SIEM (e.g., ELK Stack, AWS CloudWatch) for centralized analysis.  
- Set up alerts for repeated failed logins or privilege escalations.  

---

## 6. Disable Unused Features
**Purpose**: Minimize the attack surface by disabling unnecessary features.  

**Steps**:  
1. Disable features like `xp_cmdshell`, CLR, and Database Mail:  
   ```sql
   EXEC sp_configure 'show advanced options', 1;
   RECONFIGURE;
   EXEC sp_configure 'xp_cmdshell', 0;
   EXEC sp_configure 'clr enabled', 0;
   EXEC sp_configure 'Database Mail XPs', 0;
   RECONFIGURE;
   ```
2. Disable SQL Server Browser service if not needed:  
   ```bash
   sudo systemctl disable mssql-server-browser
   sudo systemctl stop mssql-server-browser
   ```

**Best Practice**:  
- Document enabled features and their purpose.  
- Periodically review configurations during security audits.  

---

## 7. Prevent SQL Injection
**Purpose**: Protect against SQL injection vulnerabilities.  

**Steps**:  
1. Use stored procedures or parameterized queries:  
   ```sql
   CREATE PROCEDURE GetUserData
       @UserID INT
   AS
   BEGIN
       SELECT * FROM dbo.Users WHERE UserID = @UserID;
   END;
   ```
2. Validate and sanitize inputs in the application layer.  
3. Use ORM frameworks (e.g., Entity Framework Core) for safe query execution.  

**Best Practice**:  
- Conduct regular code reviews and vulnerability scans.  
- Use tools like OWASP ZAP for penetration testing.  

---

## 8. Regularly Rotate Credentials
**Purpose**: Reduce the risk of compromised credentials.  

**Steps**:  
1. Rotate `app_user` passwords every 90 days:  
   ```sql
   ALTER LOGIN app_user WITH PASSWORD = 'NewComplexP@ssw0rd2025!';
   ```
2. Store credentials in a secure vault (e.g., AWS Secrets Manager):  
   ```bash
   aws secretsmanager create-secret --name sql_app_user --secret-string '{"username":"app_user","password":"ComplexP@ssw0rd2025!"}'
   ```
3. Restrict access to credentials to authorized users only.  

**Best Practice**:  
- Automate rotation using AWS Lambda or similar tools.  
- Audit credential access logs regularly.  

---

## 9. Use VPN or Bastion Host for SQL Management
**Purpose**: Secure administrative access to SQL Server.  

**Steps**:  
1. Avoid exposing SQL Server or SSMS over the internet.  
2. Set up a VPN (e.g., OpenVPN) or bastion host:  
   - Configure a bastion host with SSH access:  
     ```bash
     sudo apt update
     sudo apt install openssh-server
     sudo nano /etc/ssh/sshd_config
     # Restrict to specific IPs
     AllowUsers user@192.168.50.3
     sudo systemctl restart sshd
     ```
3. Connect to SQL Server via the bastion host or VPN using `sqlcmd` or SSMS.  

**Best Practice**:  
- Implement just-in-time (JIT) access for admins.  
- Log all SSH and administrative access.  

---

## 10. Enable Transparent Data Encryption (TDE)
**Purpose**: Protect data at rest from unauthorized access to database files.  

**Steps**:  
1. Create a master key and certificate:  
   ```sql
   USE master;
   CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'MasterKeyP@ssw0rd2025!';
   CREATE CERTIFICATE TDE_Cert WITH SUBJECT = 'TDE Certificate';
   ```
2. Enable TDE on the database:  
   ```sql
   USE your_database;
   CREATE DATABASE ENCRYPTION KEY
   WITH ALGORITHM = AES_256
   ENCRYPTION BY SERVER CERTIFICATE TDE_Cert;
   ALTER DATABASE your_database SET ENCRYPTION ON;
   ```
3. Back up the certificate:  
   ```sql
   BACKUP CERTIFICATE TDE_Cert TO FILE = '/var/opt/mssql/backups/TDE_Cert.cer'
   WITH PRIVATE KEY (FILE = '/var/opt/mssql/backups/TDE_Cert.pvk', ENCRYPTION BY PASSWORD = 'BackupP@ssw0rd2025!');
   ```
4. Secure the backup files:  
   ```bash
   sudo chown mssql:mssql /var/opt/mssql/backups/TDE_Cert.*
   sudo chmod 600 /var/opt/mssql/backups/TDE_Cert.*
   ```

**Best Practice**:  
- Store certificate backups in a secure, offsite location.  
- Test restore procedures periodically.  

---

## 11. Regular Patching and Updates
**Purpose**: Address vulnerabilities in SQL Server and Ubuntu.  

**Steps**:  
1. Update SQL Server with the latest cumulative updates:  
   ```bash
   sudo apt update
   sudo apt install mssql-server
   ```
2. Keep Ubuntu up to date:  
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```
3. Monitor Microsoft’s security advisories for SQL Server 2022.  

**Best Practice**:  
- Test updates in a staging environment.  
- Schedule maintenance windows for patching.  

---

## 12. Backup and Recovery Planning
**Purpose**: Ensure data availability and integrity.  

**Steps**:  
1. Configure regular encrypted backups:  
   ```sql
   BACKUP DATABASE your_database
   TO DISK = '/var/opt/mssql/backups/your_database.bak'
   WITH COMPRESSION, ENCRYPTION (ALGORITHM = AES_256, SERVER CERTIFICATE = TDE_Cert);
   ```
2. Test restore procedures:  
   ```sql
   RESTORE DATABASE your_database
   FROM DISK = '/var/opt/mssql/backups/your_database.bak'
   WITH RECOVERY;
   ```
3. Secure backup files:  
   ```bash
   sudo chown mssql:mssql /var/opt/mssql/backups/your_database.bak
   sudo chmod 600 /var/opt/mssql/backups/your_database.bak
   ```

**Best Practice**:  
- Store backups in a secure, offsite location (e.g., AWS S3 with server-side encryption).  
- Implement a retention policy (e.g., 30 days).  

---

## Sample Connection String
```plaintext
Server=192.168.50.3;Database=your_database;User Id=app_user;Password=ComplexP@ssw0rd2025!;Encrypt=True;TrustServerCertificate=False;
```

---

## Notes
- **Do not share** `sa` or admin credentials with developers or applications.  
- Ensure port 1433 is not exposed publicly.  
- Follow the **principle of least privilege** for all users and roles.  
- Conduct regular security assessments, including vulnerability scans and penetration testing.  
- Use tools like `fail2ban` to protect against brute-force attacks on SSH or SQL Server.  

---

## Attachments (Optional)
1. **DB User Creation Script**: `create_app_user.sql`  
2. **UFW Configuration Screenshot**: `ufw_rules.png`  
3. **SQL Server Network Configuration**: `mssql_conf_screenshot.png`  
4. **Sample Audit Logs**: `audit_log_sample.txt`