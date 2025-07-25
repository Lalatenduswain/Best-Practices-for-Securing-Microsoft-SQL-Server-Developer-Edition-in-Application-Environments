# Best Practices for Securing Microsoft SQL Server (Developer Edition) in Application Environments

**Version**: 1.1  
**Last Revised**: 25 July 2025  
**Prepared by**: Lalatendu Swain  

## Objective
This document provides comprehensive, step-by-step instructions to implement security best practices for Microsoft SQL Server Developer Edition. The goal is to protect sensitive data, restrict unauthorized access, and ensure a secure, production-like environment.

## Environment
- **Database Engine**: Microsoft SQL Server Developer Edition  
- **OS Platform**: Windows Server / Ubuntu with SQL Server (Linux)  
- **Deployment**: On-premises or AWS EC2  
- **Client Access**: Internal applications accessed via VPN or specific internal IP ranges  

---

## 1. Create Application-Specific Database User
**Purpose**: Avoid using high-privilege accounts (e.g., `sa`) for application operations to minimize security risks.  

**Steps**:  
1. Log in to SQL Server using SQL Server Management Studio (SSMS) or `sqlcmd` with an admin account.  
2. Create a dedicated login and user for the application:  
   ```sql
   CREATE LOGIN app_user WITH PASSWORD = 'ComplexP@ssw0rd2025!';
   USE your_database;
   CREATE USER app_user FOR LOGIN app_user;
   ```
3. Grant least-privilege permissions (e.g., `SELECT`, `INSERT`, `UPDATE`):  
   ```sql
   GRANT SELECT, INSERT, UPDATE ON dbo.YourTable TO app_user;
   ```
4. Optionally, assign the user to a custom database role for easier permission management:  
   ```sql
   CREATE ROLE AppRole;
   GRANT SELECT, INSERT, UPDATE ON dbo.YourTable TO AppRole;
   ALTER ROLE AppRole ADD MEMBER app_user;
   ```

**Best Practice**:  
- Use strong, unique passwords (minimum 12 characters, mixed case, numbers, and special characters).  
- Avoid granting `EXECUTE` on stored procedures unless necessary.  

---

## 2. Restrict Database Server Network Access
**Purpose**: Limit SQL Server exposure to trusted networks and prevent public access.  

**Steps**:  
1. **Windows Firewall (Windows Server)**:  
   - Block all external access to port 1433 (default SQL Server port).  
   - Create an inbound rule to allow connections only from:  
     - Application server IP (e.g., `192.168.50.3`).  
     - VPN IP range (e.g., `192.168.50.0/24`).  
   - Example PowerShell command to create a firewall rule:  
     ```powershell
     New-NetFirewallRule -DisplayName "Allow SQL Server" -Direction Inbound -Protocol TCP -LocalPort 1433 -RemoteAddress 192.168.50.3 -Action Allow
     ```

2. **SQL Server Configuration (Windows/Linux)**:  
   - Open **SQL Server Configuration Manager** > **SQL Server Network Configuration** > **Protocols for MSSQLSERVER**.  
   - Enable TCP/IP and configure:  
     - Disable `IPAll` to prevent binding to all interfaces.  
     - Enable specific IP addresses (e.g., `127.0.0.1`, `192.168.50.X`).  
   - Restart the SQL Server service:  
     ```bash
     sudo systemctl restart mssql-server  # Linux
     net stop MSSQLSERVER && net start MSSQLSERVER  # Windows
     ```

3. **AWS EC2 Security Groups**:  
   - Configure an EC2 security group to allow inbound traffic on port 1433 only from specific IPs or security groups.  
   - Example AWS CLI command:  
     ```bash
     aws ec2 authorize-security-group-ingress --group-id sg-12345678 --protocol tcp --port 1433 --cidr 192.168.50.0/24
     ```

**Best Practice**:  
- Regularly audit firewall rules and security groups to ensure only authorized IPs have access.  
- Use network segmentation to isolate the database server in a private subnet.  

---

## 3. Disable the `sa` Login
**Purpose**: Prevent misuse of the high-privilege `sa` account.  

**Steps**:  
1. Disable the `sa` login:  
   ```sql
   ALTER LOGIN sa DISABLE;
   ```
2. Create an alternative admin account with a strong password for emergency use:  
   ```sql
   CREATE LOGIN db_admin WITH PASSWORD = 'Adm1nP@ssw0rd2025!';
   ALTER SERVER ROLE sysadmin ADD MEMBER db_admin;
   ```

**Best Practice**:  
- Use Windows Authentication for admin accounts where possible to leverage Active Directory policies.  
- Store admin credentials in a secure vault (e.g., AWS Secrets Manager).  

---

## 4. Enforce Strong Authentication and Password Policies
**Purpose**: Strengthen authentication mechanisms to prevent unauthorized access.  

**Steps**:  
1. Enable password complexity and expiration for SQL logins:  
   ```sql
   ALTER LOGIN app_user WITH CHECK_POLICY = ON, CHECK_EXPIRATION = ON;
   ```
2. Configure SQL Server to use encrypted connections:  
   - Install a valid SSL/TLS certificate on the SQL Server.  
   - In **SQL Server Configuration Manager**, set **Force Encryption** to `Yes` under **SQL Native Client Configuration**.  
   - Restart the SQL Server service.  
3. Update application connection strings to enforce encryption:  
   ```plaintext
   Server=192.168.50.3;Database=your_database;User Id=app_user;Password=ComplexP@ssw0rd2025!;Encrypt=True;TrustServerCertificate=False;
   ```

**Best Practice**:  
- Use certificates from a trusted Certificate Authority (CA) instead of self-signed certificates.  
- Implement multi-factor authentication (MFA) for admin accounts via Active Directory if using Windows Authentication.  

---

## 5. Audit and Monitor Database Access
**Purpose**: Detect and respond to suspicious activity or unauthorized access attempts.  

**Steps**:  
1. Enable SQL Server Audit:  
   - Create a server audit to track failed logins and privilege escalations:  
     ```sql
     CREATE SERVER AUDIT Security_Audit
     TO FILE (FILEPATH = 'C:\AuditLogs\');
     ALTER SERVER AUDIT Security_Audit WITH (STATE = ON);
     CREATE SERVER AUDIT SPECIFICATION FailedLogins
     FOR SERVER AUDIT Security_Audit
     ADD (FAILED_LOGIN_GROUP);
     ALTER SERVER AUDIT SPECIFICATION FailedLogins WITH (STATE = ON);
     ```
2. Enable Extended Events for detailed login auditing:  
   ```sql
   CREATE EVENT SESSION LoginTracking ON SERVER
   ADD EVENT sqlserver.login (
       ACTION (sqlserver.client_app_name, sqlserver.client_hostname, sqlserver.username)
   )
   ADD TARGET package0.event_file (SET filename = 'C:\AuditLogs\LoginTracking.xel');
   ALTER EVENT SESSION LoginTracking ON SERVER STATE = START;
   ```
3. Regularly review audit logs for anomalies.

**Best Practice**:  
- Integrate audit logs with a SIEM (e.g., Splunk, AWS CloudWatch) for centralized monitoring.  
- Set up alerts for repeated failed login attempts or unusual access patterns.  

---

## 6. Disable Unused Features
**Purpose**: Reduce the attack surface by disabling unnecessary SQL Server features.  

**Steps**:  
1. Disable features like `xp_cmdshell`, CLR, and SQL Mail:  
   ```sql
   EXEC sp_configure 'show advanced options', 1;
   RECONFIGURE;
   EXEC sp_configure 'xp_cmdshell', 0;
   EXEC sp_configure 'clr enabled', 0;
   EXEC sp_configure 'Database Mail XPs', 0;
   RECONFIGURE;
   ```
2. Verify that only required services are running (e.g., disable SQL Server Browser if not needed).  

**Best Practice**:  
- Document any enabled features and their justification.  
- Periodically review enabled features during security audits.  

---

## 7. Prevent SQL Injection
**Purpose**: Mitigate SQL injection risks by avoiding dynamic SQL in application code.  

**Steps**:  
1. Use stored procedures or parameterized queries in application code:  
   ```sql
   -- Example Stored Procedure
   CREATE PROCEDURE GetUserData
       @UserID INT
   AS
   BEGIN
       SELECT * FROM dbo.Users WHERE UserID = @UserID;
   END;
   ```
2. Validate and sanitize all user inputs in the application layer.  
3. Use ORM frameworks (e.g., Entity Framework) that inherently parameterize queries.  

**Best Practice**:  
- Conduct regular code reviews to ensure no dynamic SQL is used.  
- Perform penetration testing to identify potential SQL injection vulnerabilities.  

---

## 8. Regularly Rotate Credentials
**Purpose**: Limit the impact of compromised credentials.  

**Steps**:  
1. Rotate `app_user` passwords every 90 days:  
   ```sql
   ALTER LOGIN app_user WITH PASSWORD = 'NewComplexP@ssw0rd2025!';
   ```
2. Store credentials in a secure vault (e.g., AWS Secrets Manager, Azure Key Vault).  
3. Restrict access to credentials to only authorized personnel.  

**Best Practice**:  
- Automate credential rotation using a secrets management tool.  
- Audit credential access logs regularly.  

---

## 9. Use VPN or Bastion Host for SQL Management
**Purpose**: Secure administrative access to SQL Server.  

**Steps**:  
1. Avoid exposing SQL Server Management Studio (SSMS) or other management tools over the internet.  
2. Configure a VPN or bastion host:  
   - Set up a bastion host in AWS with SSH access restricted to specific IPs.  
   - Example AWS CLI for bastion security group:  
     ```bash
     aws ec2 authorize-security-group-ingress --group-id sg-bastion-123 --protocol tcp --port 22 --cidr 192.168.50.0/24
     ```
3. Connect to SQL Server via the bastion host or VPN using SSMS or `sqlcmd`.  

**Best Practice**:  
- Use just-in-time (JIT) access for admin connections.  
- Log all administrative access for auditing.  

---

## 10. Enable Transparent Data Encryption (TDE)
**Purpose**: Protect data at rest to prevent unauthorized access to database files.  

**Steps**:  
1. Create a master key and certificate:  
   ```sql
   USE master;
   CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'MasterKeyP@ssw0rd2025!';
   CREATE CERTIFICATE TDE_Cert WITH SUBJECT = 'TDE Certificate';
   ```
2. Enable TDE on the target database:  
   ```sql
   USE your_database;
   CREATE DATABASE ENCRYPTION KEY
   WITH ALGORITHM = AES_256
   ENCRYPTION BY SERVER CERTIFICATE TDE_Cert;
   ALTER DATABASE your_database SET ENCRYPTION ON;
   ```
3. Back up the certificate and private key:  
   ```sql
   BACKUP CERTIFICATE TDE_Cert TO FILE = 'C:\Backups\TDE_Cert.cer'
   WITH PRIVATE KEY (FILE = 'C:\Backups\TDE_Cert.pvk', ENCRYPTION BY PASSWORD = 'BackupP@ssw0rd2025!');
   ```

**Best Practice**:  
- Store certificate backups in a secure location.  
- Regularly test TDE restore procedures.  

---

## 11. Regular Patching and Updates
**Purpose**: Mitigate vulnerabilities by keeping SQL Server and the host OS up to date.  

**Steps**:  
1. Apply the latest SQL Server cumulative updates and security patches.  
2. Update the host OS (Windows Server or Ubuntu) regularly.  
3. Monitor Microsoft’s security advisories for SQL Server vulnerabilities.  

**Best Practice**:  
- Test patches in a non-production environment before applying to production.  
- Schedule maintenance windows for applying updates.  

---

## 12. Backup and Recovery Planning
**Purpose**: Ensure data availability and integrity in case of incidents.  

**Steps**:  
1. Configure regular database backups:  
   ```sql
   BACKUP DATABASE your_database
   TO DISK = 'C:\Backups\your_database.bak'
   WITH COMPRESSION, INIT;
   ```
2. Encrypt backups:  
   ```sql
   BACKUP DATABASE your_database
   TO DISK = 'C:\Backups\your_database.bak'
   WITH COMPRESSION, ENCRYPTION (ALGORITHM = AES_256, SERVER CERTIFICATE = TDE_Cert);
   ```
3. Test restore procedures regularly:  
   ```sql
   RESTORE DATABASE your_database
   FROM DISK = 'C:\Backups\your_database.bak'
   WITH RECOVERY;
   ```

**Best Practice**:  
- Store backups in a secure, offsite location (e.g., AWS S3 with encryption).  
- Implement a backup retention policy (e.g., retain backups for 30 days).  

---

## Sample Connection String
```plaintext
Server=192.168.50.3;Database=your_database;User Id=app_user;Password=ComplexP@ssw0rd2025!;Encrypt=True;TrustServerCertificate=False;
```

---

## Notes
- **Do not share** `sa` or high-privilege credentials with developers or applications.  
- Ensure database ports (e.g., 1433) are not exposed externally.  
- Follow the **principle of least privilege** for all users and roles.  
- Conduct regular security assessments and penetration testing.  

---

## Attachments (Optional)
1. **DB User Creation SQL Script**: `create_app_user.sql`  
2. **Windows Firewall Inbound Rule Screenshot**: `firewall_rule.png`  
3. **SQL Server TCP/IP Bindings Screenshot**: `tcp_ip_config.png`  
4. **Sample Audit Logs**: `audit_log_sample.txt`
