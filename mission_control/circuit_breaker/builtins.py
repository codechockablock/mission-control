"""
Comprehensive built-in rule sets for the circuit breaker.

Each rule set targets a specific threat category. Patterns account for
common evasion techniques: quoting, variable expansion, escapes, unicode
tricks, newline injection, and argument reordering.
"""

from __future__ import annotations

from typing import Dict, List

from mission_control.circuit_breaker.rules import Rule, RuleCategory

# ---------------------------------------------------------------------------
# Filesystem Destruction
# ---------------------------------------------------------------------------

_FILESYSTEM_DESTRUCTION_RULES: List[Rule] = [
    Rule(
        name="rm_rf_root",
        category=RuleCategory.FILESYSTEM_DESTRUCTION,
        description="rm -rf / and variants targeting root filesystem",
        patterns=[
            r"""rm\s+[^;|&]*-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+/(?:\s|$|;|\||&)""",
            r"""rm\s+[^;|&]*-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*\s+/(?:\s|$|;|\||&)""",
            r"""rm\s+[^;|&]*--no-preserve-root""",
            r"""rm\s+[^;|&]*-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+/\*""",
        ],
        tool_types=["shell_exec", "bash", "terminal"],
    ),
    Rule(
        name="rm_rf_home",
        category=RuleCategory.FILESYSTEM_DESTRUCTION,
        description="Recursive force-delete of home directories",
        patterns=[
            r"""rm\s+[^;|&]*-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+~/""",
            r"""rm\s+[^;|&]*-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+\$HOME""",
            r"""rm\s+[^;|&]*-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+/home/""",
            r"""rm\s+[^;|&]*-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+/Users/""",
        ],
        tool_types=["shell_exec", "bash", "terminal"],
    ),
    Rule(
        name="rm_rf_system_dirs",
        category=RuleCategory.FILESYSTEM_DESTRUCTION,
        description="Recursive force-delete of system directories",
        patterns=[
            r"""rm\s+[^;|&]*-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+/etc(?:/|\s|$)""",
            r"""rm\s+[^;|&]*-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+/usr(?:/|\s|$)""",
            r"""rm\s+[^;|&]*-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+/var(?:/|\s|$)""",
            r"""rm\s+[^;|&]*-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+/bin(?:/|\s|$)""",
            r"""rm\s+[^;|&]*-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+/sbin(?:/|\s|$)""",
            r"""rm\s+[^;|&]*-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+/boot(?:/|\s|$)""",
            r"""rm\s+[^;|&]*-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+/lib(?:/|\s|$)""",
        ],
        tool_types=["shell_exec", "bash", "terminal"],
    ),
    Rule(
        name="mkfs_mounted",
        category=RuleCategory.FILESYSTEM_DESTRUCTION,
        description="Creating filesystem on device (potential data destruction)",
        patterns=[
            r"""mkfs(?:\.[a-z0-9]+)?\s+""",
        ],
        tool_types=["shell_exec", "bash", "terminal"],
    ),
    Rule(
        name="dd_zero_device",
        category=RuleCategory.FILESYSTEM_DESTRUCTION,
        description="dd writing zeros/random to block devices",
        patterns=[
            r"""dd\s+.*if=/dev/(?:zero|urandom|random).*of=/dev/[a-z]""",
            r"""dd\s+.*of=/dev/[a-z].*if=/dev/(?:zero|urandom|random)""",
        ],
        tool_types=["shell_exec", "bash", "terminal"],
    ),
    Rule(
        name="format_disk_windows",
        category=RuleCategory.FILESYSTEM_DESTRUCTION,
        description="Windows format command on drives",
        patterns=[
            r"""(?i)format\s+[a-zA-Z]:\s*""",
        ],
        tool_types=["shell_exec", "bash", "terminal", "cmd", "powershell"],
    ),
    Rule(
        name="shutil_rmtree_system",
        category=RuleCategory.FILESYSTEM_DESTRUCTION,
        description="Python shutil.rmtree on system/home paths",
        patterns=[
            r"""shutil\.rmtree\s*\(\s*['"]/(etc|usr|var|bin|sbin|boot|lib|home|Users)""",
            r"""shutil\.rmtree\s*\(\s*['"]/\s*['"]""",
            r"""shutil\.rmtree\s*\(\s*['"]~""",
        ],
        tool_types=[],
    ),
]

# ---------------------------------------------------------------------------
# Credential Exfiltration
# ---------------------------------------------------------------------------

_CREDENTIAL_EXFILTRATION_RULES: List[Rule] = [
    Rule(
        name="credential_pipe_to_external",
        category=RuleCategory.CREDENTIAL_EXFILTRATION,
        description="Private key content piped to external HTTP endpoint",
        patterns=[
            r"""cat\s+.*\.ssh/.*\|.*(?:curl|wget|nc|ncat)""",
            r"""(?:curl|wget)\s+.*-[dX]\s+.*(?:id_rsa|id_ed25519|id_ecdsa|authorized_keys)""",
            r"""(?:curl|wget)\s+.*--data.*(?:id_rsa|id_ed25519|id_ecdsa)""",
        ],
        tool_types=["shell_exec", "bash", "terminal"],
    ),
    Rule(
        name="base64_credential_exfil",
        category=RuleCategory.CREDENTIAL_EXFILTRATION,
        description="Base64-encoding credentials and sending externally",
        patterns=[
            r"""base64\s+.*(?:\.ssh|\.aws|\.gnupg|credentials|\.env|secret).*\|.*(?:curl|wget|nc)""",
            r"""cat\s+.*(?:\.ssh|\.aws|\.gnupg|credentials|\.env).*\|\s*base64.*\|\s*(?:curl|wget|nc)""",
            r"""openssl\s+.*enc.*(?:\.ssh|\.aws|credentials).*\|.*(?:curl|wget|nc)""",
        ],
        tool_types=["shell_exec", "bash", "terminal"],
    ),
    Rule(
        name="secrets_to_world_readable",
        category=RuleCategory.CREDENTIAL_EXFILTRATION,
        description="Writing secrets to world-readable locations",
        patterns=[
            r"""cp\s+.*(?:\.ssh|\.aws|\.gnupg|\.env)\s+.*/tmp/""",
            r"""cp\s+.*(?:\.ssh|\.aws|\.gnupg|\.env)\s+.*/var/tmp/""",
            r"""mv\s+.*(?:\.ssh|\.aws|\.gnupg|\.env)\s+.*/tmp/""",
            r"""cat\s+.*(?:id_rsa|id_ed25519|\.env|credentials)\s*>\s*/tmp/""",
        ],
        tool_types=["shell_exec", "bash", "terminal"],
    ),
    Rule(
        name="ssh_key_copy_network",
        category=RuleCategory.CREDENTIAL_EXFILTRATION,
        description="Copying SSH/AWS/GPG dirs to network locations",
        patterns=[
            r"""(?:scp|rsync)\s+.*(?:\.ssh|\.aws|\.gnupg)/?\s+.*@""",
            r"""tar\s+.*(?:\.ssh|\.aws|\.gnupg).*\|.*(?:curl|wget|nc|ssh)""",
        ],
        tool_types=["shell_exec", "bash", "terminal"],
    ),
    Rule(
        name="env_secrets_exfil",
        category=RuleCategory.CREDENTIAL_EXFILTRATION,
        description="Exfiltrating environment variables containing secrets",
        patterns=[
            r"""env\s*\|.*(?:curl|wget|nc)""",
            r"""printenv.*\|.*(?:curl|wget|nc)""",
            r"""echo\s+\$(?:AWS_SECRET|DATABASE_URL|API_KEY|TOKEN|PASSWORD|SECRET).*\|.*(?:curl|wget|nc)""",
        ],
        tool_types=["shell_exec", "bash", "terminal"],
    ),
    Rule(
        name="credential_file_read_exfil",
        category=RuleCategory.CREDENTIAL_EXFILTRATION,
        description="Reading credential files and sending to network",
        patterns=[
            r"""cat\s+.*(?:/etc/shadow|/etc/passwd).*\|.*(?:curl|wget|nc)""",
            r"""cat\s+.*\.(?:env|netrc|pgpass).*\|.*(?:curl|wget|nc)""",
        ],
        tool_types=["shell_exec", "bash", "terminal"],
    ),
    Rule(
        name="python_credential_exfil",
        category=RuleCategory.CREDENTIAL_EXFILTRATION,
        description="Python code reading credentials and sending externally",
        patterns=[
            r"""(?:requests|urllib|http\.client).*(?:\.ssh|\.aws|\.env|credentials|id_rsa)""",
            r"""open\s*\(.*(?:id_rsa|\.env|credentials|\.aws).*\).*(?:requests|urllib|socket)""",
        ],
        tool_types=[],
    ),
]

# ---------------------------------------------------------------------------
# Privilege Escalation
# ---------------------------------------------------------------------------

_PRIVILEGE_ESCALATION_RULES: List[Rule] = [
    Rule(
        name="modify_authorized_keys",
        category=RuleCategory.PRIVILEGE_ESCALATION,
        description="Modifying SSH authorized_keys file",
        patterns=[
            r"""(?:echo|cat|tee|printf).*>>?\s*.*authorized_keys""",
            r"""(?:echo|cat|tee|printf).*>>?\s*.*\.ssh/authorized_keys""",
            r"""\|\s*tee\s+.*authorized_keys""",
            r"""sed\s+.*authorized_keys""",
        ],
        tool_types=["shell_exec", "bash", "terminal"],
    ),
    Rule(
        name="modify_sudoers",
        category=RuleCategory.PRIVILEGE_ESCALATION,
        description="Modifying sudoers file",
        patterns=[
            r"""(?:echo|cat|tee|printf).*>>?\s*.*/etc/sudoers""",
            r"""(?:echo|cat|tee|printf).*>>?\s*.*/etc/sudoers\.d/""",
            r"""visudo""",
            r"""sed\s+.*(?:/etc/sudoers|sudoers\.d/)""",
        ],
        tool_types=["shell_exec", "bash", "terminal"],
    ),
    Rule(
        name="modify_passwd",
        category=RuleCategory.PRIVILEGE_ESCALATION,
        description="Modifying /etc/passwd or /etc/shadow",
        patterns=[
            r"""(?:echo|cat|tee|printf).*>>?\s*/etc/(?:passwd|shadow)""",
            r"""sed\s+.*(?:-i|--in-place).*(?:/etc/passwd|/etc/shadow)""",
            r"""chpasswd""",
            r"""usermod\s+.*(?:-p|--password)""",
        ],
        tool_types=["shell_exec", "bash", "terminal"],
    ),
    Rule(
        name="chmod_777_sensitive",
        category=RuleCategory.PRIVILEGE_ESCALATION,
        description="chmod 777 on sensitive directories",
        patterns=[
            r"""chmod\s+[^;|&]*777\s+/""",
            r"""chmod\s+[^;|&]*-R\s+777""",
            r"""chmod\s+[^;|&]*a\+rwx\s+/""",
        ],
        tool_types=["shell_exec", "bash", "terminal"],
    ),
    Rule(
        name="setuid_manipulation",
        category=RuleCategory.PRIVILEGE_ESCALATION,
        description="Setting SUID/SGID bits on files",
        patterns=[
            r"""chmod\s+[^;|&]*[ugo]\+s\s""",
            r"""chmod\s+[^;|&]*[4267][0-7]{3}\s""",
        ],
        tool_types=["shell_exec", "bash", "terminal"],
    ),
    Rule(
        name="docker_socket_escape",
        category=RuleCategory.PRIVILEGE_ESCALATION,
        description="Docker socket mounting for container escape",
        patterns=[
            r"""docker\s+run\s+.*-v\s+/var/run/docker\.sock""",
            r"""docker\s+run\s+.*--privileged""",
            r"""-v\s+/:/(?:host|mnt|rootfs)""",
        ],
        tool_types=["shell_exec", "bash", "terminal"],
    ),
    Rule(
        name="useradd_root",
        category=RuleCategory.PRIVILEGE_ESCALATION,
        description="Creating users with root-level access",
        patterns=[
            r"""useradd\s+.*(?:-o\s+-u\s*0|-G\s*(?:root|sudo|wheel))""",
            r"""usermod\s+.*-aG\s*(?:root|sudo|wheel)""",
        ],
        tool_types=["shell_exec", "bash", "terminal"],
    ),
]

# ---------------------------------------------------------------------------
# Data Exfiltration
# ---------------------------------------------------------------------------

_DATA_EXFILTRATION_RULES: List[Rule] = [
    Rule(
        name="bulk_tar_curl",
        category=RuleCategory.DATA_EXFILTRATION,
        description="Bulk file archival piped to external transfer",
        patterns=[
            r"""tar\s+.*\|.*(?:curl|wget|nc|ssh|scp)""",
            r"""zip\s+.*\|.*(?:curl|wget|nc)""",
            r"""tar\s+[^;|&]*-[a-zA-Z]*c[a-zA-Z]*.*\|.*(?:curl|wget|nc)""",
        ],
        tool_types=["shell_exec", "bash", "terminal"],
    ),
    Rule(
        name="database_dump_exfil",
        category=RuleCategory.DATA_EXFILTRATION,
        description="Database dumps piped to network commands",
        patterns=[
            r"""(?:mysqldump|pg_dump|mongodump|sqlite3\s+.*\.dump).*\|.*(?:curl|wget|nc|ssh|scp)""",
            r"""(?:mysqldump|pg_dump|mongodump).*>\s*/tmp/""",
        ],
        tool_types=["shell_exec", "bash", "terminal"],
    ),
    Rule(
        name="large_upload_unknown",
        category=RuleCategory.DATA_EXFILTRATION,
        description="Large file uploads to unknown endpoints",
        patterns=[
            r"""curl\s+.*-[TF]\s+.*(?:\.sql|\.db|\.csv|\.tar|\.zip|\.gz|\.bak)""",
            r"""curl\s+.*--upload-file\s+""",
            r"""wget\s+.*--post-file\s+""",
        ],
        tool_types=["shell_exec", "bash", "terminal"],
    ),
    Rule(
        name="find_pipe_exfil",
        category=RuleCategory.DATA_EXFILTRATION,
        description="Find command piped to archival and exfiltration",
        patterns=[
            r"""find\s+/.*\|.*(?:tar|zip|cpio).*\|.*(?:curl|wget|nc|ssh)""",
            r"""find\s+/.*-exec.*(?:curl|wget|nc|scp)""",
        ],
        tool_types=["shell_exec", "bash", "terminal"],
    ),
    Rule(
        name="dns_tunnel_exfil",
        category=RuleCategory.DATA_EXFILTRATION,
        description="DNS tunneling for data exfiltration",
        patterns=[
            r"""(?:dig|nslookup|host)\s+.*\$\(""",
            r"""xxd\s+.*\|.*(?:dig|nslookup)""",
        ],
        tool_types=["shell_exec", "bash", "terminal"],
    ),
]

# ---------------------------------------------------------------------------
# System Modification
# ---------------------------------------------------------------------------

_SYSTEM_MODIFICATION_RULES: List[Rule] = [
    Rule(
        name="modify_crontab",
        category=RuleCategory.SYSTEM_MODIFICATION,
        description="Modifying crontab entries",
        patterns=[
            r"""crontab\s+(?!-l)""",
            r"""(?:echo|cat|tee|printf).*>>?\s*/(?:etc/cron|var/spool/cron)""",
        ],
        tool_types=["shell_exec", "bash", "terminal"],
    ),
    Rule(
        name="modify_systemd",
        category=RuleCategory.SYSTEM_MODIFICATION,
        description="Modifying systemd service units",
        patterns=[
            r"""(?:echo|cat|tee|printf).*>>?\s*/etc/systemd/""",
            r"""systemctl\s+(?:enable|mask|unmask|edit|link)\s+""",
            r"""cp\s+.*\.service\s+/etc/systemd/""",
        ],
        tool_types=["shell_exec", "bash", "terminal"],
    ),
    Rule(
        name="modify_launchd",
        category=RuleCategory.SYSTEM_MODIFICATION,
        description="Modifying macOS launchd plists",
        patterns=[
            r"""(?:echo|cat|tee|printf).*>>?\s*/Library/Launch(?:Daemons|Agents)/""",
            r"""cp\s+.*\.plist\s+/Library/Launch(?:Daemons|Agents)/""",
            r"""launchctl\s+(?:load|bootstrap|enable)\s+""",
        ],
        tool_types=["shell_exec", "bash", "terminal"],
    ),
    Rule(
        name="kernel_module_ops",
        category=RuleCategory.SYSTEM_MODIFICATION,
        description="Kernel module loading/unloading",
        patterns=[
            r"""(?:insmod|modprobe|rmmod)\s+""",
            r"""kextload\s+""",
        ],
        tool_types=["shell_exec", "bash", "terminal"],
    ),
    Rule(
        name="firewall_modification",
        category=RuleCategory.SYSTEM_MODIFICATION,
        description="Modifying firewall rules",
        patterns=[
            r"""iptables\s+(?:-[AIDRF]|--(?:append|insert|delete|replace|flush))\s+""",
            r"""ufw\s+(?:allow|deny|delete|reset|disable)\s*""",
            r"""nft\s+(?:add|delete|flush)\s+""",
            r"""pfctl\s+(?:-[ef]|--enable|--disable)\s*""",
        ],
        tool_types=["shell_exec", "bash", "terminal"],
    ),
    Rule(
        name="package_manager_system",
        category=RuleCategory.SYSTEM_MODIFICATION,
        description="Package manager ops that could replace system binaries",
        patterns=[
            r"""(?:apt|apt-get|yum|dnf)\s+install\s+.*--(?:force|allow)""",
            r"""dpkg\s+--force.*-i\s+""",
            r"""rpm\s+--(?:force|nodeps).*-[iU]\s+""",
        ],
        tool_types=["shell_exec", "bash", "terminal"],
    ),
    Rule(
        name="hosts_file_modification",
        category=RuleCategory.SYSTEM_MODIFICATION,
        description="Modifying /etc/hosts or DNS resolver config",
        patterns=[
            r"""(?:echo|cat|tee|printf).*>>?\s*/etc/hosts(?:\s|$)""",
            r"""(?:echo|cat|tee|printf).*>>?\s*/etc/resolv\.conf""",
            r"""sed\s+.*(?:-i|--in-place).*/etc/hosts""",
        ],
        tool_types=["shell_exec", "bash", "terminal"],
    ),
    Rule(
        name="shell_profile_modification",
        category=RuleCategory.SYSTEM_MODIFICATION,
        description="Modifying shell profiles for persistence",
        patterns=[
            r"""(?:echo|cat|tee|printf).*>>?\s*.*(?:\.bashrc|\.bash_profile|\.zshrc|\.profile|/etc/profile)""",
        ],
        tool_types=["shell_exec", "bash", "terminal"],
    ),
]

# ---------------------------------------------------------------------------
# Network Abuse
# ---------------------------------------------------------------------------

_NETWORK_ABUSE_RULES: List[Rule] = [
    Rule(
        name="reverse_shell",
        category=RuleCategory.NETWORK_ABUSE,
        description="Reverse shell establishment",
        patterns=[
            r"""(?:bash|sh|zsh)\s+.*-[ci]\s+.*(?:/dev/tcp|/dev/udp)/""",
            r"""nc\s+.*-e\s+(?:/bin/(?:ba)?sh|cmd)""",
            r"""ncat\s+.*--exec\s+""",
            r"""python[23]?\s+.*-c\s+.*(?:socket|subprocess).*(?:connect|shell)""",
            r"""perl\s+.*-e\s+.*socket.*INET""",
            r"""mkfifo\s+.*\|\s*(?:/bin/(?:ba)?sh|sh)""",
        ],
        tool_types=["shell_exec", "bash", "terminal"],
    ),
    Rule(
        name="port_scan",
        category=RuleCategory.NETWORK_ABUSE,
        description="Network port scanning",
        patterns=[
            r"""nmap\s+""",
            r"""masscan\s+""",
        ],
        tool_types=["shell_exec", "bash", "terminal"],
    ),
]

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

DEFAULT_RULES: List[Rule] = (
    _FILESYSTEM_DESTRUCTION_RULES
    + _CREDENTIAL_EXFILTRATION_RULES
    + _PRIVILEGE_ESCALATION_RULES
    + _DATA_EXFILTRATION_RULES
    + _SYSTEM_MODIFICATION_RULES
    + _NETWORK_ABUSE_RULES
)

DOMAIN_RULES: Dict[str, List[Rule]] = {
    "sysadmin": DEFAULT_RULES,
    "data_engineering": (
        _FILESYSTEM_DESTRUCTION_RULES
        + _CREDENTIAL_EXFILTRATION_RULES
        + _DATA_EXFILTRATION_RULES
    ),
    "customer_service": (
        _CREDENTIAL_EXFILTRATION_RULES
        + _DATA_EXFILTRATION_RULES
        + _NETWORK_ABUSE_RULES
    ),
    "financial": DEFAULT_RULES,
}


def get_default_rules() -> List[Rule]:
    """Return the full default rule set."""
    return list(DEFAULT_RULES)


def get_domain_rules(domain: str) -> List[Rule]:
    """Return rules for a specific domain."""
    if domain not in DOMAIN_RULES:
        raise ValueError(f"Unknown domain: {domain!r}. Available: {list(DOMAIN_RULES.keys())}")
    return list(DOMAIN_RULES[domain])
