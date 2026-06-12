# Troubleshooting

## Connection Issues

### Shell won't connect
- Verify attacker IP and port in `$CFG`
- Check firewall: `iptables -L -n`
- Ensure listener is running: `nc -lvnp 4444`
- Try different port (443, 8080, 53)

### Connection drops immediately
- Check `max_execution_time` in php.ini
- Shell sets it to 0, but some hosting ignores ini_set
- Use `nohup php phantom.php &` for persistence

### No output / blank shell
- `disable_functions` may block all exec methods
- Shell auto-detects and falls to MINIMAL mode
- Use `capabilities` command to check

## Mode Issues

### Stuck in MINIMAL mode
The target has all execution functions disabled. Options:
1. `fetch` modules to extend capabilities
2. `selfupgrade` to try loading full shell
3. Use PHP-native functions: `read`, `write`, `ls`, `php`

### NORMAL mode instead of FULL
Server has limited resources. Check:
- `memory_limit` < 32MB
- `upload_max_filesize` < 512KB
- `max_execution_time` too short
- `/tmp` not writable

## Execution Issues

### "All execution methods blocked"
All 8 bypass methods failed. The server has:
- All exec functions in `disable_functions`
- No FFI support
- No `mail()` or `putenv()`

Try: `php <expression>` for PHP-only operations

### Commands hang
- Use Ctrl+C to interrupt
- Background long commands: `background <cmd>`
- Check with `jobs`

## File Transfer Issues

### Upload fails
- Check disk space: `df -h`
- Check write permissions on target directory
- Ensure base64 is valid and ends with `--EOF--`

### Download truncated
- Large files may timeout
- Use `compress` first, then `download`
- Or use `exfil` for gzipped base64

## Pivoting Issues

### Port forward not working
- Check if port is already in use: `ports`
- Ensure target is reachable from compromised host
- Try different local port

### SOCKS proxy fails
- Port 1080 might be blocked
- Ensure `stream_socket_server` is available

## PHP Compatibility

### PHP 5.6
- No FFI support (PHP 7.4+)
- Some array functions behave differently
- Shell handles this automatically

### PHP 8.x
- Full compatibility
- FFI available as exec bypass
- Better performance
