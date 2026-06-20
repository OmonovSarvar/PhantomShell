"""Network discovery tracker -- maps hosts and pivots discovered by agents."""

import logging
import re
import threading
import uuid

log = logging.getLogger("phantom.c2.netmap")


class NetworkMap:
    """Thread-safe network topology tracker with graph export."""

    def __init__(self):
        self._hosts: dict[str, dict] = {}
        self._edges: list[dict] = []
        self._lock = threading.Lock()

    def add_host(self, ip: str, hostname: str = "", os: str = "",
                 ports: list[int] | None = None,
                 status: str = "alive") -> str:
        """Add or merge a host entry.  Returns host_id."""
        with self._lock:
            # If the IP already exists, merge data instead of duplicating
            for hid, h in self._hosts.items():
                if h["ip"] == ip:
                    if hostname:
                        h["hostname"] = hostname
                    if os:
                        h["os"] = os
                    if ports:
                        existing = set(h.get("ports", []))
                        existing.update(ports)
                        h["ports"] = sorted(existing)
                    h["status"] = status
                    return hid

            host_id = f"host-{uuid.uuid4().hex[:8]}"
            self._hosts[host_id] = {
                "id": host_id,
                "ip": ip,
                "hostname": hostname,
                "os": os,
                "ports": sorted(ports) if ports else [],
                "status": status,
            }
        log.info(f"[+] Host discovered: {ip} ({hostname})")
        return host_id

    def update_host(self, host_id: str, **kwargs) -> bool:
        with self._lock:
            if host_id not in self._hosts:
                return False
            for key, val in kwargs.items():
                if key in self._hosts[host_id] and key != "id":
                    self._hosts[host_id][key] = val
            return True

    def add_edge(self, source_ip: str, dest_ip: str,
                 edge_type: str = "scan",
                 label: str = "") -> dict:
        """Record a relationship between two hosts.

        edge_type: pivot | scan | lateral
        """
        edge = {
            "source": source_ip,
            "target": dest_ip,
            "type": edge_type,
            "label": label,
        }
        with self._lock:
            # Deduplicate edges of the same type between the same pair
            for existing in self._edges:
                if (existing["source"] == source_ip
                        and existing["target"] == dest_ip
                        and existing["type"] == edge_type):
                    existing["label"] = label or existing["label"]
                    return existing
            self._edges.append(edge)
        log.info(f"[+] Edge: {source_ip} --[{edge_type}]--> {dest_ip}")
        return edge

    def get_hosts(self) -> list[dict]:
        with self._lock:
            return list(self._hosts.values())

    def get_graph(self) -> dict:
        """Return the full graph in a format ready for vis.js / d3."""
        with self._lock:
            nodes = []
            for h in self._hosts.values():
                nodes.append({
                    "id": h["ip"],
                    "label": h["hostname"] or h["ip"],
                    "ip": h["ip"],
                    "os": h["os"],
                    "ports": h["ports"],
                    "status": h["status"],
                })
            edges = [dict(e) for e in self._edges]
        return {"nodes": nodes, "edges": edges}

    @property
    def host_count(self) -> int:
        with self._lock:
            return len(self._hosts)

    # ---- auto-discovery from agent scan output ----

    # Regex patterns for common recon tool output
    _IP_PORT_PATTERN = re.compile(
        r"(\d{1,3}(?:\.\d{1,3}){3})[:\s]+(\d{1,5})(?:/(?:open|tcp|udp))?"
    )
    _NMAP_HOST_PATTERN = re.compile(
        r"Nmap scan report for\s+(?:(\S+)\s+\()?(\d{1,3}(?:\.\d{1,3}){3})\)?"
    )
    _ARP_PATTERN = re.compile(
        r"(\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+(\S+)"
    )

    def auto_discover(self, session_responses: list[dict]):
        """Parse scan / recon output and populate the network map.

        Looks for IP addresses and open ports in common tool output formats.
        """
        for resp in session_responses:
            output = resp.get("output", "")
            command = resp.get("command", resp.get("task_id", ""))
            if not output:
                continue

            discovered: dict[str, set] = {}  # ip -> set of ports

            # Nmap-style host headers
            for m in self._NMAP_HOST_PATTERN.finditer(output):
                hostname = m.group(1) or ""
                ip = m.group(2)
                if ip not in discovered:
                    discovered[ip] = set()
                if hostname:
                    self.add_host(ip, hostname=hostname)

            # IP:port pairs from various scanners
            for m in self._IP_PORT_PATTERN.finditer(output):
                ip = m.group(1)
                port = int(m.group(2))
                if ip not in discovered:
                    discovered[ip] = set()
                discovered[ip].add(port)

            for ip, ports in discovered.items():
                self.add_host(ip, ports=sorted(ports) if ports else None)

            # If output came from a specific session, create scan edges
            src_ip = resp.get("source_ip")
            if src_ip:
                for ip in discovered:
                    if ip != src_ip:
                        self.add_edge(src_ip, ip, edge_type="scan",
                                      label=command)
