DEFAULT_CONFIG = {
    "c2_host": "0.0.0.0",
    "c2_port": 4444,
    "transport": "tcp",
    "encryption": True,
    "sleep": 5,
    "jitter": 20,
    "kill_date": None,
    "retry_count": -1,
    "retry_delay": 10,
    "modules": [
        "recon", "fileops", "privesc", "persist",
        "lateral", "stealing", "pivoting", "evasion",
    ],
    "agent_version": "5.2",
}
