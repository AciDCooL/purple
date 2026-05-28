//! Functional grouping of SSH client config directives. Used to lay out the
//! pattern detail panel as one card per category. Classification is by the
//! directive keyword only (case-insensitive); values are never inspected.

/// A user-meaningful grouping of SSH directives. Every `ssh_config(5)` client
/// directive maps to exactly one category; unknown keywords fall to `Other` so
/// nothing the user wrote is ever hidden.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectiveCategory {
    Connection,
    Authentication,
    ProxyJump,
    Forwarding,
    HostKeys,
    Crypto,
    Session,
    Keepalive,
    Multiplexing,
    Environment,
    Logging,
    Other,
}

impl DirectiveCategory {
    /// Canonical display order for the detail panel. `Other` is last so any
    /// unrecognized directive surfaces below the known categories.
    pub const DISPLAY_ORDER: [DirectiveCategory; 12] = [
        Self::Connection,
        Self::Authentication,
        Self::ProxyJump,
        Self::Forwarding,
        Self::HostKeys,
        Self::Crypto,
        Self::Session,
        Self::Keepalive,
        Self::Multiplexing,
        Self::Environment,
        Self::Logging,
        Self::Other,
    ];

    /// Uppercase card title shown in the pattern detail panel.
    pub fn title(self) -> &'static str {
        match self {
            Self::Connection => "CONNECTION",
            Self::Authentication => "AUTHENTICATION",
            Self::ProxyJump => "PROXY & JUMP",
            Self::Forwarding => "FORWARDING",
            Self::HostKeys => "HOST KEYS",
            Self::Crypto => "CRYPTO",
            Self::Session => "SESSION",
            Self::Keepalive => "KEEPALIVE",
            Self::Multiplexing => "MULTIPLEXING",
            Self::Environment => "ENVIRONMENT",
            Self::Logging => "LOGGING",
            Self::Other => "OTHER",
        }
    }

    /// Classify an SSH directive keyword (case-insensitive). Unknown keywords
    /// map to `Other`. Deprecated spellings (e.g. `PubkeyAcceptedKeyTypes`) are
    /// recognized alongside their modern names so existing configs group cleanly.
    pub fn for_key(key: &str) -> DirectiveCategory {
        match key.to_ascii_lowercase().as_str() {
            "hostname"
            | "port"
            | "user"
            | "addressfamily"
            | "bindaddress"
            | "bindinterface"
            | "connecttimeout"
            | "connectionattempts"
            | "canonicalizehostname"
            | "canonicaldomains"
            | "canonicalizefallbacklocal"
            | "canonicalizemaxdots"
            | "canonicalizepermittedcnames"
            | "ipqos" => Self::Connection,

            "identityfile"
            | "identitiesonly"
            | "identityagent"
            | "addkeystoagent"
            | "certificatefile"
            | "pubkeyauthentication"
            | "pubkeyacceptedalgorithms"
            | "pubkeyacceptedkeytypes"
            | "passwordauthentication"
            | "kbdinteractiveauthentication"
            | "kbdinteractivedevices"
            | "challengeresponseauthentication"
            | "preferredauthentications"
            | "numberofpasswordprompts"
            | "hostbasedauthentication"
            | "hostbasedacceptedalgorithms"
            | "hostbasedkeytypes"
            | "gssapiauthentication"
            | "gssapidelegatecredentials"
            | "pkcs11provider"
            | "securitykeyprovider"
            | "enablesshkeysign"
            | "usekeychain"
            | "batchmode"
            | "casignaturealgorithms" => Self::Authentication,

            "proxyjump"
            | "proxycommand"
            | "proxyusefdpass"
            | "nohostauthenticationforproxycommand" => Self::ProxyJump,

            "localforward"
            | "remoteforward"
            | "dynamicforward"
            | "forwardagent"
            | "forwardx11"
            | "forwardx11trusted"
            | "forwardx11timeout"
            | "xauthlocation"
            | "gatewayports"
            | "clearallforwardings"
            | "exitonforwardfailure"
            | "permitlocalcommand"
            | "permitremoteopen"
            | "tunnel"
            | "tunneldevice"
            | "streamlocalbindmask"
            | "streamlocalbindunlink" => Self::Forwarding,

            "stricthostkeychecking"
            | "userknownhostsfile"
            | "globalknownhostsfile"
            | "knownhostscommand"
            | "hashknownhosts"
            | "hostkeyalias"
            | "hostkeyalgorithms"
            | "checkhostip"
            | "verifyhostkeydns"
            | "updatehostkeys"
            | "revokedhostkeys"
            | "nohostauthenticationforlocalhost"
            | "fingerprinthash"
            | "visualhostkey" => Self::HostKeys,

            "ciphers"
            | "macs"
            | "kexalgorithms"
            | "rekeylimit"
            | "requiredrsasize"
            | "compression"
            | "obscurekeystroketiming"
            | "warnweakcrypto"
            | "refuseconnection" => Self::Crypto,

            "requesttty"
            | "sessiontype"
            | "remotecommand"
            | "localcommand"
            | "escapechar"
            | "enableescapecommandline"
            | "forkafterauthentication"
            | "stdinnull"
            | "versionaddendum" => Self::Session,

            "serveraliveinterval" | "serveralivecountmax" | "tcpkeepalive" | "channeltimeout" => {
                Self::Keepalive
            }

            "controlmaster" | "controlpath" | "controlpersist" => Self::Multiplexing,

            "setenv" | "sendenv" => Self::Environment,

            "loglevel" | "logverbose" | "syslogfacility" => Self::Logging,

            _ => Self::Other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every settable client directive from ssh_config(5), paired with its
    /// expected category. Doubles as a regression guard against typos in the
    /// match arms: none of these may fall to `Other`.
    const KNOWN: &[(&str, DirectiveCategory)] = &[
        ("Hostname", DirectiveCategory::Connection),
        ("Port", DirectiveCategory::Connection),
        ("User", DirectiveCategory::Connection),
        ("AddressFamily", DirectiveCategory::Connection),
        ("BindAddress", DirectiveCategory::Connection),
        ("BindInterface", DirectiveCategory::Connection),
        ("ConnectTimeout", DirectiveCategory::Connection),
        ("ConnectionAttempts", DirectiveCategory::Connection),
        ("CanonicalizeHostname", DirectiveCategory::Connection),
        ("CanonicalDomains", DirectiveCategory::Connection),
        ("CanonicalizeFallbackLocal", DirectiveCategory::Connection),
        ("CanonicalizeMaxDots", DirectiveCategory::Connection),
        ("CanonicalizePermittedCNAMEs", DirectiveCategory::Connection),
        ("IPQoS", DirectiveCategory::Connection),
        ("IdentityFile", DirectiveCategory::Authentication),
        ("IdentitiesOnly", DirectiveCategory::Authentication),
        ("IdentityAgent", DirectiveCategory::Authentication),
        ("AddKeysToAgent", DirectiveCategory::Authentication),
        ("CertificateFile", DirectiveCategory::Authentication),
        ("PubkeyAuthentication", DirectiveCategory::Authentication),
        (
            "PubkeyAcceptedAlgorithms",
            DirectiveCategory::Authentication,
        ),
        ("PubkeyAcceptedKeyTypes", DirectiveCategory::Authentication),
        ("PasswordAuthentication", DirectiveCategory::Authentication),
        (
            "KbdInteractiveAuthentication",
            DirectiveCategory::Authentication,
        ),
        ("KbdInteractiveDevices", DirectiveCategory::Authentication),
        (
            "ChallengeResponseAuthentication",
            DirectiveCategory::Authentication,
        ),
        (
            "PreferredAuthentications",
            DirectiveCategory::Authentication,
        ),
        ("NumberOfPasswordPrompts", DirectiveCategory::Authentication),
        ("HostbasedAuthentication", DirectiveCategory::Authentication),
        (
            "HostbasedAcceptedAlgorithms",
            DirectiveCategory::Authentication,
        ),
        ("HostbasedKeyTypes", DirectiveCategory::Authentication),
        ("GSSAPIAuthentication", DirectiveCategory::Authentication),
        (
            "GSSAPIDelegateCredentials",
            DirectiveCategory::Authentication,
        ),
        ("PKCS11Provider", DirectiveCategory::Authentication),
        ("SecurityKeyProvider", DirectiveCategory::Authentication),
        ("EnableSSHKeysign", DirectiveCategory::Authentication),
        ("UseKeychain", DirectiveCategory::Authentication),
        ("BatchMode", DirectiveCategory::Authentication),
        ("CASignatureAlgorithms", DirectiveCategory::Authentication),
        ("ProxyJump", DirectiveCategory::ProxyJump),
        ("ProxyCommand", DirectiveCategory::ProxyJump),
        ("ProxyUseFdpass", DirectiveCategory::ProxyJump),
        (
            "NoHostAuthenticationForProxyCommand",
            DirectiveCategory::ProxyJump,
        ),
        ("LocalForward", DirectiveCategory::Forwarding),
        ("RemoteForward", DirectiveCategory::Forwarding),
        ("DynamicForward", DirectiveCategory::Forwarding),
        ("ForwardAgent", DirectiveCategory::Forwarding),
        ("ForwardX11", DirectiveCategory::Forwarding),
        ("ForwardX11Trusted", DirectiveCategory::Forwarding),
        ("ForwardX11Timeout", DirectiveCategory::Forwarding),
        ("XAuthLocation", DirectiveCategory::Forwarding),
        ("GatewayPorts", DirectiveCategory::Forwarding),
        ("ClearAllForwardings", DirectiveCategory::Forwarding),
        ("ExitOnForwardFailure", DirectiveCategory::Forwarding),
        ("PermitLocalCommand", DirectiveCategory::Forwarding),
        ("PermitRemoteOpen", DirectiveCategory::Forwarding),
        ("Tunnel", DirectiveCategory::Forwarding),
        ("TunnelDevice", DirectiveCategory::Forwarding),
        ("StreamLocalBindMask", DirectiveCategory::Forwarding),
        ("StreamLocalBindUnlink", DirectiveCategory::Forwarding),
        ("StrictHostKeyChecking", DirectiveCategory::HostKeys),
        ("UserKnownHostsFile", DirectiveCategory::HostKeys),
        ("GlobalKnownHostsFile", DirectiveCategory::HostKeys),
        ("KnownHostsCommand", DirectiveCategory::HostKeys),
        ("HashKnownHosts", DirectiveCategory::HostKeys),
        ("HostKeyAlias", DirectiveCategory::HostKeys),
        ("HostKeyAlgorithms", DirectiveCategory::HostKeys),
        ("CheckHostIP", DirectiveCategory::HostKeys),
        ("VerifyHostKeyDNS", DirectiveCategory::HostKeys),
        ("UpdateHostKeys", DirectiveCategory::HostKeys),
        ("RevokedHostKeys", DirectiveCategory::HostKeys),
        (
            "NoHostAuthenticationForLocalhost",
            DirectiveCategory::HostKeys,
        ),
        ("FingerprintHash", DirectiveCategory::HostKeys),
        ("VisualHostKey", DirectiveCategory::HostKeys),
        ("Ciphers", DirectiveCategory::Crypto),
        ("MACs", DirectiveCategory::Crypto),
        ("KexAlgorithms", DirectiveCategory::Crypto),
        ("RekeyLimit", DirectiveCategory::Crypto),
        ("RequiredRSASize", DirectiveCategory::Crypto),
        ("Compression", DirectiveCategory::Crypto),
        ("ObscureKeystrokeTiming", DirectiveCategory::Crypto),
        ("WarnWeakCrypto", DirectiveCategory::Crypto),
        ("RefuseConnection", DirectiveCategory::Crypto),
        ("RequestTTY", DirectiveCategory::Session),
        ("SessionType", DirectiveCategory::Session),
        ("RemoteCommand", DirectiveCategory::Session),
        ("LocalCommand", DirectiveCategory::Session),
        ("EscapeChar", DirectiveCategory::Session),
        ("EnableEscapeCommandline", DirectiveCategory::Session),
        ("ForkAfterAuthentication", DirectiveCategory::Session),
        ("StdinNull", DirectiveCategory::Session),
        ("VersionAddendum", DirectiveCategory::Session),
        ("ServerAliveInterval", DirectiveCategory::Keepalive),
        ("ServerAliveCountMax", DirectiveCategory::Keepalive),
        ("TCPKeepAlive", DirectiveCategory::Keepalive),
        ("ChannelTimeout", DirectiveCategory::Keepalive),
        ("ControlMaster", DirectiveCategory::Multiplexing),
        ("ControlPath", DirectiveCategory::Multiplexing),
        ("ControlPersist", DirectiveCategory::Multiplexing),
        ("SetEnv", DirectiveCategory::Environment),
        ("SendEnv", DirectiveCategory::Environment),
        ("LogLevel", DirectiveCategory::Logging),
        ("LogVerbose", DirectiveCategory::Logging),
        ("SyslogFacility", DirectiveCategory::Logging),
    ];

    #[test]
    fn every_known_directive_maps_to_its_category() {
        for (key, expected) in KNOWN {
            assert_eq!(
                DirectiveCategory::for_key(key),
                *expected,
                "directive {key} mapped to the wrong category"
            );
        }
    }

    #[test]
    fn no_known_directive_falls_to_other() {
        for (key, _) in KNOWN {
            assert_ne!(
                DirectiveCategory::for_key(key),
                DirectiveCategory::Other,
                "directive {key} unexpectedly fell to OTHER"
            );
        }
    }

    #[test]
    fn classification_is_case_insensitive() {
        assert_eq!(
            DirectiveCategory::for_key("hostname"),
            DirectiveCategory::Connection
        );
        assert_eq!(
            DirectiveCategory::for_key("HostName"),
            DirectiveCategory::Connection
        );
        assert_eq!(
            DirectiveCategory::for_key("HOSTNAME"),
            DirectiveCategory::Connection
        );
        assert_eq!(
            DirectiveCategory::for_key("SeTeNv"),
            DirectiveCategory::Environment
        );
    }

    #[test]
    fn unknown_directives_fall_to_other() {
        // Block selectors and structure directives are not connection settings,
        // and genuine typos must never vanish.
        assert_eq!(
            DirectiveCategory::for_key("Include"),
            DirectiveCategory::Other
        );
        assert_eq!(DirectiveCategory::for_key("Tag"), DirectiveCategory::Other);
        assert_eq!(
            DirectiveCategory::for_key("IgnoreUnknown"),
            DirectiveCategory::Other
        );
        assert_eq!(
            DirectiveCategory::for_key("FooBarTypo"),
            DirectiveCategory::Other
        );
        assert_eq!(DirectiveCategory::for_key(""), DirectiveCategory::Other);
    }

    #[test]
    fn display_order_is_complete_and_ends_with_other() {
        assert_eq!(DirectiveCategory::DISPLAY_ORDER.len(), 12);
        assert_eq!(
            *DirectiveCategory::DISPLAY_ORDER.last().unwrap(),
            DirectiveCategory::Other
        );
        // No duplicates.
        for (i, a) in DirectiveCategory::DISPLAY_ORDER.iter().enumerate() {
            for b in &DirectiveCategory::DISPLAY_ORDER[i + 1..] {
                assert_ne!(a, b, "DISPLAY_ORDER contains a duplicate: {a:?}");
            }
        }
    }

    #[test]
    fn every_category_has_a_nonempty_title() {
        for category in DirectiveCategory::DISPLAY_ORDER {
            assert!(!category.title().is_empty());
        }
    }
}
