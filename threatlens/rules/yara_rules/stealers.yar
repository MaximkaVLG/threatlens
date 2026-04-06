rule Stealer_BrowserPaths {
    meta:
        description = "Accesses multiple browser credential paths"
        severity = "critical"
        category = "password_theft"
    strings:
        $c1 = "\\Google\\Chrome\\User Data" ascii wide nocase
        $c2 = "\\Mozilla\\Firefox\\Profiles" ascii wide nocase
        $c3 = "\\Microsoft\\Edge\\User Data" ascii wide nocase
        $c4 = "\\Opera Software\\Opera" ascii wide nocase
        $c5 = "\\BraveSoftware\\Brave" ascii wide nocase
        $c6 = "\\Vivaldi\\User Data" ascii wide nocase
        $c7 = "\\Yandex\\YandexBrowser\\User Data" ascii wide nocase
    condition:
        3 of them
}

rule Stealer_DiscordToken {
    meta:
        description = "Discord token stealer"
        severity = "critical"
        category = "password_theft"
    strings:
        $d1 = "discord" ascii wide nocase
        $d2 = "token" ascii wide nocase
        $d3 = "leveldb" ascii wide nocase
        $d4 = "Local Storage" ascii wide nocase
        $regex = /[MN][A-Za-z0-9]{23,27}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27,40}/
    condition:
        3 of ($d*) or $regex
}

rule Stealer_Telegram {
    meta:
        description = "Telegram session stealer"
        severity = "critical"
        category = "password_theft"
    strings:
        $t1 = "\\Telegram Desktop\\tdata" ascii wide nocase
        $t2 = "tdata" ascii wide nocase
        $t3 = "D877F783D5D3EF8C" ascii wide nocase
        $t4 = "map0" ascii wide nocase
        $t5 = "map1" ascii wide nocase
    condition:
        $t1 or ($t2 and 2 of ($t3, $t4, $t5))
}

rule Stealer_FTP {
    meta:
        description = "FTP credential stealer"
        severity = "high"
        category = "password_theft"
    strings:
        $f1 = "\\FileZilla\\recentservers.xml" ascii wide nocase
        $f2 = "\\FileZilla\\sitemanager.xml" ascii wide nocase
        $f3 = "\\WinSCP\\WinSCP.ini" ascii wide nocase
        $f4 = "\\SmartFTP\\" ascii wide nocase
    condition:
        2 of them
}

rule Stealer_VPN {
    meta:
        description = "VPN credential stealer"
        severity = "high"
        category = "password_theft"
    strings:
        $v1 = "\\OpenVPN\\config" ascii wide nocase
        $v2 = "\\NordVPN\\" ascii wide nocase
        $v3 = "\\ProtonVPN\\" ascii wide nocase
        $v4 = "user.config" ascii wide nocase
        $v5 = "ovpn" ascii wide nocase
    condition:
        2 of them
}

rule Stealer_SSHKeys {
    meta:
        description = "SSH private key stealer"
        severity = "critical"
        category = "password_theft"
    strings:
        $s1 = "\\.ssh\\id_rsa" ascii wide nocase
        $s2 = "\\.ssh\\id_ed25519" ascii wide nocase
        $s3 = "\\.ssh\\known_hosts" ascii wide nocase
        $s4 = "BEGIN RSA PRIVATE KEY" ascii wide
        $s5 = "BEGIN OPENSSH PRIVATE KEY" ascii wide
    condition:
        2 of them
}

rule Stealer_GamePlatforms {
    meta:
        description = "Game platform credential stealer (Steam, Epic, etc)"
        severity = "high"
        category = "password_theft"
    strings:
        $g1 = "\\Steam\\config\\loginusers.vdf" ascii wide nocase
        $g2 = "\\Steam\\ssfn" ascii wide nocase
        $g3 = "\\Epic Games\\" ascii wide nocase
        $g4 = "\\Riot Games\\" ascii wide nocase
        $g5 = "\\Battle.net\\" ascii wide nocase
        $g6 = "\\Minecraft\\" ascii wide nocase
    condition:
        2 of them
}
