rule C2_Communication {
    meta:
        description = "Command and Control server communication"
        severity = "critical"
        category = "network"
    strings:
        $c1 = "User-Agent" ascii wide
        $c2 = "/gate.php" ascii wide nocase
        $c3 = "/panel/" ascii wide nocase
        $c4 = "/command" ascii wide nocase
        $c5 = "cmd=" ascii wide
        $c6 = "bot_id=" ascii wide
        $c7 = "hwid=" ascii wide
        $net1 = "InternetOpenA" ascii
        $net2 = "HttpSendRequest" ascii
        $net3 = "URLDownloadToFile" ascii
    condition:
        2 of ($c*) and 1 of ($net*)
}

rule Downloader_Generic {
    meta:
        description = "Downloads and executes remote payload"
        severity = "high"
        category = "network"
    strings:
        $dl1 = "URLDownloadToFileA" ascii
        $dl2 = "URLDownloadToFileW" ascii
        $dl3 = "Invoke-WebRequest" ascii wide nocase
        $dl4 = "wget" ascii wide
        $dl5 = "curl" ascii wide
        $exec1 = "ShellExecuteA" ascii
        $exec2 = "CreateProcessA" ascii
        $exec3 = "WinExec" ascii
        $exec4 = "Start-Process" ascii wide nocase
        $exec5 = "system(" ascii
    condition:
        1 of ($dl*) and 1 of ($exec*)
}

rule Backdoor_ReverseShell {
    meta:
        description = "Reverse shell indicators"
        severity = "critical"
        category = "injection"
    strings:
        $rs1 = "cmd.exe" ascii wide
        $rs2 = "/bin/sh" ascii wide
        $rs3 = "/bin/bash" ascii wide
        $rs4 = "socket" ascii wide
        $rs5 = "connect" ascii wide
        $rs6 = "subprocess" ascii wide
        $rs7 = "WSAStartup" ascii
        $pipe1 = "CreatePipe" ascii
        $pipe2 = "PeekNamedPipe" ascii
    condition:
        (1 of ($rs1, $rs2, $rs3)) and ($rs4 or $rs5 or $rs6 or $rs7) or (2 of ($pipe*) and $rs1)
}

rule Botnet_IRC {
    meta:
        description = "IRC-based botnet communication"
        severity = "high"
        category = "network"
    strings:
        $irc1 = "JOIN #" ascii wide
        $irc2 = "PRIVMSG" ascii wide
        $irc3 = "NICK " ascii wide
        $irc4 = "PING :" ascii wide
        $irc5 = ":6667" ascii wide
        $irc6 = ":6697" ascii wide
    condition:
        3 of them
}

rule Dropper_EmbeddedPE {
    meta:
        description = "Script containing embedded PE executable"
        severity = "high"
        category = "obfuscation"
    strings:
        $mz = "TVqQ" ascii  // Base64 of "MZ"
        $mz2 = "TVpQ" ascii  // Another Base64 variant
        $pe1 = "4D5A" ascii  // Hex of "MZ"
        $pe2 = "\\x4d\\x5a" ascii
    condition:
        any of them and filesize < 10MB
}
