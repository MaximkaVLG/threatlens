rule Packer_UPX {
    meta:
        description = "UPX packed executable"
        severity = "low"
        category = "obfuscation"
    strings:
        $upx1 = "UPX0" ascii
        $upx2 = "UPX1" ascii
        $upx3 = "UPX!" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Packer_Themida {
    meta:
        description = "Themida/WinLicense protected"
        severity = "medium"
        category = "obfuscation"
    strings:
        $s1 = ".themida" ascii
        $s2 = ".winlice" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Packer_VMProtect {
    meta:
        description = "VMProtect packed"
        severity = "medium"
        category = "obfuscation"
    strings:
        $s1 = ".vmp0" ascii
        $s2 = ".vmp1" ascii
        $s3 = ".vmp2" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Packer_ASPack {
    meta:
        description = "ASPack packed"
        severity = "low"
        category = "obfuscation"
    strings:
        $s1 = ".aspack" ascii
        $s2 = ".adata" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule HighEntropy_Executable {
    meta:
        description = "PE with very high entropy — likely packed or encrypted"
        severity = "medium"
        category = "obfuscation"
    condition:
        uint16(0) == 0x5A4D and math.entropy(0, filesize) > 7.5
}
