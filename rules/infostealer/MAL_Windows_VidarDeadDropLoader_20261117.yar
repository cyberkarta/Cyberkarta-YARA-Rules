rule MAL_Windows_VidarDeadDropLoader_20261117
{
    meta:
        author      = "Cyberkarta - leosycthe"
        date        = "2026-11-18"
        description = "Detects an unpacked Vidar infostealer payload using Telegram/Steam dead-drop C2 resolution and a custom ANSI-colored debug logger, observed in our internal dynamic analysis (2026-11-17)"
        reference   = "Internal dynamic-analysis sandbox, 2026-11-17; family confirmed by a community YARA rule matching the same unpacked memory payload, malscore 10.0/Malicious; C2 dead-drop resolvers: Telegram t.me/j0tt0s, Steam profile 76561198660175584"
        license     = "DRL-1.1"
        hash        = "68b7eef9d986dfdc044a4c3f538ed01a7e5c80aeb453ed780f9e13392e81ec2f"
        hash2       = "d1d7865b26feef581aefde9d2b12cb4e1b420d9fc41adbcf3eb86b65677e32c6"

    strings:
        // Dead-drop resolver URLs embedded in the unpacked payload — specific to this
        // build/campaign, not a generic Vidar trait. On their own, either is a strong hit.
        $x1 = "https://telegram.me/j0tt0s" ascii fullword
        $x2 = "https://steamcommunity.com/profiles/76561198660175584" ascii fullword

        // Custom ANSI-colored console debug/log markers — observed only in this build;
        // not asserted as a universal Vidar characteristic, so required in combination.
        $s1 = "[92m [+] " ascii fullword
        $s2 = "[91m [-] " ascii fullword
        $s3 = "[93m [!] " ascii fullword
        $s4 = "[96m [*] " ascii fullword
        $s5 = "[90m [~] " ascii fullword

        // Embedded build/campaign identifier observed alongside the above
        $s6 = "5b1a4dd6b552d719906c7f798a3f7426" ascii fullword

    condition:
        uint16(0) == 0x5a4d
        and filesize < 10MB
        and ( 1 of ($x*) or 3 of ($s*) )
}
