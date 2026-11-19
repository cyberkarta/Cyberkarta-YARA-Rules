import "pe"
import "math"

rule SUSP_Windows_HighEntropyPackedSection_20261119
{
    meta:
        author      = "Cyberkarta - leosycthe"
        date        = "2026-11-19"
        description = "Heuristic triage signal: flags a PE with a section entropy >= 7.5, typical of an encrypted/compressed packer stub. This is NOT a malware verdict by itself -- empirically confirmed to also fire on legitimately packed/compressed benign software (e.g. a plain UPX-packed clean binary scores 7.89). Use only as one weak input alongside other signals (behavioral detection, reputation, other YARA matches), never as a standalone block/alert decision."
        reference   = "Internal testing 2026-11-19: 19 clean .exe files all scored <=6.80 (no FP in this sample), but a UPX-packed copy of one of those same clean files scored 7.89 (proven false-positive case) -- known FP classes beyond UPX: commercial packers/protectors (Themida, VMProtect) legitimately used for anti-tamper/DRM, self-extracting installers, binaries with compressed/embedded resources (media, archives)"
        license     = "DRL-1.1"

    condition:
        uint16(0) == 0x5a4d
        and filesize < 20MB
        and pe.number_of_sections > 0
        and for any i in (0..pe.number_of_sections - 1):
            ( math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) >= 7.5 )
}
