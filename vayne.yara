import "pe"

rule Vayne_RAT : Malware Trojan
{
    meta:
        author = "Thomas Gardner"
        description = "Describe a C# RAT called Vayne"
        reference = "https://www.kitploit.com/2018/05/vayne-rat-advanced-c-net-rat.html"
        reference = "https://github.com/TheM4hd1/Vayne-RaT"
    strings:
        $av_name = "getAvName"
        $vayne_rat = /Vayne[_\.]Rat/ nocase
        $av_product = "SELECT * FROM AntivirusProduct" wide nocase
        $ipify = "api.ipify.org" wide
        $armsvc = "armsvc" wide
        $zeroapp = "By ZeroApp wide"
    condition:
        uint16be(0) == 0x4D5A and
        // pe.imports("apphelp.dll", "NtQuerySecurityObject") and
        3 of them
}
