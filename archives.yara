/*
    This rule file is all about archive files - Zips, RAR, Gzip, Bzip, Tar, etc.
*/
rule Zip
{
    meta:
        author = "Thomas Gardner"
        description = "Describes a generic Zip archive"
        reference = "https://en.wikipedia.org/wiki/List_of_file_signatures"
    strings:
        $normal = { 03 04 }
        $empty = { 05 06 }
        $span = { 07 08 }
    condition:
        uint16be(0) == 0x504B and for any of them : ($ at 2)
}
