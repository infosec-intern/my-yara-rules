/*
    This rule file is all about PE files
*/
import "pe"

private rule PE : PE
{
    meta:
        author = "Thomas Gardner"
        description = "Describes the basic PE file header. Intended for including in other rules"
    condition:
        uint16be(0) == 0x5A4D
}
rule DLL : PE Library
{
    meta:
        author = "Thomas Gardner"
        description = "Describes a DLL file"
    condition:
        PE and pe.is_dll()
}
rule Exe : PE Executable
{
    meta:
        author = "Thomas Gardner"
        description = "Describes an executable file"
    condition:
        PE and pe.characteristics & pe.EXECUTABLE_IMAGE
}
