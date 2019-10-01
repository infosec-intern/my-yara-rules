/*
    This rule file is all about common office document formats -
        including older binary Office formats, newer xml-based Office formats, and PDFs
*/
private rule Office_97_2003 : Office
{
    meta:
        author = "Thomas Gardner"
        description = "Describes the binary format that older Microsoft Office files use"
        reference = "https://en.wikipedia.org/wiki/List_of_file_signatures"
    condition:
        uint32be(0) == 0xD0CF11E0
}
private rule Office_2007 : Office
{
    meta:
        author = "Thomas Gardner"
        description = "Describes the newer XML-based Microsoft Office file format"
        reference = "https://en.wikipedia.org/wiki/List_of_file_signatures"
    strings:
        $rels = "_rels/.rels"
    condition:
        // use a specific Zip archive header - we don't need to be as generic as the Zip rule
        uint32be(0) ==  0x504B0304 and $rels
}
rule PPTX : Office Powerpoint
{
    meta:
        author = "Thomas Gardner"
        description = "Describes a PowerPoint file from Office 2007 onward"
    strings:
        $slides = "ppt/slides"
        $presentation = "ppt/presentation.xml"
        $rels = "ppt/_rels/presentation.xml.rels"
    condition:
        Office_2007 and all of them
}