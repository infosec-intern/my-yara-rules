private rule MSOffice : Office
{
    meta:
        author = "Thomas Gardner"
        description = "Describes the binary format that older Microsoft Office files use"
        reference = "https://en.wikipedia.org/wiki/List_of_file_signatures"
    strings:
        $magic = { D0 CF 11 E0 }
    condition:
        $magic at 0
}