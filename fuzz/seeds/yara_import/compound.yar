rule Seed : tag
{
    meta:
        description = "seed"
    strings:
        $a = "alpha" nocase
        $b = { 4D 5A ?? 00 }
        $c = /ab+c/
    condition:
        uint16(0) == 0x5A4D and #a >= 2 and ($b or $c)
}
