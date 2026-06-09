rule AES_SBOX : crypto aes
{
    meta:
        family = "aes"
        algorithm = "AES"
        confidence = "high"
    strings:
        $sbox = {
            63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76
            ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0
            b7 fd 93 26 36 3f f7 cc 34 a5 e5 f1 71 d8 31 15
            04 c7 23 c3 18 96 05 9a 07 12 80 e2 eb 27 b2 75
        }
    condition:
        $sbox
}

rule AES_RCON : crypto aes
{
    meta:
        family = "aes"
        algorithm = "AES"
        confidence = "medium"
    strings:
        $rcon = { 01 00 00 00 02 00 00 00 04 00 00 00 08 00 00 00 10 00 00 00 20 00 00 00 40 00 00 00 80 00 00 00 }
    condition:
        $rcon
}

rule MD5_CONSTANTS : crypto md5
{
    meta:
        family = "md5"
        algorithm = "MD5"
        confidence = "high"
    strings:
        $k0_le = { 78 a4 6a d7 56 b7 c7 e8 db 70 20 24 ee ce bd c1 }
    condition:
        $k0_le
}

rule SHA1_CONSTANTS : crypto sha1
{
    meta:
        family = "sha1"
        algorithm = "SHA-1"
        confidence = "medium"
    strings:
        $k_be = { 5a 82 79 99 6e d9 eb a1 8f 1b bc dc ca 62 c1 d6 }
        $k_le = { 99 79 82 5a a1 eb d9 6e dc bc 1b 8f d6 c1 62 ca }
    condition:
        any of them
}

rule SHA256_K : crypto sha2
{
    meta:
        family = "sha2"
        algorithm = "SHA-256"
        confidence = "high"
    strings:
        $k0_be = { 42 8a 2f 98 71 37 44 91 b5 c0 fb cf e9 b5 db a5 }
        $k0_le = { 98 2f 8a 42 91 44 37 71 cf fb c0 b5 a5 db b5 e9 }
    condition:
        any of them
}

rule CRC32_TABLE : crypto crc32
{
    meta:
        family = "crc32"
        algorithm = "CRC32"
        confidence = "high"
    strings:
        $table_le = { 00 00 00 00 96 30 07 77 2c 61 0e ee ba 51 09 99 }
    condition:
        $table_le
}

rule CHACHA20_CONSTANTS : crypto chacha20
{
    meta:
        family = "chacha20"
        algorithm = "ChaCha20"
        confidence = "high"
    strings:
        $sigma = "expand 32-byte k"
    condition:
        $sigma
}

rule POLY1305_CONSTANTS : crypto poly1305
{
    meta:
        family = "poly1305"
        algorithm = "Poly1305"
        confidence = "medium"
    strings:
        $p = { 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 }
    condition:
        $p
}

rule TEA_DELTA : crypto tea
{
    meta:
        family = "tea"
        algorithm = "TEA/XTEA"
        confidence = "medium"
    strings:
        $delta_le = { b9 79 37 9e }
        $delta_be = { 9e 37 79 b9 }
    condition:
        any of them
}
