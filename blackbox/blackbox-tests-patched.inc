// TEST sets udp_len = query_len.
#define TEST(query, uses_digest, expected) {(query), sizeof(query)-1, sizeof(query)-1, (expected), sizeof(expected)-1, (uses_digest)}
// TEST_UDPLEN sets udp_len = query_len + udp_increment. udp_len is exclusive
// of the 8-byte UDP header.
#define TEST_UDPLEN(query, udp_increment, uses_digest, expected) {(query), sizeof(query)-1, sizeof(query)-1 + (udp_increment), (expected), sizeof(expected)-1, (uses_digest)}

/* Well-formed A queries. */
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x02" "69" "\x02" "mu" "\x00" "\x00\x01\x00\x01", false,
	"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x02" "69" "\x02" "mu" "\x00" "\x00\x01\x00\x01" A_SUFFIX
),
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x08" "facebook" "\x03" "com" "\x00" "\x00\x01\x00\x01", false,
	"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x08" "facebook" "\x03" "com" "\x00" "\x00\x01\x00\x01" A_SUFFIX
),
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x07" "example" "\x03" "com" "\x00" "\x00\x01\x00\x01", false,
	""
),


/* Well-formed AAAA queries. */
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x02" "69" "\x02" "mu" "\x00" "\x00\x1c\x00\x01", false,
	"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x02" "69" "\x02" "mu" "\x00" "\x00\x1c\x00\x01" AAAA_SUFFIX
),
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x08" "facebook" "\x03" "com" "\x00" "\x00\x1c\x00\x01", false,
	"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x08" "facebook" "\x03" "com" "\x00" "\x00\x1c\x00\x01" AAAA_SUFFIX
),
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x07" "example" "\x03" "com" "\x00" "\x00\x1c\x00\x01", false,
	""
),

/* QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT are ignored. */
// QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT all zero.
TEST(
	"\x00\x00\x01\x20\x00\x00\x00\x00\x00\x00\x00\x00" "\x02" "69" "\x02" "mu" "\x00" "\x00\x01\x00\x01", false,
	"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x02" "69" "\x02" "mu" "\x00" "\x00\x01\x00\x01" A_SUFFIX
),
// QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT all > 1.
TEST(
	"\x00\x00\x01\x20\x01\x02\x03\x04\x05\x06\x07\x08" "\x02" "69" "\x02" "mu" "\x00" "\x00\x01\x00\x01", false,
	"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x02" "69" "\x02" "mu" "\x00" "\x00\x01\x00\x01" A_SUFFIX
),

// No null terminator means an end-anchored pattern doesn't match.
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x08" "facebook" "\xff" "com", false,
	""
),
// Missing QCLASS.
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x08" "facebook" "\x03" "com", false,
	""
),
// Missing QCLASS.
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
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x08" "facebook" "\xff" "com" "\x00", false,
	""
),
// Combine ending exactly after the end of the message with an embedded dot in
// the label. Missing QCLASS.
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
	""
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

// shaving bytes from the end, no QCLASS
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x02" "69" "\x02" "mu" "\x00" "\x00\x01\x00", false,
	""
),
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x02" "69" "\x02" "mu" "\x00" "\x00\x01", false,
	""
),
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x02" "69" "\x02" "mu" "\x00" "\x00", false,
	""
),
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x02" "69" "\x02" "mu" "\x00", false,
	""
),
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x02" "69" "\x02" "mu", false,
	""
),

// QTYPE=AAAA, but it's below the 127 threshold, so the AAAA is
// considered part of a label and the response defaults to A.
// No QCLASS.
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
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x02" "69" "\x02" "mu" "\x77" "\x00\x1c", false,
	""
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
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x02" "69" "\x02" "mu" "\x78" "\x00\x1c", false,
	""
),


// Embedded '.' rather than proper label separator.
// Missing QCLASS.
/*
$ (perl -e 'print "\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x0569.mu"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   00 00 01 00 00 01 00 00   00 00 00 00 05 36 39 2E   ........ .....69.
[0010]   6D 75                                               mu
*/
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x05" "69.mu", false,
	""
),
/*
$ (perl -e 'print "\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x0569.mu\x00\x00\x01\x00\x01"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   00 00 01 20 00 01 00 00   00 00 00 00 05 36 39 2E   ... .... .....69.
[0010]   6D 75 00 00 01 00 01                                mu.....
[0000]   00 00 81 80 00 01 00 01   00 00 00 00 05 36 39 2E   ........ .....69.
[0010]   6D 75 00 00 01 00 01 C0   0C 00 01 00 01 00 00 00   mu...... ........
[0020]   61 00 04 1F 0D 5E 25                                a....^%
[0000]   00 00 81 80 00 01 00 01   00 00 00 00 02 36 39 02   ........ .....69.
[0010]   6D 75 00 00 01 00 01 C0   0C 00 01 00 01 00 00 00   mu...... ........
[0020]   82 00 04 9D F0 12 12                                .......
*/
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x05" "69.mu" "\x00" "\x00\x01\x00\x01", false,
	"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x05" "69.mu" "\x00" "\x00\x01\x00\x01" A_SUFFIX
),

/*
$ (perl -e 'print "\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\xff69.mu\x00"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   00 00 01 00 00 01 00 00   00 00 00 00 FF 36 39 2E   ........ .....69.
[0010]   6D 75 00                                            mu.
*/
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\xff" "69.mu" "\x00", false,
	""
),
/*
$ (perl -e 'print "\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x7769.mu\x00"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   00 00 01 00 00 01 00 00   00 00 00 00 77 36 39 2E   ........ ....w69.
[0010]   6D 75 00                                            mu.
*/
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x77" "69.mu" "\x00", false,
	""
),
/*
$ (perl -e 'print "\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x7869.mu\x00"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   00 00 01 00 00 01 00 00   00 00 00 00 78 36 39 2E   ........ ....x69.
[0010]   6D 75 00                                            mu.
*/
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x78" "69.mu" "\x00", false,
	""
),

/*
[0000]   00 00 01 20 00 01 00 00   00 00 00 00 05 36 39 2E   ... .... .....69.
[0010]   6D 75 68                                            muh
*/
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x05" "69.mu" "\x68", false,
	""
),

/*
$ (perl -e 'print "\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x03rsf\x03org"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   33 33 01 20 00 01 00 00   00 00 00 00 03 72 73 66   33. .... .....rsf
[0010]   03 6F 72 67                                         .org
*/
TEST(
	"\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x03" "rsf" "\x03" "org", false,
	""
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
	"\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x10" "aaaaaaaaaaaaaaaa" "\x08" "facebook" "\x03" "com" "\x00" "\x00\x01\x00\x01", false,
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
	"\x08" "facebook" "\x03" "com" "\x00" "\x00\x01\x00\x01", false,
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
	"\x08" "facebook" "\x03" "com" "\x00" "\x00\x01\x00\x01", false,
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
*/
TEST(
	"\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00"
	"\x10" "aaaaaaaaaaaaaaaa"
	"\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa"
	"\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa"
	"\x08" "facebook" "\x03" "com" "\x05" "extra" "\x00" "\x00\x01\x00\x01", false,
	""
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
*/
TEST(
	"\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00"
	"\x0f" "aaaaaaaaaaaaaaa"
	"\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa"
	"\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa"
	"\x08" "facebook" "\x03" "com" "\x05" "extra" "\x00" "\x00\x01\x00\x01", false,
	""
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
	"\x08" "facebook" "\x09" "com.extra" "\x00" "\x00\x01\x00\x01", false,
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
	"\x08" "facebook" "\x03" "com" "\x05" "extra" "\x00" "\x00\x01\x00\x01", false,
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
	"\x08" "facebook" "\x03" "com" "\x05" "extra" "\x00" "\x00\x01\x00\x01", false,
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
*/
TEST(
	"\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00"
	"\x10" "aaaaaaaaaaaaaaaa"
	"\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa"
	"\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa" "\x0f" "aaaaaaaaaaaaaaa"
	"\x08" "facebook" "\x08" "comextra" "\x00" "\x00\x01\x00\x01", false,
	""
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
	"\x08" "facebook" "\x08" "comextra" "\x00" "\x00\x01\x00\x01", false,
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
	"\x08" "facebook" "\x08" "comextra" "\x00" "\x00\x01\x00\x01", false,
	""
),

/*
$ (perl -e 'print "\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\xffrsf.org\x00"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
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
	"\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\xff" "rsf.org" "\x00", false,
	""
),
/*
$ (perl -e 'print "\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\xffrsf.org\x00\x00"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   33 33 01 20 00 01 00 00   00 00 00 00 FF 72 73 66   33. .... .....rsf
[0010]   2E 6F 72 67 00 00                                   .org..
*/
TEST(
	"\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\xff" "rsf.org" "\x00\x00", false,
	""
),
/*
$ (perl -e 'print "\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\xffrsf.org\x00\x00\x00"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   33 33 01 20 00 01 00 00   00 00 00 00 FF 72 73 66   33. .... .....rsf
[0010]   2E 6F 72 67 00 00 00                                .org...
*/
TEST(
	"\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\xff" "rsf.org" "\x00\x00\x00", false,
	""
),
// When the QNAME is only 5 bytes long, the first leaked byte is always 0x00.
// The 0x00 byte also effectively serves as a terminator in the string parsed
// from the QNAME, which is why this query gets an injection despite there
// being nothing to terminate the "tt" label in the query itself.
/*
$ (perl -e 'print "\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x014\xfftt"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   00 00 01 20 00 01 00 00   00 00 00 00 01 34 FF 74   ... .... .....4.t
[0010]   74                                                  t
*/
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x01" "4" "\xff" "tt", false,
	""
),
// The same query with a 1-byte subdomain prepended increases the QNAME length
// from 5 to 7, at which point the query no longer gets an injection because
// there is nothing to terminate the "tt" label.
/*
$ (perl -e 'print "\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x01a\x014\xfftt"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   00 00 01 20 00 01 00 00   00 00 00 00 01 61 01 34   ... .... .....a.4
[0010]   FF 74 74                                            .tt
*/
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x01" "a" "\x01" "4" "\xff" "tt", false,
	""
),
// The 7-byte QNAME (with the subdomain) gets an injection only if the query
// itself contains a 0x00 byte to terminate the name string.
/*
$ (perl -e 'print "\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x01a\x014\xfftt\x00"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   00 00 01 20 00 01 00 00   00 00 00 00 01 61 01 34   ... .... .....a.4
[0010]   FF 74 74 00                                         .tt.
*/
TEST(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x01" "a" "\x01" "4" "\xff" "tt" "\x00", false,
	""
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
	""
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
	""
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
	""
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

#if 0
// When query_len == udp_len, the parser reads only 1 byte past the end of the
// query (for the next length prefix), then 4 additional bytes for QTYPE and
// QCLASS.
/*
$ (perl -e 'print "\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x08facebook\x04com\x00"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   00 00 01 20 00 01 00 00   00 00 00 00 08 66 61 63   ... .... .....fac
[0010]   65 62 6F 6F 6B 04 63 6F   6D 00                     ebook.co m.
$ perl -e 'print "\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x08facebook\x04com\x00"' | sudo ../util/gfw-scapy.py --raw --ip 212.64.11.0 --udplen 34
Sending 8 bytes UDP header + 26 bytes payload: 0000012000010000000000000866616365626f6f6b03636f6d00
0000818000010001000000000866616365626f6f6b04636f6d00ca871cbe7bc00c000100010000005e00041f0d4329
*/
TEST_UDPLEN(
	"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x08" "facebook" "\x04" "com\x00", 0, false,
	""
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
#endif


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
$ (perl -e 'print "\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03rsf\x03org\x00\x00\x01\x00\x01"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   12 34 00 00 00 01 00 00   00 00 00 00 03 72 73 66   .4...... .....rsf
[0010]   03 6F 72 67 00 00 01 00   01                        .org.... .
[0000]   12 34 84 00 00 01 00 01   00 00 00 00 03 72 73 66   .4...... .....rsf
[0010]   03 6F 72 67 00 00 01 00   01 C0 0C 00 01 00 01 00   .org.... ........
[0020]   00 00 ED 00 04 6C A0 A6   3E                        .....l.. >
*/
TEST(
	"\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" "\x03" "rsf" "\x03" "org" "\x00\x00\x01\x00\x01", false,
	"\x12\x34\x84\x00\x00\x01\x00\x01\x00\x00\x00\x00" "\x03" "rsf" "\x03" "org" "\x00\x00\x01\x00\x01" A_SUFFIX
),
// If the RD bit (0x0100) is set in the query, the response sets the
// RD (0x0100) and RA (0x0080) bits.
/*
$ (perl -e 'print "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03rsf\x03org\x00\x00\x01\x00\x01"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   12 34 01 00 00 01 00 00   00 00 00 00 03 72 73 66   .4...... .....rsf
[0010]   03 6F 72 67 00 00 01 00   01                        .org.... .
[0000]   12 34 81 80 00 01 00 01   00 00 00 00 03 72 73 66   .4...... .....rsf
[0010]   03 6F 72 67 00 00 01 00   01 C0 0C 00 01 00 01 00   .org.... ........
[0020]   00 00 B8 00 04 80 F2 F0   9D                        ........ .
*/
TEST(
	"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" "\x03" "rsf" "\x03" "org" "\x00\x00\x01\x00\x01", false,
	"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x03" "rsf" "\x03" "org" "\x00\x00\x01\x00\x01" A_SUFFIX
),
// Setting all bits in a query other than QR (i.e., Opcode, AA, TC, RD, RA, Z,
// and RCODE) yields a response with only QR (0x8000), RD (0x0100), and
// RA (0x0080) set.
/*
$ (perl -e 'print "\x12\x34\x7f\xff\x00\x01\x00\x00\x00\x00\x00\x00\x03rsf\x03org\x00\x00\x01\x00\x01"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   12 34 7F FF 00 01 00 00   00 00 00 00 03 72 73 66   .4...... .....rsf
[0010]   03 6F 72 67 00 00 01 00   01                        .org.... .
[0000]   12 34 81 80 00 01 00 01   00 00 00 00 03 72 73 66   .4...... .....rsf
[0010]   03 6F 72 67 00 00 01 00   01 C0 0C 00 01 00 01 00   .org.... ........
[0020]   00 00 6E 00 04 C0 85 4D   BF                        ..n....M .
*/
TEST(
	"\x12\x34\x7f\xff\x00\x01\x00\x00\x00\x00\x00\x00" "\x03" "rsf" "\x03" "org" "\x00\x00\x01\x00\x01", false,
	"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x03" "rsf" "\x03" "org" "\x00\x00\x01\x00\x01" A_SUFFIX
),
// Setting all bits in a query other than QR and RD (i.e., OPCODE, AA, TC, RA,
// Z, and RCODE) yields a response with only QR (0x8000) and AA (0x0400) set.
/*
$ (perl -e 'print "\x12\x34\x7e\xff\x00\x01\x00\x00\x00\x00\x00\x00\x03rsf\x03org\x00\x00\x01\x00\x01"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   12 34 7E FF 00 01 00 00   00 00 00 00 03 72 73 66   .4~..... .....rsf
[0010]   03 6F 72 67 00 00 01 00   01                        .org.... .
[0000]   12 34 84 00 00 01 00 01   00 00 00 00 03 72 73 66   .4...... .....rsf
[0010]   03 6F 72 67 00 00 01 00   01 C0 0C 00 01 00 01 00   .org.... ........
[0020]   00 00 D0 00 04 32 75 75   2A                        .....2uu *
*/
TEST(
	"\x12\x34\x7e\xff\x00\x01\x00\x00\x00\x00\x00\x00" "\x03" "rsf" "\x03" "org" "\x00\x00\x01\x00\x01", false,
	"\x12\x34\x84\x00\x00\x01\x00\x01\x00\x00\x00\x00" "\x03" "rsf" "\x03" "org" "\x00\x00\x01\x00\x01" A_SUFFIX
),
// Messages with QR=1 (indicating a response) never get an injection.
/*
$ (perl -e 'print "\x12\x34\x80\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03rsf\x03org\x00\x00\x01\x00\x01"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   12 34 80 00 00 01 00 00   00 00 00 00 03 72 73 66   .4...... .....rsf
[0010]   03 6F 72 67 00 00 01 00   01                        .org.... .
*/
TEST(
	"\x12\x34\x80\x00\x00\x01\x00\x00\x00\x00\x00\x00" "\x03" "rsf" "\x03" "org" "\x00\x00\x01\x00\x01", false,
	""
),

/*
$ (perl -e 'print "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x0agoogle.com\xff\xaa\xaa\x00\x01"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   12 34 01 00 00 01 00 00   00 00 00 00 03 77 77 77   .4...... .....www
[0010]   0A 67 6F 6F 67 6C 65 2E   63 6F 6D FF AA AA 00 01   .google. com.....
[0000]   12 34 81 80 00 01 00 01   00 00 00 00 03 77 77 77   .4...... .....www
[0010]   0A 67 6F 6F 67 6C 65 2E   63 6F 6D FF AA AA 00 01   .google. com.....
[0020]   CB 87 55 82 2E 39 90 5E   CD 40 FD 2A 45 A3 CC 56   ..U..9.^ .@.*E..V
[0030]   1F 49 8B 20 ED 1D F6 60   00 F2 90 17 9B 1F 8E 7C   .I. ...` .......|
[0040]   4F 61 46 6F 4E 38 78 03   E9 98 F9 D9 81 20 8E 52   OaFoN8x. ..... .R
[0050]   30 15 71 70 CC D7 4B 29   DA DC DE F4 90 0E C3 B0   0.qp..K) ........
[0060]   8B 74 46 D5 E2 5B 33 B0   06 67 BC 77 3F 12 09 FE   .tF..[3. .g.w?...
[0070]   EC BF E4 4C 1B 09 27 E5   6D 5D 87 E6 68 32 E6 35   ...L..'. m]..h2.5
[0080]   76 B2 D6 D5 C1 43 B8 C3   B1 BC 6E 20 44 30 C0 0C   v....C.. ..n D0..
[0090]   00 01 00 01 00 00 00 83   00 04 9D F0 02 24         ........ .....$
*/
TEST(
	"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" "\x03" "www" "\x0a" "google.com" "\xff" "\xaa\xaa\x00\x01", false,
	"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x03" "www" "\x0a" "google.com" "\xff" "\xaa\xaa\x00\x01"
	"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	A_SUFFIX
),

/*
$ (perl -e 'print "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x0agoogle.com\xff\xaa\xaa\x00\x02"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   12 34 01 00 00 01 00 00   00 00 00 00 03 77 77 77   .4...... .....www
[0010]   0A 67 6F 6F 67 6C 65 2E   63 6F 6D FF AA AA 00 02   .google. com.....
*/
TEST(
	"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" "\x03" "www" "\x0a" "google.com" "\xff" "\xaa\xaa\x00\x02", false,
	""
),

/*
$ (perl -e 'print "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x0agoogle.com\xff\xaa\xaa\x00"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   12 34 01 00 00 01 00 00   00 00 00 00 03 77 77 77   .4...... .....www
[0010]   0A 67 6F 6F 67 6C 65 2E   63 6F 6D FF AA AA 00      .google. com....
*/
TEST(
	"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" "\x03" "www" "\x0a" "google.com" "\xff" "\xaa\xaa\x00", false,
	""
),

/*
$ (perl -e 'print "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x0agoogle.com\xff\xaa\xaa\x00"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   12 34 01 00 00 01 00 00   00 00 00 00 03 77 77 77   .4...... .....www
[0010]   0A 67 6F 6F 67 6C 65 2E   63 6F 6D FF AA AA 00      .google. com....
*/
TEST(
	"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" "\x03" "www" "\x0a" "google.com" "\xff" "\xaa\xaa\x00", false,
	""
),

/*
$ (perl -e 'print "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x0agoogle.com\x20\x00\x1c\x00\x01"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   12 34 01 00 00 01 00 00   00 00 00 00 03 77 77 77   .4...... .....www
[0010]   0A 67 6F 6F 67 6C 65 2E   63 6F 6D 20 00 1C 00 01   .google. com ....
*/
TEST(
	"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" "\x03" "www" "\x0a" "google.com" "\x20" "\xaa\xaa\x00\x01", false,
	""
),

/*
$ (perl -e 'print "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x0agoogle.com\x6e\xaa\xaa\x00\x01"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   12 34 01 00 00 01 00 00   00 00 00 00 03 77 77 77   .4...... .....www
[0010]   0A 67 6F 6F 67 6C 65 2E   63 6F 6D 6E AA AA 00 01   .google. comn....
*/
TEST(
	"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" "\x03" "www" "\x0a" "google.com" "\x6e" "\xaa\xaa\x00\x01", false,
	""
),

// 0x6f (= 110) seems to be the threshold.
/*
$ (perl -e 'print "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x0agoogle.com\x6f\xaa\xaa\x00\x01"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   12 34 01 00 00 01 00 00   00 00 00 00 03 77 77 77   .4...... .....www
[0010]   0A 67 6F 6F 67 6C 65 2E   63 6F 6D 6F AA AA 00 01   .google. como....
[0000]   12 34 81 80 00 01 00 01   00 00 00 00 03 77 77 77   .4...... .....www
[0010]   0A 67 6F 6F 67 6C 65 2E   63 6F 6D 6F AA AA 00 01   .google. como....
[0020]   F7 21 0B 3E 43 D2 AF F2   98 E3 D3 A0 F5 4D 82 77   .!.>C... .....M.w
[0030]   4A F3 DE 1C 17 D8 42 9C   F7 11 B3 08 58 D6 61 F6   J.....B. ....X.a.
[0040]   25 D3 DE F3 B0 22 9C 1B   04 0E 48 11 FA 2F 2D A4   %....".. ..H../-.
[0050]   E8 E5 44 2F D6 BF 1D B9   78 8B 53 51 B2 87 F2 91   ..D/.... x.SQ....
[0060]   F4 05 79 04 BD 03 7E 26   4D FE 85 2C C1 99 D5 85   ..y...~& M..,....
[0070]   EE C8 81 6F 7E 79 74 D0   A8 FB 0B 04 C8 1C BD 7F   ...o~yt. ........
[0080]   58 7D B1 A1 1D D0 AA 3C   E0 8E 21 B8 FA E9 C0 0C   X}.....< ..!.....
[0090]   00 01 00 01 00 00 00 8E   00 04 AE 24 E4 88         ........ ...$..
*/
TEST(
	"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" "\x03" "www" "\x0a" "google.com" "\x6f" "\xaa\xaa\x00\x01", false,
	"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x03" "www" "\x0a" "google.com" "\x6f" "\xaa\xaa\x00\x01"
	"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	A_SUFFIX
),

/*
$ (perl -e 'print "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\xff\xaa\xaa\x00\x0awww.google.com\x00"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   12 34 01 00 00 01 00 00   00 00 00 00 FF AA AA 00   .4...... ........
[0010]   0A 77 77 77 2E 67 6F 6F   67 6C 65 2E 63 6F 6D 00   .www.goo gle.com.
*/
TEST(
	"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" "\xff" "\xaa\xaa\x00\x01.www.google.com\x00", false,
	""
),

/*
$ (perl -e 'print "\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x10shadowvpn.com.\xaa\xaa\x00\x00\x01\x00\x01"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   33 33 01 20 00 01 00 00   00 00 00 00 10 73 68 61   33. .... .....sha
[0010]   64 6F 77 76 70 6E 2E 63   6F 6D 2E AA AA 00 00 01   dowvpn.c om......
[0020]   00 01                                               ..
[0000]   33 33 81 80 00 01 00 01   00 00 00 00 10 73 68 61   33...... .....sha
[0010]   64 6F 77 76 70 6E 2E 63   6F 6D 2E AA AA 00 00 01   dowvpn.c om......
[0020]   00 01 C0 0C 00 01 00 01   00 00 00 51 00 04 67 F0   ........ ...Q..g.
[0030]   B6 37                                               .7
[0000]   33 33 81 80 00 01 00 01   00 00 00 00 09 73 68 61   33...... .....sha
[0010]   64 6F 77 76 70 6E 03 63   6F 6D 02 AA AA 00 00 01   dowvpn.c om......
[0020]   00 01 C0 0C 00 01 00 01   00 00 00 FA 00 04 A2 7D   ........ .......}
[0030]   20 0F                                                .
*/
TEST(
	"\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x10" "shadowvpn.com.\xaa\xaa" "\x00" "\x00\x01\x00\x01", false,
	"\x33\x33\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x10" "shadowvpn.com.\xaa\xaa" "\x00" "\x00\x01\x00\x01"
	A_SUFFIX
),

/*
$ (perl -e 'print "\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x0dshadowvpn.com\xff\xaa\xaa\x00\x01"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   33 33 01 20 00 01 00 00   00 00 00 00 0D 73 68 61   33. .... .....sha
[0010]   64 6F 77 76 70 6E 2E 63   6F 6D FF AA AA 00 01      dowvpn.c om.....
[0000]   33 33 81 80 00 01 00 01   00 00 00 00 0D 73 68 61   33...... .....sha
[0010]   64 6F 77 76 70 6E 2E 63   6F 6D FF AA AA 00 01 CD   dowvpn.c om......
[0020]   1C C8 73 D0 12 23 28 12   CE 38 17 57 0C 55 A5 8F   ..s..#(. .8.W.U..
[0030]   9B E9 A5 BB 92 69 69 E9   65 7F 9F A0 C3 78 DD D2   .....ii. e....x..
[0040]   DE F1 66 1E 43 5F 7C EA   1E 71 2C B3 E8 B4 3F C4   ..f.C_|. .q,...?.
[0050]   47 EA 97 6F 57 21 4A F2   2D 57 B6 17 A1 DD 83 CA   G..oW!J. -W......
[0060]   07 E6 A7 29 52 3E 1A 7C   AB 29 FA 42 F5 FF F9 ED   ...)R>.| .).B....
[0070]   19 DD FA AD 5D 83 86 E9   B7 6B 0E 8A 83 17 5E 78   ....]... .k....^x
[0080]   58 E8 46 18 F4 18 B9 8E   CE E8 EA 36 2B 3F C0 0C   X.F..... ...6+?..
[0090]   00 01 00 01 00 00 00 7B   00 04 6C A0 A9 2E         .......{ ..l...
*/
TEST(
	"\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x0d" "shadowvpn.com" "\xff" "\xaa\xaa" "\x00\x01", false,
	"\x33\x33\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" "\x0d" "shadowvpn.com" "\xff" "\xaa\xaa" "\x00\x01"
	"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	A_SUFFIX
),

// After the final label length, it's still within the qname bounds, so the 'X'
// garbage byte is interpreted as another label length.
/*
$ (perl -e 'print "\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x0dshadowvpn.com\x20\xaa\xaa\x00\x01"'; cat) | ncat -x /dev/stderr --udp 212.64.11.0 53 > /dev/null
[0000]   33 33 01 20 00 01 00 00   00 00 00 00 0D 73 68 61   33. .... .....sha
[0010]   64 6F 77 76 70 6E 2E 63   6F 6D 20 AA AA 00 01      dowvpn.c om ....
*/
TEST(
	"\x33\x33\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" "\x0d" "shadowvpn.com" "\x20" "\xaa\xaa" "\x00\x01", false,
	""
),
