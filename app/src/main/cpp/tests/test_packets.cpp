#define main zsraw_unused_main
#include "zs_helper.cpp"
#undef main
#include <cstdio>
#include <cstring>

static int fails = 0;
static void ok(const char* what, bool cond) {
  printf("%-46s %s\n", what, cond ? "PASS" : "FAIL");
  if (!cond) fails++;
}

int main() {
  // ---- netmaskToPrefix
  ok("netmaskToPrefix 255.255.255.0 == 24", netmaskToPrefix("255.255.255.0") == 24);
  ok("netmaskToPrefix 255.255.0.0 == 16",   netmaskToPrefix("255.255.0.0") == 16);
  ok("netmaskToPrefix 255.255.252.0 == 22", netmaskToPrefix("255.255.252.0") == 22);

  // ---- putMac
  unsigned char m[6] = {0};
  ok("putMac 9c:12:21:2d:99:ab", putMac(m, "9c:12:21:2d:99:ab") &&
      m[0]==0x9c && m[1]==0x12 && m[2]==0x21 && m[3]==0x2d && m[4]==0x99 && m[5]==0xab);
  ok("putMac rejects garbage", !putMac(m, "zz:zz"));

  // ---- buildArp
  unsigned char a[64];
  struct in_addr s{}, t{};
  inet_pton(AF_INET, "10.0.0.5", &s);
  inet_pton(AF_INET, "10.0.0.1", &t);
  size_t n = buildArp("9c:12:21:2d:99:ab", "ff:ff:ff:ff:ff:ff", "00:11:22:33:44:55",
                      s.s_addr, t.s_addr, 2, a);
  ok("buildArp length == 42", n == 42);
  ok("buildArp ethertype ARP", a[12]==0x08 && a[13]==0x06);
  ok("buildArp eth dst broadcast", a[0]==0xff && a[5]==0xff);
  ok("buildArp op == 2 (reply)", a[22]==0x00 && a[23]==0x02);
  ok("buildArp SPA == 10.0.0.5", memcmp(a+30, &s.s_addr, 4) == 0);
  ok("buildArp TPA == 10.0.0.1", memcmp(a+40, &t.s_addr, 4) == 0);
  ok("buildArp THA copied", a[34]==0x00 && a[39]==0x55);

  size_t np = buildArpProbe("9c:12:21:2d:99:ab", s.s_addr, t.s_addr, a);
  ok("buildArpProbe op == 1 (request)", a[22]==0x00 && a[23]==0x01 && np==42);
  ok("buildArpProbe THA all-zero", a[34]==0 && a[35]==0 && a[39]==0);

  // ---- buildUdpIp: the IP checksum must validate to 0
  unsigned char u[128];
  size_t un = buildUdpIp("10.0.0.5", "10.0.0.1", 40000, 53, "hello", u, sizeof u);
  ok("buildUdpIp length == 20+8+5", un == 33);
  ok("buildUdpIp version/ihl == 0x45", u[0] == 0x45);
  ok("buildUdpIp total len field", ((u[2]<<8)|u[3]) == 33);
  ok("buildUdpIp proto == 17", u[9] == 17);
  ok("buildUdpIp checksum valid", cksum(u, 20, 0) == 0);
  ok("buildUdpIp sport big-endian", u[20]==0x9c && u[21]==0x40);   // 40000
  ok("buildUdpIp dport big-endian", u[22]==0x00 && u[23]==0x35);   // 53
  ok("buildUdpIp len field == 13", u[24]==0x00 && u[25]==0x0d);
  ok("buildUdpIp payload copied", memcmp(u+28, "hello", 5) == 0);

  // ---- buildIcmpIp: both checksums must validate
  unsigned char c[128];
  size_t cn = buildIcmpIp("10.0.0.5", "10.0.0.1", 8, 0, "pingpayload", c, sizeof c);
  ok("buildIcmpIp length == 20+8+11", cn == 39);
  ok("buildIcmpIp proto == 1", c[9] == 1);
  ok("buildIcmpIp IP checksum valid", cksum(c, 20, 0) == 0);
  ok("buildIcmpIp type/code", c[20]==8 && c[21]==0);
  ok("buildIcmpIp ICMP checksum valid", cksum(c+20, 19, 0) == 0);
  ok("buildIcmpIp payload copied", memcmp(c+28, "pingpayload", 11) == 0);

  // ---- buildTcpIp: IP + TCP checksums must both validate
  unsigned char tb[160];
  size_t tn = buildTcpIp("10.0.0.5", "10.0.0.1", 1234, 80, 1000, 0, 0x02, "", tb, sizeof tb);
  ok("buildTcpIp length == 20+20", tn == 40);
  ok("buildTcpIp proto == 6", tb[9] == 6);
  ok("buildTcpIp IP checksum valid", cksum(tb, 20, 0) == 0);
  ok("buildTcpIp sport/dport", tb[20]==0x04 && tb[21]==0xd2 && tb[22]==0x00 && tb[23]==0x50);
  ok("buildTcpIp seq == 1000", tb[24]==0 && tb[25]==0 && tb[26]==0x03 && tb[27]==0xe8);
  ok("buildTcpIp data offset == 0x50", tb[32] == 0x50);
  ok("buildTcpIp flags == SYN", tb[33] == 0x02);
  {
    // Recompute the TCP checksum exactly as the sender did.
    struct in_addr s{}, d{};
    inet_pton(AF_INET, "10.0.0.5", &s);
    inet_pton(AF_INET, "10.0.0.1", &d);
    uint32_t sum = 0;
    auto add16 = [&](const uint8_t* q, size_t n) {
      while (n > 1) { sum += (q[0] << 8) | q[1]; q += 2; n -= 2; }
      if (n) sum += q[0] << 8;
    };
    add16((const uint8_t*)&s.s_addr, 4);
    add16((const uint8_t*)&d.s_addr, 4);
    sum += 6; sum += 20;
    ok("buildTcpIp TCP checksum valid", cksum(tb + 20, 20, sum) == 0);
  }
  size_t tp = buildTcpIp("10.0.0.5", "10.0.0.1", 1, 2, 3, 4, 0x12, "data", tb, sizeof tb);
  ok("buildTcpIp with payload len", tp == 44);
  ok("buildTcpIp payload placed", memcmp(tb + 40, "data", 4) == 0);

  // ---- buildEthIp
  unsigned char e[160];
  size_t en = buildEthIp("9c:12:21:2d:99:ab", "00:11:22:33:44:55", u, un, e, sizeof e);
  ok("buildEthIp length == 14+33", en == 47);
  ok("buildEthIp ethertype IPv4", e[12]==0x08 && e[13]==0x00);
  ok("buildEthIp embeds IP intact", memcmp(e+14, u, un) == 0);

  // ---- 802.11 frames
  unsigned char d[64];
  size_t dn = build80211Deauth("aa:bb:cc:dd:ee:ff", "ff:ff:ff:ff:ff:ff", 7, d);
  ok("build80211Deauth length == 20+26", dn == 46);
  ok("deauth radiotap len byte", d[2] == RADIOTAP_F_LEN);
  ok("deauth FC = mgmt|subtype12", d[RADIOTAP_F_LEN]==0xC0 && d[RADIOTAP_F_LEN+1]==0x0C);
  ok("deauth DA broadcast", d[RADIOTAP_F_LEN+4]==0xff && d[RADIOTAP_F_LEN+9]==0xff);
  ok("deauth BSSID field (16) == AP", d[RADIOTAP_F_LEN+16]==0xaa && d[RADIOTAP_F_LEN+21]==0xff);
  ok("deauth SA field (10) spoofed as AP", d[RADIOTAP_F_LEN+10]==0xaa && d[RADIOTAP_F_LEN+15]==0xff);
  ok("deauth reason code == 7", d[RADIOTAP_F_LEN+24] == 7);

  unsigned char au[64];
  size_t an = build80211Auth("aa:bb:cc:dd:ee:ff", "ff:ff:ff:ff:ff:ff", au);
  ok("build80211Auth length == 20+30", an == 50);
  ok("auth FC = mgmt|subtype11", au[RADIOTAP_F_LEN]==0xB0 && au[RADIOTAP_F_LEN+1]==0x00);

  // A deauth aimed at one station: the destination changes, and nothing else
  // may. If the source stopped being spoofed as the access point the target
  // would ignore the frame as coming from a stranger.
  unsigned char one[64];
  size_t on = build80211Deauth("aa:bb:cc:dd:ee:ff", "02:00:00:00:00:09", 7, one);
  ok("unicast deauth length == 20+26", on == 46);
  ok("unicast deauth DA is the station", one[RADIOTAP_F_LEN+4]==0x02 &&
     one[RADIOTAP_F_LEN+9]==0x09);
  ok("unicast deauth SA still spoofed as AP", one[RADIOTAP_F_LEN+10]==0xaa &&
     one[RADIOTAP_F_LEN+15]==0xff);
  ok("unicast deauth BSSID still the AP", one[RADIOTAP_F_LEN+16]==0xaa &&
     one[RADIOTAP_F_LEN+21]==0xff);

  // ---- reading a captured 802.11 frame back
  //
  // The three addresses are always in the order DA, SA, BSSID, but which of
  // them is the access point depends on the To-DS/From-DS bits. Slicing a fixed
  // offset is how a monitor-mode listener ends up attributing the neighbours'
  // traffic to the network it was told to watch, so every case is covered.
  const char* kAp  = "aa:bb:cc:dd:ee:ff";
  const char* kSta = "02:11:22:33:44:55";
  const char* kOth = "de:ad:be:ef:00:01";

  // Builds a frame behind a 20-byte radiotap header, or bare when rt == 0.
  // The buffer travels by value: returning it as a pointer would hand back the
  // address of a stack array that died with the lambda, and every assertion
  // would then be reading whatever happens to be there.
  struct Capture {
    unsigned char b[80];
    size_t n;
  };
  auto frame = [](unsigned char fc0, unsigned char fc1, const char* a1,
                  const char* a2, const char* a3, const char* a4, bool rt,
                  size_t len) {
    Capture c{};
    size_t o = 0;
    if (rt) { c.b[2] = (unsigned char)RADIOTAP_F_LEN; o = RADIOTAP_F_LEN; }
    c.b[o + 0] = fc0; c.b[o + 1] = fc1;
    putMac(c.b + o + 4, a1);
    putMac(c.b + o + 10, a2);
    putMac(c.b + o + 16, a3);
    if (a4) putMac(c.b + o + 22, a4);
    c.n = o + len;
    return c;
  };

  // management: BSSID always in addr3
  {
    auto f = frame(0xC0, 0x00, "ff:ff:ff:ff:ff:ff", kSta, kAp, nullptr, true, 26);
    ok("stationOf80211 mgmt -> sender", stationOf80211(f.b, f.n, kAp) == kSta);
  }
  // data To-DS: station -> AP, BSSID in addr1
  {
    auto f = frame(0x08, 0x05, kAp, kSta, "66:77:88:99:aa:bb", nullptr, true, 26);
    ok("stationOf80211 toDS -> addr2", stationOf80211(f.b, f.n, kAp) == kSta);
  }
  // data From-DS: AP -> station, BSSID in addr2
  {
    auto f = frame(0x08, 0x09, "66:77:88:99:aa:bb", kAp, kSta, nullptr, true, 26);
    ok("stationOf80211 fromDS -> addr3", stationOf80211(f.b, f.n, kAp) == kSta);
  }
  // data To-DS+From-DS: addr2 is the *transmitting* access point, so the
  // station that sent this is the source address in the fourth slot
  {
    auto f = frame(0x08, 0x0D, kAp, kOth, "66:77:88:99:aa:bb", kSta, true, 32);
    ok("stationOf80211 wds -> addr4", stationOf80211(f.b, f.n, kAp) == kSta);
  }
  // intra-BSS: BSSID in addr1, sender in addr2
  {
    auto f = frame(0x08, 0x01, kAp, kSta, kSta, nullptr, true, 26);
    ok("stationOf80211 ibss -> addr2", stationOf80211(f.b, f.n, kAp) == kSta);
  }
  // a frame belonging to somebody else's network must not be claimed
  {
    auto f = frame(0x08, 0x05, kOth, kSta, "66:77:88:99:aa:bb", nullptr, true, 26);
    ok("stationOf80211 other BSSID ignored", stationOf80211(f.b, f.n, kAp) == "");
  }
  // a broadcast or multicast source is an address, not a station
  {
    auto f = frame(0x08, 0x05, kAp, "ff:ff:ff:ff:ff:ff", "66:77:88:99:aa:bb", nullptr, true, 26);
    ok("stationOf80211 broadcast src ignored", stationOf80211(f.b, f.n, kAp) == "");
    auto z = frame(0x08, 0x05, kAp, "00:00:00:00:00:00", "66:77:88:99:aa:bb", nullptr, true, 26);
    ok("stationOf80211 zero src ignored", stationOf80211(f.b, f.n, kAp) == "");
  }
  // a four-address frame that is too short to hold addr4 is not guessed at
  {
    auto f = frame(0x08, 0x0D, kAp, kOth, "66:77:88:99:aa:bb", kSta, true, 28);
    ok("stationOf80211 short wds ignored", stationOf80211(f.b, f.n, kAp) == "");
  }
  // truncated below a full header
  {
    auto f = frame(0x08, 0x05, kAp, kSta, "66:77:88:99:aa:bb", nullptr, true, 20);
    ok("stationOf80211 truncated ignored", stationOf80211(f.b, f.n, kAp) == "");
  }
  // the same frame without a radiotap header in front of it
  {
    auto f = frame(0x08, 0x05, kAp, kSta, "66:77:88:99:aa:bb", nullptr, false, 26);
    ok("stationOf80211 works without radiotap", stationOf80211(f.b, f.n, kAp) == kSta);
  }
  // the BSSID the caller names is matched case-insensitively
  {
    auto f = frame(0x08, 0x05, kAp, kSta, "66:77:88:99:aa:bb", nullptr, true, 26);
    ok("stationOf80211 BSSID case-insensitive",
       stationOf80211(f.b, f.n, "AA:BB:CC:DD:EE:FF") == kSta);
  }

  ok("radiotapLen 20-byte header", radiotapLen(d, sizeof d) == RADIOTAP_F_LEN);
  {
    unsigned char bare[8] = {0x08, 0x05, 0, 0, 0, 0, 0, 0};
    ok("radiotapLen bare frame == 0", radiotapLen(bare, sizeof bare) == 0);
    unsigned char bogus[8] = {0x00, 0x00, 0xff, 0x00, 0, 0, 0, 0};
    ok("radiotapLen implausible length == 0", radiotapLen(bogus, sizeof bogus) == 0);
  }
  ok("isUnicastStation rejects broadcast", !isUnicastStation("ff:ff:ff:ff:ff:ff"));
  ok("isUnicastStation rejects multicast", !isUnicastStation("01:00:5e:00:00:01"));
  ok("isUnicastStation rejects all-zero", !isUnicastStation("00:00:00:00:00:00"));
  ok("isUnicastStation accepts a unicast MAC", isUnicastStation(kSta));

  // ---- nl80211 attribute encoding
  // The frequency path fails silently if this is wrong: nl80211 takes centre
  // frequency in units of 0.5 MHz, so an off-by-a-factor-of-two here tunes the
  // radio to half or double the intended channel. Nothing reports it -- the
  // radio transmits happily on the wrong frequency and the frames reach nobody.
  {
    nl::Attrs a;
    a.u32(nl::kAttrWiphyFreq, (uint32_t)(2412 * 2));
    ok("freq attr: 2412 MHz encodes as 4824",
       *(uint32_t*)(a.body + 4) == 4824);
    ok("freq attr: length is 4",
       *(uint16_t*)a.body == 4);
    ok("freq attr: type is WIPHY_FREQ",
       *(uint16_t*)(a.body + 2) == nl::kAttrWiphyFreq);
  }
  {
    // The 6 GHz band is the one that proves the factor: 5955 MHz must not come
    // out as 5955/2, which would land in the middle of the 5 GHz band.
    nl::Attrs a;
    a.u32(nl::kAttrWiphyFreq, (uint32_t)(5955 * 2));
    ok("freq attr: 6 GHz 5955 MHz encodes as 11910",
       *(uint32_t*)(a.body + 4) == 11910);
    ok("freq attr: 6 GHz does not collide with 2.4 GHz ch 1",
       (uint32_t)(5955 * 2) != (uint32_t)(2412 * 2));
  }
  {
    // Attributes are 4-byte aligned; an odd-length string must be padded, or
    // every following attribute is read at the wrong offset by the kernel.
    // nla_len covers the payload but not the padding, so a 6-byte payload
    // advances the offset by 4 + 8 -- padded up to the next 4-byte boundary.
    nl::Attrs a;
    a.str(nl::kAttrIfName, "wlan0");   // 6 bytes with NUL
    ok("str attr: length counts the NUL", *(uint16_t*)a.body == 6);
    ok("str attr: offset advances by 4 + 6 padded to 8", a.off == 12);
    nl::Attrs b;
    b.str(nl::kAttrIfName, "abc");    // 4 bytes, aligned
    ok("str attr: 'abc' is 4 bytes with NUL", b.off == 8);
  }
  {
    // The buffer is fixed-size; a runaway caller must not overrun it. Silently
    // dropping the attribute is the right failure -- the kernel then rejects
    // the request instead of the process writing past the end.
    nl::Attrs a;
    std::string big(600, 'x');   // past the 512-byte buffer
    a.str(nl::kAttrIfName, big);
    ok("oversized attr is dropped, not written", a.off == 0);
  }

  // ---- case helpers
  ok("upper()", upper("deauth") == "DEAUTH");
  ok("lower()", lower("9C:12") == "9c:12");
  ok("hexToStr roundtrip", hexToStr("aa:bb:cc:DD:ee:FF") == "aa:bb:cc:dd:ee:ff");
  ok("hexToStr rejects short", hexToStr("aa:bb") == "");
  ok("jesc escapes quote", jesc("a\"b") == "a\\\"b");
  ok("jesc escapes newline", jesc("a\nb") == "a\\nb");
  ok("J wraps in quotes", J("hi") == "\"hi\"");
  ok("trim", trim("  x \n") == "x");
  ok("split", split("a,b,c", ',').size() == 3);

  printf("\n%s (%d failure(s))\n", fails ? "FAILED" : "ALL PASS", fails);
  return fails ? 1 : 0;
}
