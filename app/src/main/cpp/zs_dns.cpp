#include "zs_dns.h"

#include <arpa/inet.h>
#include <cstring>

namespace {
// Returns how many bytes the label at `p` occupies, setting *ok false on any
// encoding this module refuses to follow.
//
// A length byte with either of its top two bits set is either a compression
// pointer or a reserved form. Neither can legitimately start a label in a
// question being asked, and honouring one would let a hostile packet aim the
// walk at a looping or enormous name.
size_t dnsLabel(const uint8_t* d, size_t len, size_t p, std::string* out,
                bool* ok) {
  size_t start = p;
  *ok = true;
  for (;;) {
    if (p >= len) { *ok = false; return 0; }
    uint8_t l = d[p];
    if ((l & 0xC0) != 0) { *ok = false; return 0; }
    p++;
    if (l == 0) return p - start;          // root label ends the name
    if (p + l > len) { *ok = false; return 0; }
    // One label is limited to 63 bytes; without this a crafted name could make
    // us walk a very long string inside a single frame.
    if (l > 63) { *ok = false; return 0; }
    if (out) {
      if (!out->empty()) *out += '.';
      out->append((const char*)d + p, l);
    }
    p += l;
    // A whole name is limited to 255 bytes on the wire.
    if (p - start > 255) { *ok = false; return 0; }
  }
}
}  // namespace

bool DnsQuery::parse(const uint8_t* d, size_t len) {
  if (!d || len < 12) return false;
  id = uint16_t((d[0] << 8) | d[1]);
  // QR set means this is already a reply. Answering one would put us in a
  // packet loop with whatever sent it.
  if ((d[2] & 0x80) != 0) return false;
  int qd = (d[4] << 8) | d[5];
  if (qd < 1) return false;                 // nothing to answer
  size_t p = 12;
  name.clear();
  bool ok = false;
  size_t n = dnsLabel(d, len, p, &name, &ok);
  if (!ok || n == 0) return false;
  p += n;
  if (p + 4 > len) return false;           // need qtype and qclass
  qtype = (d[p] << 8) | d[p + 1];
  questionAt = 12;
  questionLen = (p + 4) - 12;
  return true;
}

bool buildDnsAnswer(const DnsQuery& q, const uint8_t* query, size_t qlen,
                    const std::string& answerIp, std::vector<uint8_t>* out) {
  if (!query || !out) return false;
  if (q.questionAt + q.questionLen > qlen || q.questionLen == 0) return false;
  struct in_addr a{};
  if (inet_pton(AF_INET, answerIp.c_str(), &a) != 1) return false;

  std::vector<uint8_t> p;
  p.reserve(12 + q.questionLen + 16);
  p.push_back(uint8_t(q.id >> 8));
  p.push_back(uint8_t(q.id & 0xff));
  // The 16-bit flags word is QR|opcode|AA|TC|RD, then RA|Z|AD|CD|RCODE. AA is
  // in the *first* byte (bit 10), not alongside RA in the second -- with AA
  // unset a stub resolver keeps querying upstream and the spoof is a race we
  // would lose.
  p.push_back(0x91);   // QR=1, opcode 0, AA=1, RD=1 copied from the query
  p.push_back(0x80);   // RA=1
  p.push_back(0x00); p.push_back(0x01);   // QDCOUNT
  p.push_back(0x00); p.push_back(0x01);   // ANCOUNT
  p.push_back(0x00); p.push_back(0x00);   // NSCOUNT
  p.push_back(0x00); p.push_back(0x00);   // ARCOUNT
  // The question, verbatim.
  p.insert(p.end(), query + q.questionAt, query + q.questionAt + q.questionLen);
  // The answer: name as a pointer back to the question, A/IN, TTL, RDATA.
  p.push_back(0xC0); p.push_back(uint8_t(q.questionAt));
  p.push_back(0x00); p.push_back(0x01);   // TYPE A
  p.push_back(0x00); p.push_back(0x01);   // CLASS IN
  p.push_back(0x00); p.push_back(0x00);   // TTL 60s
  p.push_back(0x00); p.push_back(0x3C);
  p.push_back(0x00); p.push_back(0x04);   // RDLENGTH
  // s_addr is already in network byte order. Byte-shifting it by hand would
  // emit the address reversed -- 1.2.3.4 spoofed as 4.3.2.1 -- which is a
  // packet that looks entirely valid and resolves to the wrong host. memcpy
  // cannot get the order wrong.
  const uint8_t rdata[4] = {uint8_t(a.s_addr & 0xff), uint8_t((a.s_addr >> 8) & 0xff),
                            uint8_t((a.s_addr >> 16) & 0xff), uint8_t((a.s_addr >> 24) & 0xff)};
  p.insert(p.end(), rdata, rdata + 4);
  out->swap(p);
  return true;
}

bool dnsNameMatches(const std::string& name, const std::string& want) {
  if (want.empty() || name.empty()) return false;
  if (name.size() != want.size()) return false;
  for (size_t i = 0; i < name.size(); i++) {
    char a = name[i], b = want[i];
    if (a >= 'A' && a <= 'Z') a = char(a - 'A' + 'a');
    if (b >= 'A' && b <= 'Z') b = char(b - 'A' + 'a');
    if (a != b) return false;
  }
  return true;
}
