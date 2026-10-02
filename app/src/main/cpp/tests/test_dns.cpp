// Host tests for the DNS spoofing query parser and answer builder.
//
// These deliberately run on the host rather than only on a device: a spoofed
// answer is judged on exact bytes, and bytes are far easier to reason about
// here than through a live ARP-poisoned network. Every case below is a mistake
// that would have produced a plausible-looking but useless packet.
#include "../zs_dns.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static int gFail = 0, gRun = 0;
#define CHECK(cond, msg)                                                     \
  do {                                                                       \
    gRun++;                                                                  \
    if (!(cond)) {                                                           \
      gFail++;                                                               \
      std::printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, (msg));          \
    }                                                                        \
  } while (0)

// Builds a query the way a real resolver's client would, so the tests exercise
// the same encoding path rather than a convenient one.
static std::vector<uint8_t> query(uint16_t id, const std::string& name,
                                  int qtype, bool asResponse = false) {
  std::vector<uint8_t> d;
  d.push_back(uint8_t(id >> 8));
  d.push_back(uint8_t(id & 0xff));
  d.push_back(asResponse ? 0x81 : 0x01);
  d.push_back(0x00);
  d.push_back(0x00); d.push_back(0x01);   // QDCOUNT
  d.push_back(0x00); d.push_back(0x00);   // ANCOUNT
  d.push_back(0x00); d.push_back(0x00);   // NSCOUNT
  d.push_back(0x00); d.push_back(0x00);   // ARCOUNT
  size_t start = 0;
  while (start < name.size()) {
    size_t dot = name.find('.', start);
    if (dot == std::string::npos) dot = name.size();
    size_t l = dot - start;
    d.push_back(uint8_t(l));
    d.insert(d.end(), name.begin() + start, name.begin() + dot);
    start = dot + 1;
  }
  d.push_back(0x00);
  d.push_back(uint8_t(qtype >> 8));
  d.push_back(uint8_t(qtype & 0xff));
  d.push_back(0x00); d.push_back(0x01);   // CLASS IN
  return d;
}

static uint16_t rd16(const std::vector<uint8_t>& d, size_t p) {
  return uint16_t((d[p] << 8) | d[p + 1]);
}

int main() {
  // ---- the normal case ----------------------------------------------------
  {
    auto q = query(0xBEEF, "example.com", 1);
    DnsQuery parsed;
    CHECK(parsed.parse(q.data(), q.size()), "example.com must parse");
    CHECK(parsed.id == 0xBEEF, "id must round-trip");
    CHECK(parsed.name == "example.com", "name must decode to dotted form");
    CHECK(parsed.qtype == 1, "qtype must be A");
    CHECK(parsed.questionAt == 12, "question starts right after the header");
    CHECK(parsed.questionLen == q.size() - 12, "question covers name+qtype+qclass");
  }

  // ---- single-label and trailing-dot names --------------------------------
  {
    auto q = query(1, "localhost", 1);
    DnsQuery p;
    CHECK(p.parse(q.data(), q.size()), "single-label name must parse");
    CHECK(p.name == "localhost", "single label has no dot to synthesise");
  }
  {
    // "a.b." encodes identically to "a.b" -- a trailing dot is a root label
    // and must not become an empty trailing component.
    auto q = query(1, "a.b", 1);
    DnsQuery p;
    CHECK(p.parse(q.data(), q.size()) && p.name == "a.b", "short name ok");
  }

  // ---- a response is not a query -----------------------------------------
  {
    auto q = query(1, "example.com", 1, /*asResponse=*/true);
    DnsQuery p;
    CHECK(!p.parse(q.data(), q.size()),
          "must reject QR=1, or we would answer a reply and amplify");
  }

  // ---- truncation and junk ------------------------------------------------
  {
    DnsQuery p;
    CHECK(!p.parse(nullptr, 0), "null buffer must be rejected");
    std::vector<uint8_t> tiny = {0x00, 0x01};
    CHECK(!p.parse(tiny.data(), tiny.size()), "shorter than a header is rejected");
    std::vector<uint8_t> hdr(12, 0);
    CHECK(!p.parse(hdr.data(), hdr.size()), "QDCOUNT=0 has nothing to answer");
  }

  // ---- compression pointer inside a question ------------------------------
  {
    // A pointer can never legitimately appear in a question being asked, and
    // following one would let a hostile packet make the parser walk a huge or
    // looping name.
    auto q = query(1, "example.com", 1);
    q[12] = 0xC0; q[13] = 0x2C;
    DnsQuery p;
    CHECK(!p.parse(q.data(), q.size()), "compression pointer must be rejected");
  }

  // ---- label longer than the 63 bytes DNS allows --------------------------
  {
    std::string big(64, 'a');
    auto q = query(1, big + ".com", 1);
    DnsQuery p;
    CHECK(!p.parse(q.data(), q.size()), "64-byte label is malformed");
  }

  // ---- name longer than the 255 bytes DNS allows --------------------------
  {
    std::string name;
    for (int i = 0; i < 40; i++) name += "abcdefghi.";   // 400 bytes
    auto q = query(1, name, 1);
    DnsQuery p;
    CHECK(!p.parse(q.data(), q.size()), "over-long name must be rejected");
  }

  // ---- qtype is reported, not assumed -------------------------------------
  {
    auto q = query(1, "example.com", 28);   // AAAA
    DnsQuery p;
    CHECK(p.parse(q.data(), q.size()) && p.qtype == 28, "AAAA must be reported");
  }

  // ---- the answer ---------------------------------------------------------
  {
    auto q = query(0x1234, "example.com", 1);
    DnsQuery parsed;
    parsed.parse(q.data(), q.size());
    std::vector<uint8_t> out;
    bool built = buildDnsAnswer(parsed, q.data(), q.size(), "1.2.3.4", &out);
    CHECK(built, "answer must be built");
    if (!built) { std::printf("%d checks, %d failure(s)\n", gRun, gFail); return 1; }

    CHECK(rd16(out, 0) == 0x1234, "answer echoes the query id or it is discarded");
    CHECK((out[2] & 0x80) != 0, "QR must be set on a reply");
    // AA is bit 10 of the 16-bit flags word, i.e. 0x10 of the *first* byte.
    CHECK((out[2] & 0x10) != 0, "AA must be set so a stub resolver stops asking");
    CHECK((out[2] & 0x01) != 0, "RD must be echoed back from the query");
    CHECK((out[3] & 0x80) != 0, "RA must be set");
    CHECK(rd16(out, 4) == 1, "QDCOUNT echoed");
    CHECK(rd16(out, 6) == 1, "ANCOUNT must be 1");
    // The question must be byte-identical to what was asked.
    // Question section copied verbatim.
    CHECK(std::memcmp(out.data() + 12, q.data() + 12, parsed.questionLen) == 0,
          "question must be copied byte for byte");
    // Answer name is a compression pointer to offset 12.
    size_t rr = 12 + parsed.questionLen;
    CHECK(out[rr] == 0xC0 && out[rr + 1] == 12, "answer name points at the question");
    CHECK(rd16(out, rr + 2) == 1, "answer TYPE must be A");
    CHECK(rd16(out, rr + 4) == 1, "answer CLASS must be IN");
    // TTL is four bytes, so everything after it shifts by four. Reading
    // RDLENGTH at rr+8 would have compared against the low half of the TTL and
    // passed a packet with a broken answer.
    CHECK(rd16(out, rr + 6) == 0 && rd16(out, rr + 8) == 60, "answer TTL is 60s");
    CHECK(rd16(out, rr + 10) == 4, "answer RDLENGTH is 4 for an IPv4 address");
    CHECK(out[rr + 12] == 1 && out[rr + 13] == 2 && out[rr + 14] == 3 &&
              out[rr + 15] == 4,
          "RDATA must be the requested address");

    size_t expect = 12 + parsed.questionLen + 16;
    CHECK(out.size() == expect, "no trailing bytes");
  }

  // ---- a bad answer address is refused, not half-written ------------------
  {
    auto q = query(1, "example.com", 1);
    DnsQuery parsed;
    parsed.parse(q.data(), q.size());
    std::vector<uint8_t> out;
    CHECK(!buildDnsAnswer(parsed, q.data(), q.size(), "not-an-ip", &out),
          "a non-address must produce no packet at all");
    CHECK(out.empty(), "a refused answer must leave the buffer untouched");
    for (const char* bad : {"1.2.3", "1.2.3.4.5", "999.1.1.1", "", "::1"}) {
      std::vector<uint8_t> t;
      CHECK(!buildDnsAnswer(parsed, q.data(), q.size(), bad, &t),
            "malformed address must be refused");
    }
  }

  // ---- a rejected parser state cannot be used to build -------------------
  {
    DnsQuery bad;   // never parsed successfully
    auto q = query(1, "example.com", 1);
    DnsQuery parsed;
    parsed.parse(q.data(), q.size());
    std::vector<uint8_t> out;
    // A DnsQuery that was never parsed successfully has questionLen 0; one
    // claiming more than the message holds must also be refused.
    CHECK(!buildDnsAnswer(bad, q.data(), q.size(), "1.2.3.4", &out),
          "an unparsed DnsQuery must not be buildable");
    bad.questionAt = 0;
    bad.questionLen = q.size() + 8;
    CHECK(!buildDnsAnswer(bad, q.data(), q.size(), "1.2.3.4", &out),
          "question bounds beyond the query must be refused");
    CHECK(!buildDnsAnswer(parsed, nullptr, 0, "1.2.3.4", &out),
          "a null query must be refused");
    CHECK(!buildDnsAnswer(parsed, q.data(), q.size(), "1.2.3.4", nullptr),
          "a null output must be refused");
  }

  // ---- name matching is case-insensitive, and exact ----------------------
  {
    CHECK(dnsNameMatches("example.com", "example.com"), "exact match");
    CHECK(dnsNameMatches("EXAMPLE.com", "example.com"), "DNS names are caseless");
    CHECK(dnsNameMatches("Example.Com", "EXAMPLE.COM"), "mixed case both ways");
    CHECK(!dnsNameMatches("notexample.com", "example.com"),
          "a suffix is not a match; evil-example.com must not be spoofed as example.com");
    CHECK(!dnsNameMatches("example.com.evil.net", "example.com"),
          "a prefix is not a match either");
    CHECK(!dnsNameMatches("example.co", "example.com"), "a shorter name is not it");
    CHECK(!dnsNameMatches("", "example.com"), "empty query name matches nothing");
    CHECK(!dnsNameMatches("example.com", ""), "empty want matches nothing");
    CHECK(!dnsNameMatches("", ""), "two empty strings are not a match");
  }

  std::printf("\n%d checks, %d failure(s)\n", gRun, gFail);
  if (gFail) return 1;
  std::printf("ALL PASS (0 failure(s))\n");
  return 0;
}
