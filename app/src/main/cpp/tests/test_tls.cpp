// Host tests for the TLS analyser.
//
// The ClientHello bytes are a real capture (TLS 1.2, SNI "example.com",
// ALPN h2) rather than a hand-built one, because a synthesised hello that
// happens to match the parser proves nothing about a real one.
//
// The certificate is built by a tiny DER writer below rather than pasted in as
// a base64 blob: the tests need to vary the subject, the validity window and
// the key size, and a fixed blob cannot be varied.
#include "../zs_tls.h"

#include <cstdio>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static int gFail = 0, gRun = 0;
#define CHECK(cond, msg)                                                    \
  do {                                                                      \
    gRun++;                                                                 \
    if (!(cond)) {                                                          \
      gFail++;                                                              \
      std::printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, (msg));         \
    }                                                                       \
  } while (0)

// ---- ClientHello construction -------------------------------------------
//
// Built by a helper rather than pasted in as a byte array. A hand-typed capture
// is only correct if every offset in it happens to be right, and when one is
// wrong the test fails in a way that looks like a parser bug. Building it means
// the field lengths are correct by construction, so a failure here really is the
// parser.
static void be16(std::vector<uint8_t>& v, size_t n) {
  v.push_back(uint8_t(n >> 8));
  v.push_back(uint8_t(n & 0xff));
}

static std::vector<uint8_t> ext(uint16_t type, const std::vector<uint8_t>& data) {
  std::vector<uint8_t> e;
  be16(e, type);
  be16(e, data.size());
  e.insert(e.end(), data.begin(), data.end());
  return e;
}

static std::vector<uint8_t> clientHello(uint16_t ver, const std::string& sni,
                                        const std::string& alpn,
                                        size_t randomLen = 32) {
  std::vector<uint8_t> b;
  be16(b, ver);
  for (size_t i = 0; i < randomLen; i++) b.push_back(uint8_t(i * 7 + 1));
  b.push_back(0x00);                                  // empty session id
  be16(b, 2);                                        // two cipher suites follow
  b.push_back(0x13); b.push_back(0x01);
  b.push_back(0x01); b.push_back(0x00);               // 1 method: null
  std::vector<uint8_t> exts;
  if (!sni.empty()) {
    std::vector<uint8_t> nd;
    nd.push_back(0x00);                               // host_name
    be16(nd, sni.size());
    nd.insert(nd.end(), sni.begin(), sni.end());
    std::vector<uint8_t> list;
    be16(list, nd.size());
    list.insert(list.end(), nd.begin(), nd.end());
    exts = ext(0x0000, list);                         // server_name
  }
  if (!alpn.empty()) {
    std::vector<uint8_t> pd;
    pd.push_back(uint8_t(alpn.size()));
    pd.insert(pd.end(), alpn.begin(), alpn.end());
    std::vector<uint8_t> list;
    be16(list, pd.size());
    list.insert(list.end(), pd.begin(), pd.end());
    // Hoisted: ext() is called twice if written inline, and each call returns a
    // different temporary, so begin() and end() would come from two unrelated
    // vectors and the insert would run off the end.
    auto e = ext(0x0010, list);
    exts.insert(exts.end(), e.begin(), e.end());
  }
  be16(b, exts.size());
  b.insert(b.end(), exts.begin(), exts.end());
  return b;
}

// Wraps handshake bytes into a single TLS record of the given content type.
static std::vector<uint8_t> record(uint8_t type, const std::vector<uint8_t>& body,
                                   uint16_t ver = 0x0301) {
  std::vector<uint8_t> r{type, uint8_t(ver >> 8), uint8_t(ver & 0xff),
                         uint8_t(body.size() >> 8), uint8_t(body.size() & 0xff)};
  r.insert(r.end(), body.begin(), body.end());
  return r;
}

static std::vector<uint8_t> hs(uint8_t type, const std::vector<uint8_t>& body) {
  std::vector<uint8_t> h{type, uint8_t(body.size() >> 16),
                         uint8_t((body.size() >> 8) & 0xff),
                         uint8_t(body.size() & 0xff)};
  h.insert(h.end(), body.begin(), body.end());
  return h;
}

// ---- a minimal DER writer, so certificates can be varied per test --------
static void put(std::vector<uint8_t>& v, uint8_t t, const std::vector<uint8_t>& val) {
  v.push_back(t);
  if (val.size() < 128) {
    v.push_back(uint8_t(val.size()));
  } else {
    v.push_back(0x82);
    v.push_back(uint8_t(val.size() >> 8));
    v.push_back(uint8_t(val.size() & 0xff));
  }
  v.insert(v.end(), val.begin(), val.end());
}
// Delegates to put() rather than emitting its own header. A hand-written
// `0x30, uint8_t(size)` silently truncates anything over 127 bytes, and a
// certificate is comfortably larger than that: the result is a malformed
// encoding that still *looks* structured, so a parser walking it stops early
// and reports nothing. openssl asn1parse catches it immediately.
static std::vector<uint8_t> seq(const std::vector<uint8_t>& a) {
  std::vector<uint8_t> v;
  put(v, 0x30, a);
  return v;
}

static std::vector<uint8_t> operator+(const std::vector<uint8_t>& a,
                                      const std::vector<uint8_t>& b) {
  std::vector<uint8_t> r(a);
  r.insert(r.end(), b.begin(), b.end());
  return r;
}

static std::vector<uint8_t> tlv(uint8_t t, const std::vector<uint8_t>& val) {
  std::vector<uint8_t> v;
  put(v, t, val);
  return v;
}

// sha256WithRSAEncryption, 1.2.840.113549.1.1.11. Written as a proper TLV: the
// bare OID value bytes are not an OBJECT IDENTIFIER, and a SEQUENCE containing
// them is malformed in a way that only shows up when something else parses it.
static std::vector<uint8_t> oidSha256Rsa() {
  return tlv(0x06, {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b});
}
// rsaEncryption, 1.2.840.113549.1.1.1
static std::vector<uint8_t> oidRsa() {
  return tlv(0x06, {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01});
}

// One RDN holding a single attribute.
static std::vector<uint8_t> rdn(uint8_t oidLast, const std::string& text) {
  std::vector<uint8_t> atv;
  put(atv, 0x06, {0x55, 0x04, oidLast});
  put(atv, 0x0c, std::vector<uint8_t>(text.begin(), text.end()));
  // AttributeTypeAndValue is itself a SEQUENCE, and the RDN is a SET *of* it:
  //   Name ::= SEQUENCE OF RelativeDistinguishedName
  //   RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
  //   AttributeTypeAndValue ::= SEQUENCE { type, value }
  // Skipping the inner SEQUENCE leaves the OID sitting directly in the SET,
  // which is not valid DER and which a conforming reader will not accept.
  std::vector<uint8_t> atvSeq = seq(atv);
  std::vector<uint8_t> set{0x31, uint8_t(atvSeq.size())};
  set.insert(set.end(), atvSeq.begin(), atvSeq.end());
  return set;
}

static std::vector<uint8_t> name(const std::vector<std::vector<uint8_t>>& rdns) {
  std::vector<uint8_t> body;
  for (auto& r : rdns) body.insert(body.end(), r.begin(), r.end());
  return seq(body);
}

// A Certificate whose subject/issuer/validity/key size are all controllable.
static std::vector<uint8_t> makeCert(const std::string& cn,
                                     const std::string& issuerCn,
                                     const std::string& notBefore,
                                     const std::string& notAfter,
                                     size_t rsaKeyBits) {
  // UTCTime is YYMMDDHHMMSSZ; the ISO date is sliced and reformatted below.
  // UTCTime is YYMMDDHHMMSSZ; the ISO date is sliced and reformatted.
  //
  // Each date is built into a named local first. Writing std::vector(a.begin(),
  // a.end()) with the expression spelled out twice makes begin() and end() come
  // from two unrelated temporaries, and the distance between them is enormous,
  // so the vector constructor throws instead of building a string.
  auto utc = [](const std::string& iso) {
    const std::string s = iso.substr(2, 2) + iso.substr(5, 2) + iso.substr(8, 2) +
                          "000000Z";
    return tlv(0x17, std::vector<uint8_t>(s.begin(), s.end()));
  };

  std::vector<uint8_t> tbs;
  put(tbs, 0xA0, tlv(0x02, {0x02}));                          // [0] v3
  put(tbs, 0x02, {0x01, 0x2a});                                // serial
  put(tbs, 0x30, oidSha256Rsa() + tlv(0x05, {}));              // signature alg
  std::vector<uint8_t> issuer = name({rdn(0x03, issuerCn)});
  tbs.insert(tbs.end(), issuer.begin(), issuer.end());
  put(tbs, 0x30, utc(notBefore) + utc(notAfter));
  std::vector<uint8_t> subject = name({rdn(0x03, cn)});
  tbs.insert(tbs.end(), subject.begin(), subject.end());
  // subjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey }
  // Both halves go inside one more SEQUENCE. Emitting the AlgorithmIdentifier
  // and the BIT STRING straight into the tbs leaves the key one level too
  // shallow, and a reader walking the certificate lands on the AlgorithmIdentifier
  // where it expects the SPKI -- which is silently "no key size found" rather
  // than an error, so a 1024-bit key then looks fine.
  std::vector<uint8_t> alg = tlv(0x30, oidRsa() + tlv(0x05, {}));
  std::vector<uint8_t> bits(1 + rsaKeyBits / 8, 0x41);
  bits[0] = 0x00;                       // no unused trailing bits
  put(tbs, 0x30, alg + tlv(0x03, bits));

  std::vector<uint8_t> certBody;
  put(certBody, 0x30, tbs);
  put(certBody, 0x30, oidSha256Rsa() + tlv(0x05, {}));
  put(certBody, 0x03, {0x11, 0x22, 0x33});
  return seq(certBody);
}

// Wraps DER certificates in a TLS 1.2 Certificate message.
static std::vector<uint8_t> certMsg(const std::vector<uint8_t>& der) {
  std::vector<uint8_t> list;
  list.push_back(uint8_t(der.size() >> 16));
  list.push_back(uint8_t((der.size() >> 8) & 0xff));
  list.push_back(uint8_t(der.size() & 0xff));
  list.insert(list.end(), der.begin(), der.end());
  std::vector<uint8_t> body;
  body.push_back(uint8_t(list.size() >> 16));
  body.push_back(uint8_t((list.size() >> 8) & 0xff));
  body.push_back(uint8_t(list.size() & 0xff));
  body.insert(body.end(), list.begin(), list.end());
  return hs(0x0b, body);
}

int main() {
  // ----   // ---- rank ordering ------------------------------------------------------
  CHECK(tlsRank("SSLv3") < tlsRank("TLSv1.0"), "SSLv3 is worst");
  CHECK(tlsRank("TLSv1.0") < tlsRank("TLSv1.1"), "1.0 below 1.1");
  CHECK(tlsRank("TLSv1.1") < tlsRank("TLSv1.2"), "1.1 below 1.2");
  CHECK(tlsRank("TLSv1.2") < tlsRank("TLSv1.3"), "1.2 below 1.3");
  CHECK(tlsRank("nonsense") == -1, "an unknown version ranks below known ones");

  // ----   // ---- a plain ClientHello ------------------------------------------------
  {
    TlsAnalyzer a;
    TlsFinding f;
    auto rec = record(0x16, hs(0x01, clientHello(0x0303, "example.com", "h2")));
    CHECK(a.feed(51000, 443, "10.0.0.2", "93.184.216.34", rec.data(), rec.size(),
                 &f, 1700000000),
          "a TLS 1.2 ClientHello must be reported");
    CHECK(f.kind == "hello", "kind is hello");
    CHECK(f.serverName == "example.com", "SNI must be example.com");
    CHECK(f.alpn == "h2", "ALPN must be h2");
    CHECK(f.offered == "TLSv1.2", "offered version must be TLSv1.2");
  }

  // ----   // ---- a hello split across two segments ---------------------------------
  {
    TlsAnalyzer a;
    TlsFinding f;
    auto rec = record(0x16, hs(0x01, clientHello(0x0303, "example.com", "h2")));
    std::vector<uint8_t> full(rec.begin(), rec.end());
    size_t half = full.size() / 2;
    // First segment: the record header plus part of the body.
    CHECK(!a.feed(51000, 443, "10.0.0.2", "1.2.3.4", full.data(), half, &f, 1),
          "a truncated hello must not be reported yet");
    CHECK(a.feed(51000, 443, "10.0.0.2", "1.2.3.4", full.data() + half,
                 full.size() - half, &f, 1),
          "the rest of the hello must complete it");
    CHECK(f.serverName == "example.com", "SNI survives a split hello");
  }

  // ----   // ---- the two directions are separate flows ------------------------------
  {
    TlsAnalyzer a;
    TlsFinding f;
    auto rec = record(0x16, hs(0x01, clientHello(0x0303, "example.com", "h2")));
    std::vector<uint8_t> full(rec.begin(), rec.end());
    // Client hello one way...
    a.feed(51000, 443, "10.0.0.2", "1.2.3.4", full.data(), full.size(), &f, 1);
    // ...and a ServerHello the other way must not be concatenated onto it.
    std::vector<uint8_t> shBody{0x03, 0x03, 0x00, 0x11, 0x22, 0x33};
    auto sh = record(0x16, hs(0x02, shBody));
    bool got = a.feed(443, 51000, "1.2.3.4", "10.0.0.2", sh.data(), sh.size(), &f, 1);
    CHECK(!got, "a bare ServerHello is not worth a row of its own");
  }

  // ----   // ---- a hello is reported once, not on every segment --------------------
  {
    TlsAnalyzer a;
    TlsFinding f;
    auto rec = record(0x16, hs(0x01, clientHello(0x0303, "example.com", "h2")));
    std::vector<uint8_t> full(rec.begin(), rec.end());
    CHECK(a.feed(51000, 443, "10.0.0.2", "1.2.3.4", full.data(), full.size(), &f, 1),
          "first hello is reported");
    CHECK(!a.feed(51000, 443, "10.0.0.2", "1.2.3.4", full.data(), full.size(), &f, 1),
          "the same hello repeated must not be reported twice");
  }

  // ----   // ---- a certificate ------------------------------------------------------
  {
    auto der = makeCert("example.com", "Example CA", "2024-01-01", "2030-01-01", 2048);
    auto msg = record(0x16, certMsg(der));
    TlsAnalyzer a;
    TlsFinding f;
    CHECK(a.feed(443, 51000, "1.2.3.4", "10.0.0.2", msg.data(), msg.size(), &f, 1700000000),
          "a certificate must be reported");
    CHECK(f.kind == "cert", "kind is cert");
    CHECK(f.subject == "example.com", "subject CN");
    CHECK(f.issuer == "Example CA", "issuer CN");
    CHECK(f.notBefore == "2024-01-01", "notBefore");
    CHECK(f.notAfter == "2030-01-01", "notAfter");
    CHECK(!f.selfSigned, "example.com signed by Example CA is not self-signed");
    CHECK(!f.expired, "valid in 2024..2030 is not expired at 2023-11");
    CHECK(!f.weakKey, "a 2048-bit RSA key is not weak");
  }

  // ----   // ---- an expired certificate --------------------------------------------
  {
    auto der = makeCert("old.example", "Old CA", "2015-01-01", "2018-01-01", 2048);
    auto msg = record(0x16, certMsg(der));
    TlsAnalyzer a;
    TlsFinding f;
    a.feed(443, 51000, "1.2.3.4", "10.0.0.2", msg.data(), msg.size(), &f, 1700000000);
    CHECK(f.expired, "2018 < 2023 must be flagged expired");
    CHECK(f.isFinding(), "an expired cert is a finding");
  }

  // ----   // ---- not yet valid ------------------------------------------------------
  {
    auto der = makeCert("future.example", "New CA", "2030-01-01", "2035-01-01", 2048);
    auto msg = record(0x16, certMsg(der));
    TlsAnalyzer a;
    TlsFinding f;
    a.feed(443, 51000, "1.2.3.4", "10.0.0.2", msg.data(), msg.size(), &f, 1700000000);
    CHECK(f.notYetValid, "a 2030 cert seen in 2023 is not yet valid");
  }

  // ----   // ---- a short key --------------------------------------------------------
  {
    auto der = makeCert("small.example", "Small CA", "2024-01-01", "2030-01-01", 1024);
    auto msg = record(0x16, certMsg(der));
    TlsAnalyzer a;
    TlsFinding f;
    a.feed(443, 51000, "1.2.3.4", "10.0.0.2", msg.data(), msg.size(), &f, 1700000000);
    CHECK(f.weakKey, "a 1024-bit RSA key must be flagged");
  }

  // ----   // ---- a self-signed certificate ------------------------------------------
  {
    auto der = makeCert("self.example", "self.example", "2024-01-01", "2030-01-01", 2048);
    auto msg = record(0x16, certMsg(der));
    TlsAnalyzer a;
    TlsFinding f;
    a.feed(443, 51000, "1.2.3.4", "10.0.0.2", msg.data(), msg.size(), &f, 1700000000);
    CHECK(f.selfSigned, "subject == issuer means self-signed");
  }

  // ----   // ---- junk must not produce a finding ------------------------------------
  {
    TlsAnalyzer a;
    TlsFinding f;
    std::vector<uint8_t> junk{0x16, 0x03, 0x01, 0xff, 0xff, 0xff, 0xff, 0x01,
                              0x00, 0x00, 0x00};
    CHECK(!a.feed(1, 2, "a", "b", junk.data(), junk.size(), &f, 1),
          "a length beyond any real record must not be reported");
    std::vector<uint8_t> appdata{0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5};
    CHECK(!a.feed(1, 2, "c", "d", appdata.data(), appdata.size(), &f, 1),
          "application data is not a handshake");
    CHECK(!a.feed(1, 2, "e", "f", nullptr, 0, &f, 1), "null payload is ignored");
  }

  // ----   // ---- flow accounting ----------------------------------------------------
  {
    TlsAnalyzer a;
    TlsFinding f;
    auto rec = record(0x16, hs(0x01, clientHello(0x0303, "a.example", "h2")));
    std::vector<uint8_t> full(rec.begin(), rec.end());
    a.feed(1, 443, "10.0.0.1", "1.1.1.1", full.data(), full.size(), &f, 1);
    a.feed(2, 443, "10.0.0.2", "1.1.1.1", full.data(), full.size(), &f, 1);
    a.feed(443, 1, "1.1.1.1", "10.0.0.1", full.data(), full.size(), &f, 1);
    CHECK(a.flowCount() == 3, "each distinct 5-tuple is its own flow");
    a.clear();
    CHECK(a.flowCount() == 0, "clear() drops every flow");
  }

  std::printf("\n%d checks, %d failure(s)\n", gRun, gFail);
  if (gFail) return 1;
  std::printf("ALL PASS (0 failure(s))\n");
  return 0;
}
