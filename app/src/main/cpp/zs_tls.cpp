#include "zs_tls.h"

#include <cstdio>
#include <cstring>
#include <ctime>

namespace {

// TLS record and handshake content types we care about.
constexpr uint8_t kRecHandshake = 0x16;
constexpr uint8_t kHsClientHello = 0x01;
constexpr uint8_t kHsServerHello = 0x02;
constexpr uint8_t kHsCertificate = 0x0b;

// A TLSPlaintext length is 2^14; allow a little for the MAC that rides along.
constexpr size_t kMaxRecord = 16384 + 2048;
// Enough for a ClientHello with a long SNI, ALPN list and many extensions.
constexpr size_t kMaxFlowBuf = 8192;

std::string versionName(uint16_t v) {
  switch (v) {
    case 0x0300: return "SSLv3";
    case 0x0301: return "TLSv1.0";
    case 0x0302: return "TLSv1.1";
    case 0x0303: return "TLSv1.2";
    case 0x0304: return "TLSv1.3";
    default: return "0x" + [v] {
      char b[8];
      std::snprintf(b, sizeof b, "%04x", v);
      return std::string(b);
    }();
  }
}

// ---- minimal DER reader ---------------------------------------------------
//
// Only enough to walk a certificate: no crypto, no validation, no trust
// decisions. A malformed field is skipped rather than treated as an error, so a
// single odd encoding cannot lose the whole certificate.
struct Der {
  const uint8_t* p = nullptr;
  const uint8_t* end = nullptr;

  bool has(size_t n) const { return size_t(end - p) >= n; }
  bool empty() const { return p >= end; }
  uint8_t u8() const { return p < end ? *p : 0; }
};

// Reads one tag-length-value at the cursor and advances past it. Lengths use
// definite form only, and the short/long form is bounded so a hostile length
// cannot walk us off the end.
bool derNext(Der& d, uint8_t* tag, const uint8_t** val, size_t* vlen) {
  if (!d.has(2)) return false;
  uint8_t t = d.p[0];
  d.p++;
  size_t l = d.p[0];
  d.p++;
  if (l & 0x80) {
    size_t nb = l & 0x7f;
    // Indefinite length is not valid in DER, and a large length count is either
    // malformed or an attempt to exhaust us.
    if (nb == 0 || nb > 4) return false;
    if (!d.has(nb)) return false;
    l = 0;
    for (size_t i = 0; i < nb; i++) l = (l << 8) | d.p[i];
    d.p += nb;
  }
  if (!d.has(l)) return false;
  *tag = t;
  *val = d.p;
  *vlen = l;
  d.p += l;
  return true;
}

std::string derText(const uint8_t* v, size_t n) {
  // PrintableString, UTF8String, IA5String and BMPString all appear in
  // certificates. Anything with an interior NUL is not a name we can show, and
  // embedded control bytes are stripped rather than rendered into the console.
  std::string s;
  for (size_t i = 0; i < n; i++) {
    uint8_t c = v[i];
    if (c == 0) break;                 // BMPString is UTF-16BE
    if (c < 0x20 || c == 0x7f) continue;
    s.push_back(char(c));
  }
  return s;
}

// 2.5.4.3 commonName, 2.5.4.10 organizationName, both DER-encoded as
// 55 04 03 and 55 04 0a.
bool oidIs(const uint8_t* v, size_t n, uint8_t last) {
  return n == 3 && v[0] == 0x55 && v[1] == 0x04 && v[2] == last;
}

// Pulls the CN (or O) out of one RDN. Returns an empty string when the RDN
// carries neither, which is normal -- a DN may hold other attributes.
std::string derRdnName(const uint8_t* rdn, size_t rdnLen) {
  Der d{rdn, rdn + rdnLen};
  std::string cn, org;
  while (!d.empty()) {
    uint8_t tag = 0;
    const uint8_t* at = nullptr;
    size_t atLen = 0;
    if (!derNext(d, &tag, &at, &atLen)) break;
    if (tag != 0x30) continue;                       // expect AttributeTypeAndValue
    Der a{at, at + atLen};
    uint8_t otag = 0;
    const uint8_t* ov = nullptr;
    size_t olen = 0;
    if (!derNext(a, &otag, &ov, &olen)) continue;
    if (otag != 0x06) continue;                      // expect OBJECT IDENTIFIER
    uint8_t vtag = 0;
    const uint8_t* vv = nullptr;
    size_t vlen = 0;
    if (!derNext(a, &vtag, &vv, &vlen)) continue;
    if (oidIs(ov, olen, 0x03) && cn.empty()) cn = derText(vv, vlen);
    if (oidIs(ov, olen, 0x0a) && org.empty()) org = derText(vv, vlen);
  }
  if (!cn.empty()) return cn;
  return org;
}

std::string derName(const uint8_t* p, size_t n) {
  // p and n are the *contents* of the Name SEQUENCE, so the RDN SETs start
  // immediately. Priming the cursor with a read here consumed the first RDN
  // before the loop saw it, and every DN came back empty.
  Der d{p, p + n};
  std::string out;
  while (!d.empty()) {
    uint8_t t = 0;
    const uint8_t* rv = nullptr;
    size_t rl = 0;
    if (!derNext(d, &t, &rv, &rl)) break;
    if (t != 0x31) continue;                         // expect SET
    std::string one = derRdnName(rv, rl);
    if (one.empty()) continue;
    if (!out.empty()) out += ", ";
    out += one;
  }
  return out;
}

// Days from 1970-01-01, the usual civil-date algorithm. Used to turn a validity
// period into something comparable with the wall clock.
int64_t daysFromCivil(int y, int m, int d) {
  y -= m <= 2;
  const int64_t era = (y >= 0 ? y : y - 399) / 400;
  const unsigned yoe = unsigned(y - era * 400);
  const unsigned doy = (153u * unsigned(m + (m > 2 ? -3 : 9)) + 2) / 5 + unsigned(d) - 1;
  const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  return era * 146097 + int64_t(doe) - 719468;
}

// Parses UTCTime (YYMMDDHHMMSSZ) and GeneralizedTime (YYYYMMDDHHMMSSZ).
// Returns an epoch, or 0 when the encoding is not one of those two. The
// two-digit year rule is the one from RFC 5280: 50..99 means 19xx, 00..49 20xx.
int64_t derTime(uint8_t tag, const uint8_t* v, size_t n, std::string* fmt) {
  std::string s((const char*)v, n);
  if (fmt) fmt->clear();
  if (tag == 0x17) {                 // UTCTime
    if (n < 11) return 0;
    int yy = (s[0] - '0') * 10 + (s[1] - '0');
    int year = yy >= 50 ? 1900 + yy : 2000 + yy;
    if (n < 13) return 0;
    int mo = (s[2] - '0') * 10 + (s[3] - '0');
    int da = (s[4] - '0') * 10 + (s[5] - '0');
    if (fmt) *fmt = std::to_string(year) + "-" + s.substr(2, 2) + "-" + s.substr(4, 2);
    return daysFromCivil(year, mo, da) * 86400;
  }
  if (tag == 0x18) {                 // GeneralizedTime
    if (n < 13) return 0;
    int year = 0;
    for (int i = 0; i < 4; i++) {
      if (s[i] < '0' || s[i] > '9') return 0;
      year = year * 10 + (s[i] - '0');
    }
    int mo = (s[4] - '0') * 10 + (s[5] - '0');
    int da = (s[6] - '0') * 10 + (s[7] - '0');
    if (mo < 1 || mo > 12 || da < 1 || da > 31) return 0;
    if (fmt) *fmt = s.substr(0, 4) + "-" + s.substr(4, 2) + "-" + s.substr(6, 2);
    return daysFromCivil(year, mo, da) * 86400;
  }
  return 0;
}

// Walks the subjectPublicKeyInfo to find the algorithm and key size. Anything we
// cannot identify is reported as not weak, so a new algorithm is never flagged
// as a small key by default.
bool derWeakKey(const uint8_t* tbs, size_t tbsLen) {
  // Walk to subjectPublicKeyInfo: optional [0] version, then serialNumber,
  // signature, issuer, validity, subject.
  //
  // Written as "peek, then optionally consume" rather than as a counted loop
  // that decrements its own counter: a counted loop whose body can rewind the
  // index spins forever whenever the tag it is skipping repeats.
  Der d{tbs, tbs + tbsLen};
  uint8_t tag = 0;
  const uint8_t* v = nullptr;
  size_t vl = 0;
  if (!derNext(d, &tag, &v, &vl)) return false;
  if (tag == 0xA0 && !derNext(d, &tag, &v, &vl)) return false;   // version
  // Four more: signature, issuer, validity, subject. Five would consume the
  // subjectPublicKeyInfo itself and leave the cursor on the field after it, so
  // the read below picked up an extension or nothing at all.
  for (int i = 0; i < 4; i++) {
    if (!derNext(d, &tag, &v, &vl)) return false;
  }
  // Now the cursor is on subjectPublicKeyInfo.
  if (!derNext(d, &tag, &v, &vl) || tag != 0x30) return false;   // SPKI SEQUENCE
  // Now the cursor is on subjectPublicKeyInfo: an AlgorithmIdentifier followed
  // by the key as a BIT STRING.
  Der spki{v, v + vl};
  uint8_t atag = 0;
  const uint8_t* av = nullptr;
  size_t al = 0;
  if (!derNext(spki, &atag, &av, &al) || atag != 0x30) return false;  // AlgorithmIdentifier
  // The algorithm OID is a TLV inside that SEQUENCE, so its tag byte has to be
  // consumed first. Comparing the AlgorithmIdentifier's raw content against the
  // OID's *value* bytes never matches, which is why this reported every key as
  // an acceptable size.
  Der alg{av, av + al};
  uint8_t otag = 0;
  const uint8_t* ov = nullptr;
  size_t ol = 0;
  if (!derNext(alg, &otag, &ov, &ol) || otag != 0x06) return false;   // algorithm OID
  // rsaEncryption, 1.2.840.113549.1.1.1. Only RSA and DSA report a key size in
  // the bit string; an EC key is not weak, so an unrecognised OID is left alone.
  static const uint8_t kRsa[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01};
  if (ol != sizeof kRsa || memcmp(ov, kRsa, sizeof kRsa) != 0) return false;
  uint8_t btag = 0;
  const uint8_t* bv = nullptr;
  size_t bl = 0;
  if (!derNext(spki, &btag, &bv, &bl) || btag != 0x03) return false;
  if (bl < 2) return false;
  // The first content byte of a BIT STRING is the count of unused trailing
  // bits, so the key itself is bl - 1 bytes.
  return (bl - 1) * 8 < 2048;
}

}  // namespace

int tlsRank(const std::string& name) {
  if (name == "SSLv3") return 0;
  if (name == "TLSv1.0") return 1;
  if (name == "TLSv1.1") return 2;
  if (name == "TLSv1.2") return 3;
  if (name == "TLSv1.3") return 4;
  return -1;
}

TlsAnalyzer::TlsAnalyzer() {
  now_ = int64_t(std::time(nullptr));
}

void TlsAnalyzer::clear() { flows_.clear(); }

bool TlsAnalyzer::feed(int sport, int dport, const std::string& src,
                       const std::string& dst, const uint8_t* p, size_t n,
                       TlsFinding* out, int64_t nowEpoch) {
  if (!p || n == 0) return false;
  if (nowEpoch) now_ = nowEpoch;

  // Direction matters, so the key includes the ports. A five-tuple hash keyed
  // only on addresses would merge the two directions and hand the analyser a
  // certificate followed by a ClientHello, which parses as garbage.
  std::string key = src + ":" + std::to_string(sport) + ">" + dst + ":" +
                    std::to_string(dport);
  Flow& f = flows_[key];

  f.buf.append(reinterpret_cast<const char*>(p), n);
  if (f.buf.size() > kMaxFlowBuf) {
    // Drop from the front. A partial record that straddles the cut is lost and
    // resync finds the next one; the alternative is unbounded growth.
    f.buf.erase(0, f.buf.size() - kMaxFlowBuf);
  }

  for (;;) {
    if (f.buf.size() < 5) return false;
    const uint8_t* b = reinterpret_cast<const uint8_t*>(f.buf.data());
    // TLSPlaintext: type(1) version(2) length(2). The length is bytes 3 and 4;
    // reading bytes 2 and 3 instead picks up the low half of the version, which
    // yields a length in the hundreds and makes every record look truncated.
    uint8_t type = b[0];
    size_t rlen = (size_t(b[3]) << 8) | b[4];
    if (type != kRecHandshake || rlen == 0 || rlen > kMaxRecord) {
      // Not a handshake record where we expected one. Slide forward a byte and
      // look again rather than dropping the flow: a TCP stream that starts with
      // data before the handshake is normal, and giving up here loses every
      // later record too.
      f.buf.erase(0, 1);
      continue;
    }
    if (f.buf.size() < 5 + rlen) return false;      // wait for the rest

    const uint8_t* hs = b + 5;
    size_t hsLen = rlen;
    if (hsLen < 4) { f.buf.erase(0, 5 + rlen); continue; }
    uint8_t hsType = hs[0];
    size_t hsBodyLen = (size_t(hs[1]) << 16) | (size_t(hs[2]) << 8) | hs[3];
    const uint8_t* body = hs + 4;

    bool ready = false;
    TlsFinding fnd;
    fnd.src = src;
    fnd.dst = dst;
    fnd.sport = sport;
    fnd.dport = dport;

    if (hsType == kHsClientHello && !f.helloSeen && hsBodyLen >= 2 &&
        hsBodyLen <= hsLen - 4) {
      uint16_t ver = uint16_t((body[0] << 8) | body[1]);
      fnd.kind = "hello";
      fnd.offered = versionName(ver);
      // Walk: version(2) random(32) sessionId cipherSuites compression extensions
      size_t p2 = 2 + 32;
      if (p2 < hsBodyLen) {
        size_t sidLen = body[p2];
        p2 += 1 + sidLen;
      }
      if (p2 + 2 <= hsBodyLen) {
        size_t csLen = (size_t(body[p2]) << 8) | body[p2 + 1];
        p2 += 2 + csLen;
      }
      if (p2 < hsBodyLen) {
        size_t compLen = body[p2];
        p2 += 1 + compLen;
      }
      if (p2 + 2 <= hsBodyLen) {
        size_t extTotal = (size_t(body[p2]) << 8) | body[p2 + 1];
        size_t p3 = p2 + 2;
        size_t extEnd = p3 + extTotal;
        if (extEnd > hsBodyLen) extEnd = hsBodyLen;
        while (p3 + 4 <= extEnd) {
          uint16_t etype = uint16_t((body[p3] << 8) | body[p3 + 1]);
          size_t elen = (size_t(body[p3 + 2]) << 8) | body[p3 + 3];
          size_t ev = p3 + 4;
          if (ev + elen > extEnd) break;
          if (etype == 0 && elen >= 5) {              // server_name
            size_t listLen = (size_t(body[ev]) << 8) | body[ev + 1];
            size_t q = ev + 2;
            size_t qEnd = q + listLen;
            if (qEnd > ev + elen) qEnd = ev + elen;
            while (q + 3 <= qEnd) {
              uint8_t ntype = body[q];
              size_t nlen = (size_t(body[q + 1]) << 8) | body[q + 2];
              if (ntype == 0 && q + 3 + nlen <= qEnd) {
                fnd.serverName.assign((const char*)body + q + 3, nlen);
                break;
              }
              q += 3 + nlen;
            }
          } else if (etype == 16 && elen >= 3) {       // ALPN
            size_t listLen = (size_t(body[ev]) << 8) | body[ev + 1];
            size_t q = ev + 2;
            if (q < ev + 2 + listLen && listLen >= 1) {
              size_t nlen = body[q];
              if (nlen && q + 1 + nlen <= ev + 2 + listLen) {
                fnd.alpn.assign((const char*)body + q + 1, nlen);
              }
            }
          }
          p3 = ev + elen;
        }
      }
      ready = true;
      f.helloSeen = true;
    } else if (hsType == kHsServerHello && hsBodyLen >= 2 &&
               hsBodyLen <= hsLen - 4) {
      uint16_t ver = uint16_t((body[0] << 8) | body[1]);
      f.negotiated = versionName(ver);
      // Consume the record before continuing. A bare ServerHello is not worth
      // a row of its own, but `continue` here would skip the erase at the
      // bottom of the loop and re-parse this same record for ever.
      f.buf.erase(0, 5 + rlen);
      continue;
    } else if (hsType == kHsCertificate && !f.certSeen && hsBodyLen >= 3 &&
               hsBodyLen <= hsLen - 4) {
      // TLS 1.2 and below: a 3-byte list length then length-prefixed certs.
      size_t listLen = (size_t(body[0]) << 16) | (size_t(body[1]) << 8) | body[2];
      size_t p2 = 3;
      size_t listEnd = p2 + listLen;
      if (listEnd > hsBodyLen) listEnd = hsBodyLen;
      if (p2 + 3 <= listEnd) {
        size_t clen = (size_t(body[p2]) << 16) | (size_t(body[p2 + 1]) << 8) |
                      body[p2 + 2];
        p2 += 3;
        if (p2 + clen <= listEnd) {
          const uint8_t* cert = body + p2;
          Der d{cert, cert + clen};
          uint8_t tag = 0;
          const uint8_t* v = nullptr;
          size_t vl = 0;
          if (derNext(d, &tag, &v, &vl) && tag == 0x30) {
            Der c{v, v + vl};
            uint8_t t2 = 0;
            const uint8_t* tbs = nullptr;
            size_t tbsLen = 0;
            if (derNext(c, &t2, &tbs, &tbsLen) && t2 == 0x30) {
              fnd.kind = "cert";
              // tbsCertificate fields in order: [0] version (optional),
              // serialNumber, signature, issuer, validity, subject, SPKI. The
              // version is optional, so peek before consuming.
              Der w{tbs, tbs + tbsLen};
              uint8_t tt = 0;
              const uint8_t* tv = nullptr;
              size_t tvl = 0;
              // derNext inside the condition already consumed the [0] version;
              // reading again here shifted every later field by one, so the
              // "issuer" came back holding the validity SEQUENCE and every DN
              // came out empty.
              if (derNext(w, &tt, &tv, &tvl) && tt == 0xA0) {
                // version consumed
              }
              derNext(w, &tt, &tv, &tvl);       // serialNumber
              derNext(w, &tt, &tv, &tvl);       // signature
              uint8_t itag = 0;
              const uint8_t* iv = nullptr;
              size_t il = 0;
              if (derNext(w, &itag, &iv, &il) && itag == 0x30) {
                fnd.issuer = derName(iv, il);
              }

              uint8_t vtag = 0;
              const uint8_t* vv = nullptr;
              size_t vl2 = 0;
              if (derNext(w, &vtag, &vv, &vl2) && vtag == 0x30) {
                Der vt{vv, vv + vl2};
                uint8_t nt = 0, ot = 0;
                const uint8_t* nv = nullptr;
                const uint8_t* ov = nullptr;
                size_t nl = 0, ol = 0;
                if (derNext(vt, &nt, &nv, &nl)) {
                  int64_t nb = derTime(nt, nv, nl, &fnd.notBefore);
                  if (derNext(vt, &ot, &ov, &ol)) {
                    int64_t na = derTime(ot, ov, ol, &fnd.notAfter);
                    if (na && now_) {
                      fnd.expired = na < now_;
                      fnd.notYetValid = nb > now_;
                    }
                  }
                }
              }
              uint8_t stag = 0;
              const uint8_t* sv = nullptr;
              size_t sl = 0;
              if (derNext(w, &stag, &sv, &sl) && stag == 0x30) {
                fnd.subject = derName(sv, sl);
              }
              // Self-signed means the issuer and subject encodings match. Not a
              // proof, and not a check against a trust store -- just the shape.
              fnd.selfSigned = (fnd.issuer == fnd.subject) && !fnd.subject.empty();
              fnd.weakKey = derWeakKey(tbs, tbsLen);
              ready = true;
              f.certSeen = true;
            }
          }
        }
      }
    }

    f.buf.erase(0, 5 + rlen);
    if (ready && out) {
      // Copy first, then attach the flow's remembered version. Doing it the
      // other way round silently discarded the negotiated version on every
      // finding, because *out = fnd overwrote what we had just written.
      *out = fnd;
      if (!f.negotiated.empty()) out->negotiated = f.negotiated;
      return true;
    }
  }
}
