// TLS session analysis for the Hijacker module.
//
// SCOPE, STATED PLAINLY
//   This parses TLS as it crosses the capture path and reports what the session
//   *is*: the name the client asked for, the protocol version, and the
//   certificate chain the server presented. It does not decrypt anything and
//   holds no interception CA.
//
//   cSploit's Hijacker does decrypt, by handing the traffic to ettercap with a
//   bundled csploit.p12 and etterfilter scripts, and reading the cleartext in a
//   WebView. Reproducing that means shipping a CA private key, a TLS stack, and
//   on-the-fly leaf certificate generation -- none of which belongs in an APK
//   that is meant to be installed on someone's phone, and all of which would be
//   trivial to misuse. The findings below are the part that is useful without
//   that: which hosts a device talks to, on which protocol versions, against
//   which issuers, and which certificates are broken.
//
//   The capture sees both directions of a connection, so this works on the same
//   MITM path as the other modules: the client offers, the server answers.
#ifndef ZS_TLS_H
#define ZS_TLS_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

// Orders protocol names so a downgrade can be compared. Returns -1 for an
// unrecognised name so a parse we do not understand is never treated as better
// than one we do.
int tlsRank(const std::string& name);

// One reportable observation. A hello and a certificate are separate findings
// because they arrive in separate handshake messages and the interesting facts
// are not the same: a hello tells you what the client wanted, a certificate
// tells you what the server proved.
struct TlsFinding {
  std::string kind;        // "hello" or "cert"
  std::string src, dst;
  int sport = 0, dport = 0;

  // From a ClientHello.
  std::string serverName;  // SNI
  std::string alpn;        // first offered protocol, e.g. h2
  std::string offered;     // highest version the client offered
  std::string negotiated;  // version the server selected, if a ServerHello arrived

  // From the server's certificate chain.
  std::string subject, issuer;
  std::string notBefore, notAfter;   // "YYYY-MM-DD"
  bool selfSigned = false;
  bool expired = false;
  bool notYetValid = false;
  bool weakKey = false;              // RSA/DSA below 2048, or any EC key

  // True when any of the above is a problem worth surfacing in red.
  bool isFinding() const {
    return expired || notYetValid || weakKey || selfSigned ||
           (!negotiated.empty() && tlsRank(negotiated) < tlsRank("TLSv1.2"));
  }
};

// Per-connection analyser. Each direction of a flow gets its own buffer, keyed
// by the 5-tuple, because a ClientHello and a Certificate travel in opposite
// directions and must not be concatenated.
//
// Handshake messages routinely straddle TCP segments, so bytes are accumulated
// until a whole record is present. The window is bounded and the front is
// dropped when it overflows: a client that keeps sending data without a
// handshake must not grow this without limit.
class TlsAnalyzer {
 public:
  TlsAnalyzer();

  // Feeds payload bytes for one direction of one flow.
  //
  // Returns true and fills *out when a complete, previously unreported
  // handshake message was parsed. Set `nowEpoch` to control expiry checks; it
  // defaults to the wall clock.
  bool feed(int sport, int dport, const std::string& src, const std::string& dst,
            const uint8_t* p, size_t n, TlsFinding* out,
            int64_t nowEpoch = 0);

  void clear();

  size_t flowCount() const { return flows_.size(); }

 private:
  struct Flow {
    std::string buf;
    bool helloSeen = false;
    bool certSeen = false;
    std::string negotiated;   // version the server picked
  };
  std::unordered_map<std::string, Flow> flows_;
  int64_t now_ = 0;
};

#endif  // ZS_TLS_H
