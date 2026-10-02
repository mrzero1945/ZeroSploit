// Credential sniffer: pulls cleartext logins out of captured packet payloads.
//
// Lives in the privileged helper rather than the app process because the only
// place packet payloads are ever available is the AF_PACKET socket in
// cmdMitm() -- the app process has no way to see them, and routing them through
// a pipe just to parse them in Java would copy every captured byte across two
// process boundaries to do work that is pure byte crunching.
//
// Scope note: this is a *cleartext* sniffer. It reads credentials out of
// protocols that send them in the clear (HTTP Basic, FTP, POP3, IMAP, SMTP,
// Telnet, Redis, MQTT, Postgres, SNMP, RDP's CredSSP publicInfo) and reports
// what a passive capture of that traffic contains. It does not decrypt
// anything, which is why it works without a CA and why HTTPS credentials show
// up only as encrypted bytes it cannot read.
#ifndef ZS_SNIFF_H
#define ZS_SNIFF_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>

struct Cred {
  std::string proto;
  std::string src;
  std::string dst;
  int dport = 0;
  std::string user;
  std::string pass;
  // True when the "password" is a challenge response rather than the secret
  // itself, so the UI can say so instead of printing a scramble as if it were a
  // password. MySQL's native auth and SMTP CRAM-MD5 both do this.
  bool challenge = false;
};

// Per-connection sliding window plus a "already reported" set.
//
// The window exists because a credential regularly straddles a segment
// boundary: a base64 blob split across two TCP segments parses fine if each
// segment is scanned on its own only by luck. Keeping the last few hundred
// bytes of each direction and rescanning means the parse succeeds when the
// bytes are all present, regardless of which packet carried them.
//
// The dedup set exists because these protocols *repeat*: an FTP client sends
// USER/PASS on every reconnect, and a polling session re-sends its
// authorization periodically. Without it one login produces a stream of
// identical events and floods the results list.
class CredSniffer {
 public:
  // `maxWindow` is the retained payload per direction, `maxReport` the number
  // of distinct credentials to report before the sniffer goes quiet.
  explicit CredSniffer(size_t maxWindow = 512, size_t maxReport = 200)
      : windowMax_(maxWindow), maxReport_(maxReport) {}

  // `proto` is IPPROTO_TCP or IPPROTO_UDP, `sport`/`dport` the transport ports.
  // Returns true only when a credential not already reported was recognised.
  bool feed(int proto, int sport, int dport, const std::string& src,
            const std::string& dst, const uint8_t* data, size_t len,
            Cred* out);

  // Number of distinct credentials reported so far.
  size_t reported() const { return reported_.size(); }
  bool saturated() const { return reported_.size() >= maxReport_; }

 private:
  struct Flow {
    std::string buf;
  };

  bool parse(int proto, int sport, int dport, const std::string& src,
             const std::string& dst, std::string& view, Cred* out);
  bool already(const Cred& c);

  std::unordered_map<std::string, Flow> flows_;
  std::unordered_set<std::string> reported_;
  size_t windowMax_;
  size_t maxReport_;
};

// Exposed for the unit test: decodes standard base64, ignoring whitespace and
// stopping at the first invalid character. Returns false if the input is not
// valid base64 length/padding.
bool b64Decode(const std::string& in, std::string* out);

// Renders bytes that are not printable ASCII as \xNN so a binary secret does
// not put raw control characters in a TextView.
std::string printable(const std::string& s, size_t maxLen = 96);

#endif  // ZS_SNIFF_H
