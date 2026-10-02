// Credential sniffer implementation. See zs_sniff.h for scope and rationale.
#include "zs_sniff.h"

#include <arpa/inet.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <vector>

namespace {

// ---- small helpers ---------------------------------------------------------

std::string lower(std::string s) {
  for (auto& ch : s) ch = (char)std::tolower((unsigned char)ch);
  return s;
}

// Case-insensitive find, used for header names where a server is free to send
// "authorization:" or "Authorization:".
size_t ifind(const std::string& hay, const char* needle, size_t from = 0) {
  if (from > hay.size()) return std::string::npos;
  size_t n = std::strlen(needle);
  if (hay.size() - from < n) return std::string::npos;
  for (size_t i = from; i + n <= hay.size(); i++) {
    size_t k = 0;
    while (k < n && std::tolower((unsigned char)hay[i + k]) ==
                        std::tolower((unsigned char)needle[k]))
      k++;
    if (k == n) return i;
  }
  return std::string::npos;
}

std::string trim(const std::string& s) {
  size_t a = 0, b = s.size();
  while (a < b && (unsigned char)s[a] <= ' ') a++;
  while (b > a && (unsigned char)s[b - 1] <= ' ') b--;
  return s.substr(a, b - a);
}

// Strips CR/LF and the telnet IAC negotiation so the remaining text can be
// matched as a normal line stream.
std::string stripIac(const std::string& in) {
  std::string out;
  out.reserve(in.size());
  for (size_t i = 0; i < in.size(); i++) {
    if ((unsigned char)in[i] == 0xFF) {
      // IAC SB <data> IAC SE -- 0xFA to 0xFF, terminated by IAC SE.
      if (i + 1 < in.size() && (unsigned char)in[i + 1] == 0xFA) {
        i += 2;
        while (i + 1 < in.size() &&
               !((unsigned char)in[i] == 0xFF && (unsigned char)in[i + 1] == 0xF0))
          i++;
        i++;  // land on the IAC of the terminator
        continue;
      }
      // Plain two-byte commands (WILL/WONT/DO/DONT) are a verb plus an option.
      if (i + 2 < in.size() && (unsigned char)in[i + 1] >= 0xFB) {
        i += 2;
        continue;
      }
      if (i + 1 < in.size()) {
        i += 1;
        continue;
      }
    }
    if ((unsigned char)in[i] == 0x00) continue;  // NUL padding
    out += in[i];
  }
  return out;
}

// Percent-decoding, for credentials submitted in an HTML form. '+' is a space in
// form encoding, which is a genuine difference from base64 and worth getting
// right: it is why "p+ss" and "p ss" are the same submitted password.
std::string urldecode(const std::string& s) {
  std::string out;
  auto hex = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  for (size_t i = 0; i < s.size(); i++) {
    if (s[i] == '%' && i + 2 < s.size()) {
      int h = hex(s[i + 1]), l = hex(s[i + 2]);
      if (h >= 0 && l >= 0) {
        out += (char)(h * 16 + l);
        i += 2;
        continue;
      }
    }
    out += (s[i] == '+') ? ' ' : s[i];
  }
  return out;
}

// Pulls "name=value" out of a form body, matching the name case-insensitively
// and decoding the value. Returns false when the key is absent.
bool formField(const std::string& body, const char* key, std::string* out) {
  std::string k = std::string(key) + "=";
  // The first field in a body has no separator in front of it, so requiring one
  // means the leading pair is only ever found by accident, when some other
  // parameter happens to repeat the name later in the body.
  size_t p = ifind(body, k.c_str());
  size_t v = p + k.size();
  if (p == std::string::npos) return false;
  size_t e = body.find_first_of("&\r\n ", v);
  *out = urldecode(body.substr(v, e == std::string::npos ? std::string::npos
                                                         : e - v));
  return !out->empty();
}

// Reads a base64 token starting at `p`, and requires it to be followed by a line
// ending.
//
// The requirement is what makes a truncated capture honest. Half of
// "Ym9iOmJ1aWxkZXI=" decodes cleanly to "bob:bu" -- printable, colon-bearing,
// and indistinguishable from a real credential with the password "bu". A
// request that is still in flight simply has no CRLF after the token yet, so it
// is not a credential *yet*; the sliding window re-scans on the next packet and
// the complete token parses then.
static std::string b64TokenLine(const std::string& s, size_t p) {
  size_t e = p;
  while (e < s.size() && (isalnum((unsigned char)s[e]) || s[e] == '+' ||
                          s[e] == '/' || s[e] == '='))
    e++;
  if (e == p) return "";
  if (e + 1 >= s.size() || s[e] != '\r' || s[e + 1] != '\n') return "";
  return s.substr(p, e - p);
}

// Reads a token for schemes that are not base64. A Bearer token is usually a
// JWT, whose segments are separated by dots, so the base64 alphabet alone
// truncates "abc.def.ghi" to "abc" and reports a short token as though that
// were all of it.
std::string authToken(const std::string& s, size_t p) {
  size_t e = p;
  while (e < s.size() && (isalnum((unsigned char)s[e]) || s[e] == '.' ||
                          s[e] == '-' || s[e] == '_' || s[e] == '~' ||
                          s[e] == '+' || s[e] == '/' || s[e] == '='))
    e++;
  return s.substr(p, e - p);
}

// Walks the lines of a protocol transcript, stripping telnet noise and dropping
// empty ones. Callers use this instead of scanning the raw buffer so a command
// split across two packets still parses.
std::vector<std::string> lines(const std::string& raw) {
  std::string body = stripIac(raw);
  std::vector<std::string> out;
  size_t p = 0;
  while (p <= body.size()) {
    size_t e = body.find('\n', p);
    std::string l = trim(body.substr(p, e == std::string::npos
                                            ? std::string::npos
                                            : e - p));
    if (!l.empty()) out.push_back(l);
    if (e == std::string::npos) break;
    p = e + 1;
  }
  return out;
}

int u16(const uint8_t* p) { return (int)((p[0] << 8) | p[1]); }
int u32(const uint8_t* p) {
  return (int)(((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
               ((uint32_t)p[2] << 8) | p[3]);
}

bool isPrintableRun(const std::string& s) {
  if (s.empty()) return false;
  for (unsigned char ch : s)
    if (ch < 0x20 || ch > 0x7E) return false;
  return true;
}

}  // namespace

// ---- base64 ----------------------------------------------------------------

bool b64Decode(const std::string& in, std::string* out) {
  static int8_t rev[256];
  static bool init = false;
  if (!init) {
    memset(rev, -1, sizeof rev);
    const char* A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (int i = 0; i < 64; i++) rev[(unsigned char)A[i]] = (int8_t)i;
    init = true;
  }
  uint32_t acc = 0;
  int bits = 0;
  out->clear();
  for (unsigned char ch : in) {
    if (isspace(ch)) continue;
    if (ch == '=') break;
    if (rev[ch] < 0) return false;
    acc = (acc << 6) | (uint32_t)rev[ch];
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out->push_back((char)((acc >> bits) & 0xFF));
    }
  }
  return !out->empty();
}

std::string printable(const std::string& s, size_t maxLen) {
  std::string out;
  size_t n = std::min(s.size(), maxLen);
  for (size_t i = 0; i < n; i++) {
    unsigned char ch = (unsigned char)s[i];
    if (ch >= 0x20 && ch <= 0x7E) {
      out += (char)ch;
    } else {
      char buf[8];
      snprintf(buf, sizeof buf, "\\x%02X", ch);
      out += buf;
    }
  }
  if (s.size() > n) out += "...";
  return out;
}

// ---- per-protocol parsers --------------------------------------------------
//
// Each returns true and fills `out` when it recognises a credential. They are
// written to be stateless and idempotent against the sliding window, so a
// credential that spans a segment boundary parses the same whether it arrived
// in one packet or three.

namespace {

// Skips the run of spaces/tabs after an auth-scheme keyword, returning the
// offset of its argument.
static size_t skipBlanks(const std::string& s, size_t p) {
  while (p < s.size() && (s[p] == ' ' || s[p] == '\t')) p++;
  return p;
}

bool parseAuthorization(const std::string& view, const std::string& src,
                        const std::string& dst, int dport, Cred* out) {
  size_t p = 0;
  for (;;) {
    p = ifind(view, "authorization:", p);
    if (p == std::string::npos) return false;
    // v points just past the colon; the scheme follows after the blanks. Reading
    // the base64 from v + 5 instead starts on the space after "Basic", which is
    // not a base64 character, so every header yields an empty token and nothing
    // is ever found.
    size_t v = skipBlanks(view, p + 14);
    if (ifind(view, "basic", v) == v) {
      size_t a = skipBlanks(view, v + 5);
      std::string tok = b64TokenLine(view, a);
      std::string dec;
      if (!b64Decode(tok, &dec)) {
        p = v;
        continue;
      }
      size_t colon = dec.find(':');
      if (colon == std::string::npos) {
        p = v;
        continue;
      }
      std::string user = dec.substr(0, colon);
      std::string pass = dec.substr(colon + 1);
      // A base64 blob split across a segment boundary still decodes -- to
      // whatever those first bytes happen to be -- and the garbage routinely
      // contains a colon. Requiring both halves to be printable is what
      // separates a real credential from a truncated one, and it is also why
      // the sliding window is worth having: the complete blob passes this.
      if (!isPrintableRun(user) || pass.empty() || !isPrintableRun(pass)) {
        p = v;
        continue;
      }
      out->proto = "http";
      out->src = src;
      out->dst = dst;
      out->dport = dport;
      out->user = printable(user);
      out->pass = printable(pass);
      return true;
    }
    if (ifind(view, "bearer", v) == v) {
      std::string tok = authToken(view, skipBlanks(view, v + 6));
      if (tok.empty()) {
        p = v;
        continue;
      }
      out->proto = "http";
      out->src = src;
      out->dst = dst;
      out->dport = dport;
      out->user = "bearer";
      out->pass = printable(tok);
      out->challenge = true;  // a token, not a password
      return true;
    }
    p = v;
  }
}

bool parseHttpForm(const std::string& view, const std::string& src,
                   const std::string& dst, int dport, Cred* out) {
  // Only a form body carries username=...&password=..., and only after a
  // Content-Type of application/x-www-form-urlencoded. Requiring the header
  // keeps a URL with ?password= in a GET line from being reported as a login.
  if (ifind(view, "content-type:") == std::string::npos) return false;
  size_t ct = ifind(view, "content-type:");
  size_t ctEnd = view.find('\n', ct);
  if (ctEnd == std::string::npos) ctEnd = view.size();
  if (ifind(view.substr(ct, ctEnd - ct), "x-www-form-urlencoded") ==
      std::string::npos)
    return false;

  size_t body = view.find("\r\n\r\n");
  size_t skip = 4;
  if (body == std::string::npos) {
    body = view.find("\n\n");
    skip = 2;
  }
  if (body == std::string::npos) return false;
  std::string b = view.substr(body + skip);

  // The field names vary by form, so try the usual spellings rather than only
  // one; a login form that calls it "user" is as common as one that says
  // "username", and both are the same credential.
  static const char* users[] = {"username", "user", "login", "email",
                                "userid",    "usr", "mail", nullptr};
  static const char* passes[] = {"password", "passwd", "pass", "pwd", nullptr};
  std::string u, pw;
  bool gotU = false, gotP = false;
  for (int i = 0; users[i] && !(gotU && gotP); i++)
    if (!gotU && formField(b, users[i], &u)) gotU = true;
  for (int i = 0; passes[i] && !(gotU && gotP); i++)
    if (!gotP && formField(b, passes[i], &pw)) gotP = true;
  if (!gotP) return false;
  if (!gotU) u = "";
  out->proto = "http";
  out->src = src;
  out->dst = dst;
  out->dport = dport;
  out->user = printable(u);
  out->pass = printable(pw);
  return true;
}

// FTP (21) and POP3 (110) both send bare "USER x" / "PASS x" lines.
//
// The *latest* complete pair wins, and the username is the one seen before that
// password rather than the first username in the buffer. The sliding window
// keeps the previous exchange around, so a client that logs in twice on the
// same 4-tuple (a reconnect that reuses the port, or a kept-alive session that
// re-authenticates) would otherwise only ever be reported once -- the first
// login in the window shadows the second, and dedup throws the result away as
// a repeat. Pairing the last PASS with the USER that preceded it is also what
// stops a half-finished third login from being reported as new-user with the
// old password.
bool parseUserPass(const std::vector<std::string>& ls, const char* proto,
                   const std::string& src, const std::string& dst, int dport,
                   Cred* out) {
  std::string curUser, lastUser, lastPass;
  bool lastChallenge = false;
  for (const auto& l : ls) {
    if (l.size() > 5 && ifind(l, "user ") == 0) {
      curUser = trim(l.substr(5));
      continue;
    }
    if (l.size() > 5 && ifind(l, "pass ") == 0) {
      lastUser = curUser;
      lastPass = trim(l.substr(5));
      lastChallenge = false;
      continue;
    }
    // POP3 APOP carries the password MD5'd with a server nonce. That is a
    // challenge response, not a password, and reporting the digest as the
    // password would be a lie.
    if (l.size() > 5 && ifind(l, "apop ") == 0) {
      lastUser = trim(l.substr(5));
      lastPass = "apop md5 challenge";
      lastChallenge = true;
      curUser.clear();
    }
  }
  if (lastPass.empty()) return false;
  out->proto = proto;
  out->src = src;
  out->dst = dst;
  out->dport = dport;
  out->user = printable(lastUser);
  out->pass = printable(lastPass);
  out->challenge = lastChallenge;
  return true;
}

bool parseImap(const std::vector<std::string>& ls, const std::string& src,
               const std::string& dst, int dport, Cred* out) {
  // The last LOGIN in the window wins, for the same reason as parseUserPass: a
  // re-authentication on an open session still has to be reportable.
  bool found = false;
  for (const auto& l : ls) {
    size_t k = ifind(l, "login ");
    if (k == std::string::npos) continue;
    std::vector<std::string> t;
    size_t p = k + 6;
    while (p <= l.size()) {
      size_t e = l.find(' ', p);
      if (e == std::string::npos) {
        t.push_back(l.substr(p));
        break;
      }
      t.push_back(l.substr(p, e - p));
      p = e + 1;
    }
    if (t.size() < 2) continue;
    // An IMAP LOGIN is quoted; the quotes are syntax, not part of the name.
    auto unq = [](std::string s) {
      s = trim(s);
      if (s.size() >= 2 && s.front() == '"' && s.back() == '"')
        s = s.substr(1, s.size() - 2);
      return s;
    };
    out->proto = "imap";
    out->src = src;
    out->dst = dst;
    out->dport = dport;
    out->user = printable(unq(t[0]));
    out->pass = printable(unq(t[1]));
    out->challenge = false;
    found = true;
  }
  return found;
}

bool parseSmtp(const std::vector<std::string>& ls, const std::string& src,
               const std::string& dst, int dport, Cred* out) {
  // Last AUTH in the window wins, as in parseUserPass.
  bool found = false;
  Cred hit;
  for (size_t i = 0; i < ls.size(); i++) {
    const std::string& l = ls[i];
    size_t k = ifind(l, "auth ");
    if (k != 0) continue;
    std::vector<std::string> t;
    size_t p = 5;
    while (p <= l.size()) {
      size_t e = l.find(' ', p);
      if (e == std::string::npos) {
        t.push_back(l.substr(p));
        break;
      }
      t.push_back(l.substr(p, e - p));
      p = e + 1;
    }
    if (t.empty()) continue;
    std::string mech = lower(t[0]);

    if (mech == "plain") {
      // "AUTH PLAIN [b64]" where b64 is NUL user NUL pass. Without the initial
      // response the credentials are in the two following base64 lines.
      std::string tok = (t.size() > 1) ? t[1] : "";
      if (tok.empty() && i + 1 < ls.size()) tok = trim(ls[i + 1]);
      std::string dec;
      if (!b64Decode(tok, &dec)) continue;
      // PLAIN is authzid NUL authcid NUL passwd, so the first NUL ends the
      // (usually empty) authzid and the *second* one ends the username. Taking
      // the first NUL as the separator yields an empty username and the
      // username as the password.
      size_t a = dec.find('\0');
      if (a == std::string::npos) continue;
      size_t b = dec.find('\0', a + 1);
      if (b == std::string::npos) continue;
      hit.proto = "smtp";
      hit.src = src;
      hit.dst = dst;
      hit.dport = dport;
      hit.user = printable(dec.substr(a + 1, b - a - 1));
      hit.pass = printable(dec.substr(b + 1));
      found = true;
      continue;
    }
    if (mech == "login") {
      // "AUTH LOGIN" is answered by base64(user) then base64(pass), so the
      // credentials are the next two lines.
      if (i + 2 >= ls.size()) continue;
      std::string u, pw;
      if (!b64Decode(trim(ls[i + 1]), &u)) continue;
      if (!b64Decode(trim(ls[i + 2]), &pw)) continue;
      hit.user = printable(u);
      hit.pass = printable(pw);
      found = true;
      continue;
    }
    if (mech == "cram-md5") {
      std::string tok = (t.size() > 1) ? t[1] : "";
      if (tok.empty() && i + 1 < ls.size()) tok = trim(ls[i + 1]);
      std::string dec;
      if (!b64Decode(tok, &dec)) continue;
      size_t sp = dec.find(' ');
      out->proto = "smtp";
      out->src = src;
      out->dst = dst;
      out->dport = dport;
      hit.user = printable(sp == std::string::npos ? dec : dec.substr(0, sp));
      hit.pass = "cram-md5 md5 challenge";
      hit.challenge = true;
      found = true;
      continue;
    }
  }
  if (!found) return false;
  hit.proto = "smtp";
  hit.src = src;
  hit.dst = dst;
  hit.dport = dport;
  *out = hit;
  return true;
}

bool parseTelnet(const std::vector<std::string>& ls, const std::string& src,
                 const std::string& dst, int dport, Cred* out) {
  // A login is a prompt followed by a line that is not a prompt. The prompt
  // tells us which field the next line fills, so a bare "admin" line means
  // nothing on its own and must not be reported.
  const char* kUser[] = {"login", "username", "user name", nullptr};
  const char* kPass[] = {"password", "passwd", "pass", nullptr};
  // Last exchange in the window wins, as in parseUserPass.
  bool found = false;
  Cred hit;
  for (size_t i = 0; i + 1 < ls.size(); i++) {
    std::string p = lower(ls[i]);
    auto isPrompt = [&](const char* const* keys) {
      for (int k = 0; keys[k]; k++)
        if (p.find(keys[k]) != std::string::npos) return true;
      return false;
    };
    if (!isPrompt(kUser) && !isPrompt(kPass)) continue;
    // The prompt and its answer can be on one line: "Password: hunter2".
    size_t colon = p.find(':');
    std::string inline_;
    bool haveInline = false;
    if (colon != std::string::npos) {
      std::string tail = trim(ls[i].substr(colon + 1));
      if (!tail.empty()) {
        inline_ = tail;
        haveInline = true;
      }
    }
    std::string ans = haveInline ? inline_ : trim(ls[i + 1]);
    if (ans.empty()) continue;
    // A following prompt means the previous line was a prompt with no answer
    // captured, not a password.
    if (!haveInline && lower(ans).find(':') != std::string::npos) continue;

    hit.proto = "telnet";
    hit.src = src;
    hit.dst = dst;
    hit.dport = dport;
    if (isPrompt(kPass)) {
      // The username is whatever was typed at the earlier prompt; the banner on
      // line 0 is a guess, and is labelled "?" when the window has no answer.
      std::string prev = printable(trim(ls[0]));
      hit.user = prev.empty() ? "?" : prev;
      hit.pass = printable(ans);
    } else {
      hit.user = printable(ans);
      hit.pass.clear();
    }
    hit.challenge = false;
    found = true;
  }
  if (!found) return false;
  *out = hit;
  return true;
}

bool parseRedis(const std::string& view, const std::string& src,
                const std::string& dst, int dport, Cred* out) {
  // RESP, not a line protocol: a command is *2\r\n$4\r\nAUTH\r\n$6\r\ns3cret.
  // Scanning for "AUTH " as a line finds nothing, because the protocol has no
  // spaces in it at all -- the earlier version of this returned on every
  // Redis packet.
  std::vector<std::string> args;
  size_t i = 0;
  if (i >= view.size() || view[i] != '*') return false;
  i++;
  // array length
  size_t ls = i;
  while (i < view.size() && view[i] != '\r') i++;
  if (i >= view.size()) return false;
  int n = atoi(view.substr(ls, i - ls).c_str());
  i += 2;
  for (int k = 0; k < n; k++) {
    if (i >= view.size() || view[i] != '$') break;
    i++;
    size_t ls2 = i;
    while (i < view.size() && view[i] != '\r') i++;
    if (i >= view.size()) return false;
    int len = atoi(view.substr(ls2, i - ls2).c_str());
    i += 2;
    if (len < 0 || i + (size_t)len > view.size()) return false;
    args.push_back(view.substr(i, (size_t)len));
    i += (size_t)len;
    if (i < view.size() && view[i] == '\r') i += 2;
  }
  if (args.size() < 2) return false;
  if (lower(args[0]) != "auth") return false;
  std::string user, pass = args[1];
  // "AUTH <pass>" (no user, the default) or "AUTH <user> <pass>".
  if (args.size() >= 3) {
    user = args[1];
    pass = args[2];
  }
  if (pass.empty()) return false;
  out->proto = "redis";
  out->src = src;
  out->dst = dst;
  out->dport = dport;
  out->user = printable(user);
  out->pass = printable(pass);
  return true;
}

bool parseMqtt(const std::string& view, const std::string& src,
               const std::string& dst, int dport, Cred* out) {
  // A CONNECT control packet is fixed up to the client id, then a run of
  // length-prefixed UTF-8 strings. The will fields come before username and
  // password, so they are counted off rather than assumed absent -- skipping
  // that step reads a will topic as the username whenever a will is set.
  if (view.size() < 12) return false;
  const uint8_t* p = (const uint8_t*)view.data();
  size_t i = 0;
  auto readStr = [&](std::string* s) -> bool {
    if (i + 2 > view.size()) return false;
    int n = u16(p + i);
    i += 2;
    if (n < 0 || i + (size_t)n > view.size()) return false;
    *s = view.substr(i, (size_t)n);
    i += (size_t)n;
    return true;
  };
  std::string protoName, clientId;
  if (!readStr(&protoName) || lower(protoName) != "mqtt") return false;
  if (i + 4 > view.size()) return false;
  uint8_t flags = p[i + 1];
  i += 4;  // level, flags, keepalive
  if (!readStr(&clientId)) return false;
  std::string willTopic, willMsg, user, pass;
  if (flags & 0x04) {
    if (!readStr(&willTopic) || !readStr(&willMsg)) return false;
  }
  if (flags & 0x80) {
    if (!readStr(&user)) return false;
  }
  if (flags & 0x40) {
    if (!readStr(&pass)) return false;
  }
  if (user.empty() && pass.empty()) return false;
  out->proto = "mqtt";
  out->src = src;
  out->dst = dst;
  out->dport = dport;
  out->user = printable(user.empty() ? clientId : user);
  out->pass = printable(pass);
  return true;
}

bool parsePostgres(const std::string& view, const std::string& src,
                   const std::string& dst, int dport, Cred* out) {
  // StartupMessage: length, then protocol version 3.0, then NUL-terminated
  // key/value pairs ended by a single NUL. 'user' and 'password' are ordinary
  // keys in that list, so the whole thing is one walk. The version is at offset
  // 4, not 0 -- offset 0 is the message length.
  if (view.size() < 8) return false;
  const uint8_t* p = (const uint8_t*)view.data();
  if (u32(p + 4) != 0x00030000) return false;
  size_t i = 8;
  std::string user, pass;
  for (;;) {
    if (i >= view.size()) return false;
    if (p[i] == 0) break;  // end of the parameter list
    size_t ks = i;
    while (i < view.size() && p[i]) i++;
    size_t i2 = i;
    std::string key(view, ks, i2 - ks);
    i++;  // the NUL after the key
    if (i >= view.size()) return false;
    size_t vs = i;
    while (i < view.size() && p[i]) i++;
    if (i >= view.size()) return false;
    std::string val(view, vs, i - vs);
    i++;
    if (key == "user") user = val;
    if (key == "password") pass = val;
    // The list is closed by a NUL, and the scan above has just consumed one as
    // the terminator of this value -- so the *next* NUL ends the list. Testing
    // for it here is what stops the walk from running off the end of the buffer
    // on the last parameter: a StartupMessage always ends with one empty pair,
    // and the naive loop eats that terminator as a value and then overruns.
    if (i < view.size() && p[i] == 0) break;
  }
  if (pass.empty()) return false;
  out->proto = "postgres";
  out->src = src;
  out->dst = dst;
  out->dport = dport;
  out->user = printable(user);
  out->pass = printable(pass);
  return true;
}

bool parseSnmp(const std::string& view, const std::string& src,
               const std::string& dst, int dport, Cred* out) {
  // BER: SEQUENCE { INTEGER version, OCTET STRING community, ... }. The
  // community is the SNMP equivalent of a password and is the second TLV.
  if (view.size() < 8) return false;
  const uint8_t* p = (const uint8_t*)view.data();
  if (p[0] != 0x30) return false;  // SEQUENCE
  size_t i = 2;
  if (i >= view.size() || p[i] != 0x02) return false;  // INTEGER
  // tag + length byte + value, so the advance is 2 + len. Advancing by 1 + len
  // leaves i on the version byte, the next tag never matches 0x04, and every
  // SNMP packet is reported as having no community string.
  i += 2 + p[i + 1];
  if (i + 1 >= view.size() || p[i] != 0x04) return false;  // OCTET STRING
  int n = p[i + 1];
  if (n < 0 || i + 2 + (size_t)n > view.size()) return false;
  std::string comm(view, i + 2, (size_t)n);
  // "public" is the default and carries no information; reporting it as a
  // discovered credential would just be noise.
  if (comm.empty() || lower(comm) == "public") return false;
  out->proto = "snmp";
  out->src = src;
  out->dst = dst;
  out->dport = dport;
  out->user = "community";
  out->pass = printable(comm);
  return true;
}

bool parseRdp(const std::string& view, const std::string& src,
              const std::string& dst, int dport, Cred* out) {
  // CredSSP wraps the client's NTLM exchange in a TPKT (0x03 0x00 len16) whose
  // SPNEGO publicInfo carries the cleartext "user" and "password" AV pairs
  // that build the Kerberos ticket. Matching the NUL-delimited pair names is
  // enough here and avoids pulling a full ASN.1 decoder in for two fields.
  for (const char* key : {"user", "password"}) {
    // Built with an explicit length. std::string("\0") is an *empty* string,
    // because the const char* constructor stops at the first NUL -- so writing
    // the delimiter that way silently loses the leading byte, the name matches
    // one byte early, and the 2-byte length is then read from the wrong place
    // and comes out as 0. Every AV pair is skipped as malformed.
    std::string k(1, '\0');
    k += key;
    k += '\0';
    size_t p = 0;
    for (;;) {
      p = view.find(k, p);
      if (p == std::string::npos) break;
      // The value is a 2-byte big-endian length followed by the bytes.
      if (p + k.size() + 2 > view.size()) break;
      size_t vp = p + k.size();
      int n = ((uint8_t)view[vp] << 8) | (uint8_t)view[vp + 1];
      if (n <= 0 || vp + 2 + (size_t)n > view.size()) {
        p = vp;
        continue;
      }
      std::string val = view.substr(vp + 2, (size_t)n);
      // A real credential is a short printable run. Rejecting anything else is
      // what keeps a coincidental "\0user\0" inside a Kerberos blob from being
      // reported with the rest of the packet as its password.
      if (isPrintableRun(val) && val.size() <= 64) {
        if (std::strcmp(key, "user") == 0) {
          out->user = printable(val);
          out->pass.clear();
        } else {
          out->pass = printable(val);
          out->proto = "rdp";
          out->src = src;
          out->dst = dst;
          out->dport = dport;
          if (out->user.empty()) out->user = "?";
          return true;
        }
      }
      p = vp;
    }
  }
  return false;
}

}  // namespace

// ---- session ---------------------------------------------------------------

bool CredSniffer::already(const Cred& c) {
  std::string k = c.proto + "\x1f" + c.user + "\x1f" + c.pass + "\x1f" + c.dst;
  if (reported_.count(k)) return true;
  if (saturated()) return true;
  reported_.insert(k);
  return false;
}

bool CredSniffer::feed(int proto, int sport, int dport, const std::string& src,
                       const std::string& dst, const uint8_t* data, size_t len,
                       Cred* out) {
  if (len == 0 || saturated()) return false;

  // Keyed by direction. A sniffed flow is one-directional: the client sends the
  // password, the server never does, so folding both directions into one buffer
  // would interleave a server banner into the middle of a login exchange.
  char key[80];
  snprintf(key, sizeof key, "%s:%d>%s:%d", src.c_str(), sport, dst.c_str(), dport);
  Flow& f = flows_[key];

  // A retransmit repeats the previous window verbatim. Re-scanning it would
  // find the same credential, which dedup absorbs anyway, but dropping the
  // duplicate here keeps the window from filling with one login.
  size_t start = 0;
  if (len <= f.buf.size() && f.buf.size() >= len &&
      memcmp(f.buf.data() + (f.buf.size() - len), data, len) == 0)
    return false;
  if (len < f.buf.size() && start == 0 &&
      f.buf.compare(0, f.buf.size() - len, (const char*)data, len) == 0)
    return false;

  f.buf.append((const char*)data, len);
  if (f.buf.size() > windowMax_)
    f.buf.erase(0, f.buf.size() - windowMax_);

  // Bound the number of tracked flows. A busy link with ephemeral ports will
  // create a new key for nearly every connection seen, and this map is the one
  // structure here that grows with traffic rather than with findings.
  if (flows_.size() > 4096) flows_.clear();

  if (!parse(proto, sport, dport, src, dst, f.buf, out)) return false;
  if (already(*out)) return false;
  return true;
}

bool CredSniffer::parse(int proto, int sport, int dport, const std::string& src,
                        const std::string& dst, std::string& view, Cred* out) {
  // Port-driven parsers run first: they are the ones where the port is
  // authoritative, and a Redis "AUTH" line on port 6379 is a Redis credential
  // no matter what the payload would otherwise look like.
  switch (dport) {
    case 21: return parseUserPass(lines(view), "ftp", src, dst, dport, out);
    case 110: return parseUserPass(lines(view), "pop3", src, dst, dport, out);
    case 143: return parseImap(lines(view), src, dst, dport, out);
    case 25:
    case 465:
    case 587: return parseSmtp(lines(view), src, dst, dport, out);
    case 23: return parseTelnet(lines(view), src, dst, dport, out);
    case 6379: return parseRedis(view, src, dst, dport, out);
    case 1883:
    case 8883: return parseMqtt(view, src, dst, dport, out);
    case 5432: return parsePostgres(view, src, dst, dport, out);
    case 161:
    case 162: return parseSnmp(view, src, dst, dport, out);
    case 3389: return parseRdp(view, src, dst, dport, out);
    default: break;
  }
  // A browser talking to a web server on a non-standard port is ordinary, and
  // HTTP has no port that identifies it, so it is tried on anything left.
  if (ifind(view, "authorization:") != std::string::npos)
    return parseAuthorization(view, src, dst, dport, out);
  if (ifind(view, "content-type:") != std::string::npos &&
      ifind(view, "x-www-form-urlencoded") != std::string::npos)
    return parseHttpForm(view, src, dst, dport, out);
  return false;
}
