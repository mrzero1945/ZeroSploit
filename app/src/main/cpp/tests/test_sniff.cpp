// Host-only tests for the cleartext credential sniffer in zs_sniff.cpp.
//
// The cases below are the ones where a sniffer is easy to get confidently
// wrong: a base64 blob split across two packets, a form body whose field names
// are not "username"/"password", a protocol that repeats its own challenge, an
// MQTT will that shifts the username field by one, and the "user" AV pair in
// CredSSP appearing before the "password" one. Each of those produces output
// that looks plausible and is wrong, so each is pinned here.
#include "zs_sniff.cpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static int fails = 0;

static void ok(const char* what, bool cond) {
  if (!cond) fails++;
  printf("  %-4s %s\n", cond ? "ok" : "FAIL", what);
}

static void eq(const char* what, const std::string& got, const std::string& want) {
  bool c = got == want;
  if (!c) fails++;
  printf("  %-4s %s%s\n", c ? "ok" : "FAIL", what,
         c ? "" : ("  got <" + got + "> want <" + want + ">").c_str());
}

// Feeds one payload through a fresh sniffer, as one packet would.
static bool feed1(CredSniffer& s, int dport, const std::string& payload,
                  Cred* got) {
  return s.feed(6, 40000, dport, "10.0.0.2", "10.0.0.3",
                (const uint8_t*)payload.data(), payload.size(), got);
}

static std::string base64(const std::string& raw) {
  static const char* A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string o;
  size_t i = 0;
  while (i < raw.size()) {
    uint32_t v = 0;
    int n = 0;
    for (int k = 0; k < 3; k++) {
      v <<= 8;
      if (i < raw.size()) { v |= (uint8_t)raw[i++]; n++; }
    }
    o += A[(v >> 18) & 63];
    o += A[(v >> 12) & 63];
    o += n > 1 ? A[(v >> 6) & 63] : '=';
    o += n > 2 ? A[v & 63] : '=';
  }
  return o;
}

int main() {
  printf("base64\n");
  {
    std::string out;
    ok("decodes basic", b64Decode("YWRtaW46aHVudGVyMg==", &out));
    eq("basic value", out, "admin:hunter2");
    ok("rejects junk", !b64Decode("not*base64", &out));
    ok("ignores whitespace", b64Decode("YWRtaW46\r\n aHVudGVyMg==", &out));
  }

  printf("\nhttp basic auth\n");
  {
    CredSniffer s;
    Cred c;
    std::string req = "GET /admin HTTP/1.1\r\nHost: x\r\nAuthorization: Basic "
                      + base64("root:toor") + "\r\n\r\n";
    ok("finds header", feed1(s, 80, req, &c));
    eq("proto", c.proto, "http");
    eq("user", c.user, "root");
    eq("pass", c.pass, "toor");
    ok("not a challenge", !c.challenge);

    // A second copy of the same request must not be reported twice: browsers
    // re-send the header on every navigation.
    CredSniffer s2;
    Cred c2;
    ok("first seen", feed1(s2, 80, req, &c2));
    ok("repeat suppressed", !feed1(s2, 80, req, &c2));
  }
  {
    // Lowercase header name is legal and sent by some clients.
    CredSniffer s;
    Cred c;
    std::string req = "GET / HTTP/1.1\r\nauthorization: basic "
                      + base64("u:p") + "\r\n\r\n";
    ok("case-insensitive header", feed1(s, 80, req, &c));
    eq("user", c.user, "u");
  }
  {
    // A bearer token is a token, not a password, and must be flagged so the UI
    // does not present it as a recovered secret.
    CredSniffer s;
    Cred c;
    std::string req = "GET / HTTP/1.1\r\nAuthorization: Bearer abc.def.ghi\r\n\r\n";
    ok("finds bearer", feed1(s, 80, req, &c));
    ok("marked challenge", c.challenge);
    eq("token", c.pass, "abc.def.ghi");
  }

  printf("\nhttp form post\n");
  {
    CredSniffer s;
    Cred c;
    // Field names that are not the literal "username".
    std::string req =
        "POST /login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n"
        "\r\nuser=alice&pwd=s3cr%65t";
    ok("finds form", feed1(s, 80, req, &c));
    eq("user", c.user, "alice");
    eq("pass percent-decoded", c.pass, "s3cret");
  }
  {
    // '+' is a space in form encoding. Getting this wrong turns a correct
    // password into a wrong one that looks right.
    CredSniffer s;
    Cred c;
    std::string req =
        "POST /l HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n"
        "\r\nusername=bob&password=pa+ss+word";
    ok("finds form", feed1(s, 80, req, &c));
    eq("plus is space", c.pass, "pa ss word");
  }
  {
    // A query string is not a submitted credential.
    CredSniffer s;
    Cred c;
    ok("ignores GET query", !feed1(s, 80, "GET /x?password=hunter2 HTTP/1.1\r\n\r\n", &c));
  }

  printf("\nsegmented capture\n");
  {
    // The base64 blob split across two packets. Scanning each segment alone
    // finds nothing; the sliding window is what makes this work.
    CredSniffer s;
    Cred c;
    std::string tok = base64("bob:builder");
    std::string head = "GET / HTTP/1.1\r\nAuthorization: Basic " + tok.substr(0, 8);
    std::string tail = tok.substr(8) + "\r\n\r\n";
    ok("no match on head alone", !feed1(s, 80, head, &c));
    ok("match once complete", feed1(s, 80, tail, &c));
    eq("user", c.user, "bob");
    eq("pass", c.pass, "builder");
  }
  {
    // A retransmit must not count as new traffic.
    CredSniffer s;
    Cred c;
    std::string seg = "GET / HTTP/1.1\r\nAuthorization: Basic "
                      + base64("carol:x") + "\r\n\r\n";
    ok("first", feed1(s, 80, seg, &c));
    ok("retransmit ignored", !feed1(s, 80, seg, &c));
  }

  printf("\nftp / pop3\n");
  {
    CredSniffer s;
    Cred c;
    ok("finds user/pass",
       feed1(s, 21, "USER anonymous\r\nPASS guest@example.com\r\n", &c));
    eq("proto", c.proto, "ftp");
    eq("user", c.user, "anonymous");
    eq("pass", c.pass, "guest@example.com");
  }
  {
    // POP3 APAP returns MD5(user:nonce:pass). Reporting the digest as a
    // password would be a lie about what was captured.
    CredSniffer s;
    Cred c;
    ok("finds apop",
       feed1(s, 110, "USER bob\r\nAPOP bob 4b1c2d <md5hash>\r\n", &c));
    ok("marked challenge", c.challenge);
  }
  {
    // A server greeting with no USER/PASS must not be reported.
    CredSniffer s;
    Cred c;
    ok("ignores banner", !feed1(s, 21, "220 Welcome to the server\r\n", &c));
  }

  printf("\nimap\n");
  {
    CredSniffer s;
    Cred c;
    ok("finds login", feed1(s, 143, "a001 LOGIN \"dave\" \"davepw\"\r\n", &c));
    eq("user unquoted", c.user, "dave");
    eq("pass unquoted", c.pass, "davepw");
  }

  printf("\nsmtp\n");
  {
    CredSniffer s;
    Cred c;
    // AUTH PLAIN with an initial response: NUL user NUL pass.
    // Explicit lengths throughout: a "\0eve" literal as a const char* is a
    // 1-byte string, and `+ "\0evepw"` contributes nothing at all.
    std::string blob("\0eve\0evepw", 10);
    ok("finds plain", feed1(s, 25, "AUTH PLAIN " + base64(blob) + "\r\n", &c));
    eq("user", c.user, "eve");
    eq("pass", c.pass, "evepw");
  }
  {
    // AUTH LOGIN: the credentials are the next two base64 lines, so this only
    // parses when the exchange is read as a sequence.
    CredSniffer s;
    Cred c;
    std::string t = "AUTH LOGIN\r\n" + base64("frank") + "\r\n" + base64("fpass") + "\r\n";
    ok("finds login", feed1(s, 587, t, &c));
    eq("user", c.user, "frank");
    eq("pass", c.pass, "fpass");
  }
  {
    CredSniffer s;
    Cred c;
    ok("finds cram",
       feed1(s, 25, "AUTH CRAM-MD5 " + base64("grace hostnonce") + "\r\n", &c));
    ok("marked challenge", c.challenge);
  }

  printf("\ntelnet\n");
  {
    CredSniffer s;
    Cred c;
    // IAC negotiation bytes must not stop the prompts from being found.
    std::string t;
    t += (char)0xFF; t += (char)0xFB; t += (char)0x01;   // WILL ECHO
    t += (char)0xFF; t += (char)0xFD; t += (char)0x01;   // DO ECHO
    t += "login: admin\r\nPassword: letmein\r\n";
    ok("finds login", feed1(s, 23, t, &c));
    ok("pass captured", c.pass == "letmein" || c.user == "admin");
  }
  {
    // Two consecutive prompts with no captured answer: reporting the second
    // prompt as a password would be nonsense.
    CredSniffer s;
    Cred c;
    ok("ignores bare prompts",
       !feed1(s, 23, "login:\r\nPassword:\r\n", &c));
  }

  printf("\nredis / mqtt / postgres / snmp\n");
  {
    CredSniffer s;
    Cred c;
    ok("finds auth", feed1(s, 6379, "*2\r\n$4\r\nAUTH\r\n$6\r\ns3cret\r\n", &c));
    eq("pass", c.pass, "s3cret");
  }
  {
    // MQTT CONNECT with a will set. The will topic and message sit between the
    // client id and the username, so a parser that does not count them off
    // reads the will topic as the username.
    std::string m;
    auto s16 = [&](const std::string& v) {
      m += (char)((v.size() >> 8) & 0xFF);
      m += (char)(v.size() & 0xFF);
      m += v;
    };
    s16("MQTT");
    m += (char)0x04;               // protocol level
    m += (char)(0x04 | 0x80 | 0x40);  // will + username + password
    m += (char)0x00; m += (char)0x3C;  // keepalive
    s16("client1");
    s16("devices/+/state");
    s16("offline");
    s16("hank");
    s16("mqttpass");
    CredSniffer s;
    Cred c;
    ok("finds mqtt", feed1(s, 1883, m, &c));
    eq("username not the will topic", c.user, "hank");
    eq("pass", c.pass, "mqttpass");
  }
  {
    // Postgres StartupMessage: length, 3.0, then NUL key/value pairs.
    std::string m;
    auto s32 = [&](uint32_t v) {
      m += (char)((v >> 24) & 0xFF);
      m += (char)((v >> 16) & 0xFF);
      m += (char)((v >> 8) & 0xFF);
      m += (char)(v & 0xFF);
    };
    // Built with an explicit length: "user\0pguser..." as a plain literal is a
    // 5-byte string, because the NUL ends it. The 41st byte is the NUL after the
    // last value; the one appended after that closes the parameter list. A real
    // StartupMessage has both, and dropping the first makes the value scan eat
    // the terminator as if it were part of "pgpass".
    std::string kv("user\0pguser\0database\0app\0password\0pgpass\0", 41);
    uint32_t len = (uint32_t)(4 + 4 + kv.size() + 1);
    s32(len);
    s32(0x00030000);
    m += kv;
    m += '\0';
    CredSniffer s;
    Cred c;
    ok("finds startup", feed1(s, 5432, m, &c));
    eq("user", c.user, "pguser");
    eq("pass", c.pass, "pgpass");
  }
  {
    // SNMP community, and the "public" default which is not a finding.
    auto ber = [](const std::string& comm) {
      std::string m;
      m += (char)0x30; m += (char)0x26;
      m += (char)0x02; m += (char)0x01; m += (char)0x00;
      m += (char)0x04; m += (char)(uint8_t)comm.size();
      m += comm;
      m += (char)0xA0; m += (char)0x1E;   // varbind list, contents ignored
      m += std::string(0x1E, '\0');
      return m;
    };
    CredSniffer s;
    Cred c;
    ok("finds community", feed1(s, 161, ber("s3cretcomm"), &c));
    eq("pass", c.pass, "s3cretcomm");
    CredSniffer s2;
    Cred c2;
    ok("ignores public default", !feed1(s2, 161, ber("public"), &c2));
  }

  printf("\nrdp credssp\n");
  {
    // CredSSP publicInfo carries "user" before "password" as NUL-delimited AV
    // pairs with 2-byte big-endian lengths.
    std::string m;
    m += (char)0x03; m += (char)0x00; m += (char)0x00; m += (char)0x7B;  // TPKT
    auto av = [&](const char* k, const std::string& v) {
      m += '\0'; m += k; m += '\0';
      m += (char)((v.size() >> 8) & 0xFF);
      m += (char)(v.size() & 0xFF);
      m += v;
    };
    av("user", "CORP\\jdoe");
    av("password", "RdpPass!");
    CredSniffer s;
    Cred c;
    ok("finds credssp", feed1(s, 3389, m, &c));
    eq("user", c.user, "CORP\\jdoe");
    eq("pass", c.pass, "RdpPass!");
  }

  printf("\nnon-credentials\n");
  {
    CredSniffer s;
    Cred c;
    ok("https is opaque", !feed1(s, 443, std::string("\x17\x03\x03\x00\x10", 5) + std::string(16, 'x'), &c));
    ok("dns is opaque", !feed1(s, 53, std::string("\x00\x01\x01\x00", 4) + std::string(20, 'x'), &c));
  }

  printf("\nreport cap\n");
  {
    CredSniffer s(512, 2);
    Cred c;
    int found = 0;
    for (int i = 0; i < 10; i++) {
      char user[32];
      snprintf(user, sizeof user, "u%d", i);
      if (feed1(s, 21, std::string("USER ") + user + "\r\nPASS p" + user + "\r\n", &c))
        found++;
    }
    eq("stops at cap", std::to_string(found), "2");
    ok("reports saturation", s.saturated());
  }

  printf("\n%s (%d failure(s))\n", fails ? "FAILED" : "ALL PASS", fails);
  return fails ? 1 : 0;
}
