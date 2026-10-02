// Host-only tests for the service fingerprint and CVE matching pipeline in
// zs_engine.cpp.
//
// Separate from test_packets.cpp and test_json.cpp: this one pulls in
// zs_engine.cpp, which needs zs_util.cpp linked alongside it (the other two
// translation units each include one of those and would collide on trim/J).
//
// Every case here is a bug that was found and fixed. The point of the file is
// that the specific false positives that were shipped -- a patched Samba
// reported CRITICAL, OpenSSH p1 and p2 compared equal, an unreadable version
// reading as 0.0.0, version-independent rules never firing, an OUI row
// shadowed by an earlier one -- stay fixed.
#include "zs_engine.cpp"

#include <cstdio>
#include <set>
#include <string>
#include <vector>

// zs_engine.cpp opens `namespace zs` and never closes it, so including it
// leaves the test body outside that namespace with nothing in scope. The
// engine is only ever built as one translation unit, so pulling the namespace
// in here is equivalent to what the real build does.
using namespace zs;

namespace zs {
// opCapabilities() in the same file calls this. It lives in zs_raw.cpp, which
// pulls in Android headers and cannot be linked into a host test, and nothing
// in this file exercises it -- the stub only exists so the link resolves.
RawCaps probeRawCaps(const std::string&) {
  RawCaps c;
  c.detail = "not available in host unit tests";
  return c;
}
}  // namespace zs

static int fails = 0;
static void ok(const char* what, bool cond) {
  printf("%-58s %s\n", what, cond ? "PASS" : "FAIL");
  if (!cond) fails++;
}

// Does `cve` appear in this result set?
static bool hasCve(const std::vector<Finding>& f, const char* cve) {
  for (auto& x : f)
    if (x.cve == cve) return true;
  return false;
}

static int countProduct(const std::vector<Finding>& f, const std::string& p) {
  int n = 0;
  for (auto& x : f)
    if (x.product == p) n++;
  return n;
}

int main() {
  // ================================================================ versions
  {
    bool okp = false;
    ok("cmpVersion 4.9.5 > 4.6.7", cmpVersion("4.9.5", "4.6.7", &okp) > 0 && okp);
    ok("cmpVersion 8.4p1 == 8.4p1", cmpVersion("8.4p1", "8.4p1", &okp) == 0 && okp);
    // The reason the parser has a fourth component. These two are different
    // releases and one of them is the fix for a CRITICAL.
    ok("cmpVersion 9.3p1 < 9.3p2", cmpVersion("9.3p1", "9.3p2", &okp) < 0 && okp);
    ok("cmpVersion 9.3p2 == 9.3p2", cmpVersion("9.3p2", "9.3p2", &okp) == 0 && okp);
    ok("cmpVersion 9.3 < 9.3p1 (p-level above plain)", cmpVersion("9.3", "9.3p1", &okp) < 0 && okp);
    ok("cmpVersion 8.9p1 < 9.3p1", cmpVersion("8.9p1", "9.3p1", &okp) < 0 && okp);
    ok("cmpVersion strips leading v", cmpVersion("v1.2.3", "1.2.3", &okp) == 0 && okp);
    ok("cmpVersion 2.88 < 2.90 (not string compare)", cmpVersion("2.88", "2.90", &okp) < 0 && okp);
    ok("cmpVersion 2.9 > 2.90 is false, 2.9 < 2.90", cmpVersion("2.9", "2.90", &okp) < 0 && okp);
    ok("cmpVersion 1.4.53 > 1.4.9 (not string compare)", cmpVersion("1.4.53", "1.4.9", &okp) > 0 && okp);
  }

  // ---- an unreadable version must not compare as 0.0.0
  {
    bool okp = true;
    cmpVersion("smbd", "4.17.12", &okp);
    ok("cmpVersion rejects \"smbd\" as a version", !okp);
    okp = true;
    cmpVersion("unknown", "4.17.12", &okp);
    ok("cmpVersion rejects \"unknown\"", !okp);
    okp = true;
    cmpVersion("", "1.0", &okp);
    ok("cmpVersion rejects the empty string", !okp);
    okp = true;
    cmpVersion("4.9.5", "smbd", &okp);
    ok("cmpVersion rejects a bad bound too", !okp);
  }

  // ============================================================ fingerprints
  {
    auto s = fingerprint(22, "SSH-2.0-OpenSSH_9.3p1 Ubuntu-3ubuntu0.4", "");
    ok("ssh banner -> product OpenSSH", s.product == "OpenSSH");
    ok("ssh banner -> version 9.3p1", s.version == "9.3p1");

    s = fingerprint(22, "SSH-2.0-OpenSSH_9.3p2", "");
    ok("ssh p2 banner -> version 9.3p2", s.version == "9.3p2");

    s = fingerprint(22, "SSH-2.0-dropbear_2022.83", "");
    ok("dropbear banner -> product Dropbear", s.product == "Dropbear");
    ok("dropbear banner -> version 2022.83", s.version == "2022.83");

    // A non-OpenSSH SSH server must not be reported as OpenSSH, which is what
    // made every SSH host on the LAN match the OpenSSH rules.
    s = fingerprint(22, "SSH-2.0-Sun_SSH_1.1.5", "");
    ok("vendor ssh is not OpenSSH", s.product != "OpenSSH");

    // "Samba smbd 4.9.5": the version is the second token. The first token
    // after "samba " is "smbd", which has no digits in it.
    s = fingerprint(445, "Samba smbd 4.9.5", "");
    ok("samba banner -> product Samba", s.product == "Samba");
    ok("samba banner -> version 4.9.5", s.version == "4.9.5");

    s = fingerprint(80, "Server: uhttpd/1.0.0", "");
    ok("uhttpd banner -> version 1.0.0", s.product == "uhttpd" && s.version == "1.0.0");
  }

  // ============================================================ CVE matching
  // The OpenSSH p-level boundary: 9.3p1 is vulnerable to the p1 fix, 9.3p2 is
  // not. With a three-component parser these two were indistinguishable, so
  // either the vulnerable host went unreported or the patched host was.
  {
    std::vector<ServiceInfo> v;
    v.push_back(fingerprint(22, "SSH-2.0-OpenSSH_9.3p1", ""));
    auto f = matchCves("10.0.0.1", v);
    ok("OpenSSH 9.3p1 -> CVE-2023-38408 reported", hasCve(f, "CVE-2023-38408"));
    ok("OpenSSH 9.3p1 -> CVE-2023-1389 NOT reported", !hasCve(f, "CVE-2023-1389"));
  }
  {
    std::vector<ServiceInfo> v;
    v.push_back(fingerprint(22, "SSH-2.0-OpenSSH_9.3p2", ""));
    auto f = matchCves("10.0.0.1", v);
    ok("OpenSSH 9.3p2 -> CVE-2023-38408 NOT reported", !hasCve(f, "CVE-2023-38408"));
    ok("OpenSSH 9.3p2 -> CVE-2023-1389 NOT reported", !hasCve(f, "CVE-2023-1389"));
  }
  {
    std::vector<ServiceInfo> v;
    v.push_back(fingerprint(22, "SSH-2.0-OpenSSH_8.4p1", ""));
    auto f = matchCves("10.0.0.1", v);
    ok("OpenSSH 8.4p1 -> both rules fire", hasCve(f, "CVE-2023-38408") &&
                                          hasCve(f, "CVE-2023-1389"));
  }

  // A patched Samba must be clean. Note that 4.9.5 is NOT a good "patched"
  // example: it is numerically below the 4.17.12 bound for CVE-2023-34966 and
  // is an EOL branch without the fix, so reporting that one is correct. The
  // regression being guarded here is narrower -- "Samba smbd 4.9.5" used to
  // yield version "smbd" -> 0.0.0, which is below every bound in the table, so
  // all three samba rules fired on a host that had only Text4Shell already
  // addressed.
  {
    std::vector<ServiceInfo> v;
    v.push_back(fingerprint(445, "Samba smbd 4.18.4", ""));
    auto f = matchCves("10.0.0.1", v);
    // "No samba CVE" would be wrong now: a patched Samba still carries the
    // CVE-2026-4408 audit note, which is a config question and not a version
    // verdict. What must be absent is every versioned samba rule.
    ok("Samba 4.18.4 (patched) -> no versioned samba CVE",
       !hasCve(f, "CVE-2023-34966") && !hasCve(f, "CVE-2022-42889") &&
           !hasCve(f, "CVE-2019-10197"));
  }
  // The version really is being read, and compared numerically: 4.18.4 is
  // above 4.17.12 only as a number, not as a string ("4.18" < "4.17" lexically).
  {
    std::vector<ServiceInfo> v;
    v.push_back(fingerprint(445, "Samba smbd 4.9.5", ""));
    auto f = matchCves("10.0.0.1", v);
    ok("Samba 4.9.5 (EOL) -> CVE-2023-34966 reported",
       hasCve(f, "CVE-2023-34966"));
    ok("Samba 4.9.5 -> Text4Shell NOT reported (4.6.7 < 4.9.5)",
       !hasCve(f, "CVE-2022-42889"));
  }
  // Text4Shell boundary, both sides of 4.6.7.
  {
    std::vector<ServiceInfo> v;
    v.push_back(fingerprint(445, "Samba smbd 4.6.6", ""));
    ok("Samba 4.6.6 -> Text4Shell reported",
       hasCve(matchCves("10.0.0.1", v), "CVE-2022-42889"));
  }
  {
    std::vector<ServiceInfo> v;
    v.push_back(fingerprint(445, "Samba smbd 4.6.7", ""));
    ok("Samba 4.6.7 -> Text4Shell NOT reported",
       !hasCve(matchCves("10.0.0.1", v), "CVE-2022-42889"));
  }
  // An unparseable version must produce no *versioned* finding at all, rather
  // than silently matching every rule. The version-independent audit note is
  // still correct here: the banner says "Samba", so the product is known even
  // though the version is not.
  {
    ServiceInfo s;
    s.port = 445;
    s.name = "smb";
    s.product = "Samba";
    s.version = "smbd";
    s.banner = "Samba smbd";
    s.confidence = "medium";
    std::vector<ServiceInfo> v{s};
    auto f = matchCves("10.0.0.1", v);
    ok("Samba with unreadable version -> no versioned finding",
       !hasCve(f, "CVE-2023-34966") && !hasCve(f, "CVE-2022-42889") &&
           !hasCve(f, "CVE-2019-10197"));
  }
  // A genuinely old Samba is still reported, so the fix did not go too far.
  {
    std::vector<ServiceInfo> v;
    v.push_back(fingerprint(445, "Samba smbd 4.4.5", ""));
    auto f = matchCves("10.0.0.1", v);
    ok("Samba 4.4.5 -> Text4Shell reported", hasCve(f, "CVE-2022-42889"));
    ok("Samba 4.4.5 -> CVE-2019-10197 reported", hasCve(f, "CVE-2019-10197"));
  }

  // ---- version-independent rules
  // These were all unreachable: the matcher insisted on a parsed version
  // before any rule could apply, and these products do not report one.
  {
    std::vector<ServiceInfo> v;
    v.push_back(fingerprint(23, "BusyBox v1.22.1\r\n", ""));
    auto f = matchCves("10.0.0.1", v);
    ok("telnet cleartext rule now fires", hasCve(f, "WEAK-PROTO-0001"));
  }
  {
    std::vector<ServiceInfo> v;
    v.push_back(fingerprint(80, "Server: uhttpd/1.0.0", ""));
    auto f = matchCves("10.0.0.1", v);
    ok("uhttpd unauthenticated rule now fires", hasCve(f, "INFO-UA-0001"));
  }
  {
    std::vector<ServiceInfo> v;
    v.push_back(fingerprint(80, "HTTP/1.1 400 Bad Request\r\nServer: nginx/1.18.0\r\n", ""));
    auto f = matchCves("10.0.0.1", v);
    ok("plain HTTP -> no-transport-security rule fires", hasCve(f, "WEAK-TLS-0001"));
    ok("nginx version banner is disclosed", hasCve(f, "INFO-HDR-0002"));
  }
  // A failed probe is not an observation. Port 8080 with no banner at all is
  // named "http" by the port table, and reporting "no TLS" for a host that
  // never answered would be inventing a finding.
  {
    ServiceInfo s;
    s.port = 8080;
    s.name = "http";
    s.product = "http";
    s.version = "unknown";
    s.banner = "";
    s.confidence = "low";
    std::vector<ServiceInfo> v{s};
    auto f = matchCves("10.0.0.1", v);
    ok("empty banner -> no version-independent findings", f.empty());
  }

  // ==================================================================== OUI
  // The table is scanned first-match-wins, so a repeated prefix made every
  // later row dead. That is not cosmetic: 00:04:20 appeared twice and the row
  // that won labelled an SMC Networks router as vendor Sony, kind tv.
  {
    std::set<std::string> seen;
    int dup = 0;
    for (auto& r : kOui) {
      std::string k = lower(r.prefix);
      if (!seen.insert(k).second) dup++;
    }
    ok("OUI table has no duplicate prefixes", dup == 0);
  }
  {
    std::string kind;
    ouiVendor("00:04:20:11:22:33", &kind);
    ok("OUI 00:04:20 resolves to a real vendor", kind != "unknown" && !kind.empty());
    // classify() short-circuits on the OUI table, so a wrong kind here is
    // what puts a router on the television row in the UI.
    ouiVendor("00:0c:29:aa:bb:cc", &kind);
    ok("OUI 00:0C:29 (VMware) is a pc", kind == "pc");
  }

  // ================================================================ severity
  // Every rule's severity must be one the UI can colour, or a finding renders
  // with the default text colour and reads as a note rather than an alert.
  {
    std::set<std::string> known{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"};
    int bad = 0;
    for (auto& r : kCves)
      if (!known.count(r.severity)) bad++;
    ok("all rule severities are known to the UI", bad == 0);
  }
  // A bound of "0.1" is the sentinel for "no version limit", and only that
  // literal means it. A stray "999" in a row would silently exclude nothing.
  {
    int versionless = 0;
    for (auto& r : kCves)
      if (strcmp(r.maxVer, kAnyVersion) == 0) versionless++;
    ok("version-independent rules are present", versionless >= 8);
  }

  // ============================================================== 2026 rules
  // Built by hand because a real service object is easier to state than a
  // banner for these, and because several of them are Netatalk/AFP, which
  // sends no banner at all -- the product has to come from somewhere else.
  auto svc = [](int port, const char* product, const char* version,
                const char* banner) -> ServiceInfo {
    ServiceInfo s;
    s.port = port;
    s.name = "test";
    s.product = product;
    s.version = version;
    s.banner = banner;
    s.confidence = "high";
    return s;
  };
  auto matchOne = [&](ServiceInfo s) { return matchCves("h", {s}); };

  // OpenSSH 10.4, the first release honouring the auth delay (CVE-2026-60001).
  ok("OpenSSH 10.3p2 -> CVE-2026-60001 reported",
     hasCve(matchOne(svc(22, "OpenSSH", "10.3p2", "SSH-2.0-OpenSSH_10.3p2")),
            "CVE-2026-60001"));
  ok("OpenSSH 10.4 -> CVE-2026-60001 NOT reported",
     !hasCve(matchOne(svc(22, "OpenSSH", "10.4", "SSH-2.0-OpenSSH_10.4")),
             "CVE-2026-60001"));
  ok("OpenSSH 10.4p1 -> CVE-2026-60001 NOT reported",
     !hasCve(matchOne(svc(22, "OpenSSH", "10.4p1", "SSH-2.0-OpenSSH_10.4p1")),
             "CVE-2026-60001"));
  // A 2025 host must not accumulate the 2026 rule either.
  ok("OpenSSH 9.6p1 -> CVE-2026-60001 reported",
     hasCve(matchOne(svc(22, "OpenSSH", "9.6p1", "SSH-2.0-OpenSSH_9.6p1")),
            "CVE-2026-60001"));

  // Netatalk 4.4.3 is the release the 2026 batch fixed in.
  ok("Netatalk 4.4.2 -> CVE-2026-45699 reported",
     hasCve(matchOne(svc(548, "Netatalk", "4.4.2", "Netatalk 4.4.2")),
            "CVE-2026-45699"));
  ok("Netatalk 4.4.3 -> CVE-2026-45699 NOT reported",
     !hasCve(matchOne(svc(548, "Netatalk", "4.4.3", "Netatalk 4.4.3")),
             "CVE-2026-45699"));
  ok("Netatalk 4.4.2 -> CVE-2026-44047 (SQLi) reported",
     hasCve(matchOne(svc(548, "Netatalk", "4.4.2", "Netatalk 4.4.2")),
            "CVE-2026-44047"));
  ok("Netatalk 4.4.2 -> CVE-2026-44066 (OOB read) reported",
     hasCve(matchOne(svc(548, "Netatalk", "4.4.2", "Netatalk 4.4.2")),
            "CVE-2026-44066"));

  // The lower bound is the point of the minVer field. CVE-2026-45699 was
  // introduced in 3.1.19, so a 3.0.x host is below the affected range and must
  // not be reported. Without this, the 4.4.3 upper bound alone would flag it.
  ok("Netatalk 3.0.0 -> CVE-2026-45699 NOT reported (below minVer)",
     !hasCve(matchOne(svc(548, "Netatalk", "3.0.0", "Netatalk 3.0.0")),
             "CVE-2026-45699"));
  ok("Netatalk 3.1.18 -> CVE-2026-45699 NOT reported (just below minVer)",
     !hasCve(matchOne(svc(548, "Netatalk", "3.1.18", "Netatalk 3.1.18")),
             "CVE-2026-45699"));
  ok("Netatalk 3.1.19 -> CVE-2026-45699 reported (at minVer)",
     hasCve(matchOne(svc(548, "Netatalk", "3.1.19", "Netatalk 3.1.19")),
            "CVE-2026-45699"));
  // A different 2026 rule with a wider range still applies to 3.0.x.
  ok("Netatalk 3.0.2 -> CVE-2026-44051 reported (wider minVer)",
     hasCve(matchOne(svc(548, "Netatalk", "3.0.2", "Netatalk 3.0.2")),
            "CVE-2026-44051"));
  ok("Netatalk 3.0.1 -> CVE-2026-44051 NOT reported (below its minVer)",
     !hasCve(matchOne(svc(548, "Netatalk", "3.0.1", "Netatalk 3.0.1")),
             "CVE-2026-44051"));

  // The DHCAST128 row fixes in 4.2.3, not 4.4.3 -- a different fix line.
  ok("Netatalk 4.2.2 -> CVE-2026-44053 reported",
     hasCve(matchOne(svc(548, "Netatalk", "4.2.2", "Netatalk 4.2.2")),
            "CVE-2026-44053"));
  ok("Netatalk 4.2.3 -> CVE-2026-44053 NOT reported",
     !hasCve(matchOne(svc(548, "Netatalk", "4.2.3", "Netatalk 4.2.3")),
             "CVE-2026-44053"));

  // CVE-2026-4408 needs a configuration a banner cannot show, so it is raised
  // as INFO rather than as a confirmed CRITICAL on every Samba host.
  {
    auto f = matchOne(svc(445, "Samba", "4.18.4", "Samba smbd 4.18.4"));
    bool found = false;
    std::string sev;
    for (auto& x : f)
      if (x.cve == "CVE-2026-4408") { found = true; sev = x.severity; }
    ok("Samba -> CVE-2026-4408 audit note raised", found);
    ok("CVE-2026-4408 is INFO, not a confirmed CRITICAL", sev == "INFO");
  }
  // It must still not appear for a service that is not Samba at all.
  {
    ok("non-Samba service -> no CVE-2026-4408",
       !hasCve(matchOne(svc(80, "nginx", "1.18.0", "Server: nginx/1.18.0")),
               "CVE-2026-4408"));
  }

  // Every rule that claims a version window has to have one that can actually
  // be satisfied: a maxVer at or below its minVer matches nothing, which is a
  // silently dead row.
  {
    int broken = 0;
    for (auto& r : kCves) {
      if (!r.minVer[0]) continue;
      bool okp = false;
      if (cmpVersion(r.minVer, r.maxVer, &okp) >= 0 || !okp) broken++;
    }
    ok("no rule has minVer >= maxVer (no dead windows)", broken == 0);
  }

  printf("\n%s (%d failure(s))\n", fails ? "FAILED" : "ALL PASS", fails);
  return fails ? 1 : 0;
}
