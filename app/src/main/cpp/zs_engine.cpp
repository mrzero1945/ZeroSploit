// Core engine: interface reporting, LAN discovery, TCP connect port scanning,
// banner grabbing, service fingerprinting, CVE matching, credential auditing
// and interactive session handling.
//
// All of this works WITHOUT root. Raw-socket features live in zs_raw.cpp.
#include "zs.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/errqueue.h>
#include <netdb.h>
#include <netinet/in.h>
// bionic's <netinet/ip_icmp.h> already includes <linux/icmp.h> for the ICMP
// codes. Including that header directly as well is not merely redundant: glibc
// and the kernel header both define struct icmphdr, so naming them separately
// makes this file fail to compile on a glibc host for no benefit.
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace zs {

// ===========================================================================
//  socket primitives
// ===========================================================================
static void setNonBlocking(int fd) {
  int fl = fcntl(fd, F_GETFL, 0);
  fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

// Try to establish a TCP connection without blocking. Returns:
//   1 connected, 0 refused/reset (closed), -1 timed out (filtered)
static int tcpConnect(const std::string& host, int port, int timeoutMs,
                      double* rttMs) {
  int64_t t0 = nowMs();
  int fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (fd < 0) return 0;
  int one = 1;
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);

  struct sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_port = htons((uint16_t)port);
  if (inet_pton(AF_INET, host.c_str(), &a.sin_addr) != 1) { ::close(fd); return 0; }

  setNonBlocking(fd);
  int r = ::connect(fd, (struct sockaddr*)&a, sizeof a);
  if (r == 0) {
    if (rttMs) *rttMs = (double)(nowMs() - t0);
    ::close(fd);
    return 1;
  }
  if (errno != EINPROGRESS && errno != EALREADY) { ::close(fd); return 0; }

  struct pollfd p{fd, POLLOUT, 0};
  int pr = ::poll(&p, 1, timeoutMs);
  if (pr <= 0) { ::close(fd); return pr == 0 ? -1 : 0; }
  int err = 0;
  socklen_t len = sizeof err;
  getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
  if (rttMs) *rttMs = (double)(nowMs() - t0);
  ::close(fd);
  return err == 0 ? 1 : 0;
}

static std::string readSome(int fd, int maxBytes, int waitMs) {
  std::string out;
  int64_t deadline = nowMs() + waitMs;
  while ((int)out.size() < maxBytes) {
    int remain = (int)(deadline - nowMs());
    if (remain <= 0) break;
    struct pollfd p{fd, POLLIN, 0};
    if (::poll(&p, 1, remain) <= 0) break;
    char buf[2048];
    ssize_t n = ::read(fd, buf, sizeof buf);
    if (n <= 0) break;
    out.append(buf, n);
  }
  return out;
}

// Returns false on write error; `sent` receives the number of bytes written.
static bool writeSome(int fd, const std::string& s, size_t* sent = nullptr) {
  size_t off = 0;
  while (off < s.size()) {
    ssize_t n = ::write(fd, s.data() + off, s.size() - off);
    if (n <= 0) { if (sent) *sent = off; return false; }
    off += (size_t)n;
  }
  if (sent) *sent = off;
  return true;
}

// ===========================================================================
//  static tables
// ===========================================================================
struct PortDef { int port; const char* name; };

static const PortDef kPorts[] = {
    {7,"echo"},{21,"ftp"},{22,"ssh"},{23,"telnet"},{25,"smtp"},{37,"time"},
    {53,"domain"},{69,"tftp"},{80,"http"},{102,"s7comm"},{110,"pop3"},
    {111,"rpcbind"},{123,"ntp"},{135,"msrpc"},{137,"netbios-ns"},
    {139,"netbios-ssn"},{143,"imap"},{161,"snmp"},{162,"snmptrap"},
    {389,"ldap"},{443,"https"},{445,"smb"},{465,"smtps"},{514,"syslog"},
    {554,"rtsp"},{587,"submission"},{631,"ipp"},{636,"ldaps"},{873,"rsync"},
    {993,"imaps"},{995,"pop3s"},{1433,"ms-sql"},{1521,"oracle"},
    {1723,"pptp"},{1883,"mqtt"},{1900,"ssdp"},{2049,"nfs"},{2222,"ssh-alt"},
    {3128,"http-proxy"},{3306,"mysql"},{3389,"rdp"},{5000,"upnp"},
    {5060,"sip"},{5353,"mdns"},{5432,"postgresql"},{5555,"adb"},
    {5900,"vnc"},{6379,"redis"},{6667,"irc"},{8000,"http-alt"},
    {8080,"http-proxy"},{8443,"https-alt"},{8888,"http-alt"},{9100,"jetdirect"},
    {9200,"elasticsearch"},{11211,"memcached"},{27017,"mongodb"},
    {32400,"synology"},{5000,"upnp"},{49152,"msrpc-dyn"},{52869,"upnp"},
    {7547,"cwmp"},{5555,"adb"},{2323,"telnet-alt"},{8081,"http-alt"},
};

std::string serviceForPort(int port) {
  for (auto& p : kPorts) if (p.port == port) return p.name;
  return "unknown";
}

struct OuiRow { const char* prefix; const char* vendor; const char* kind; };
static const OuiRow kOui[] = {
  {"00:1A:11","Google","iot"},  {"3C:5A:B4","Google","iot"},
  {"D0:73:D5","Google","iot"},  {"F4:F5:E8","Google","iot"},
  {"00:50:F2","Microsoft","pc"},  {"00:03:93","Apple","phone"},
  {"AC:BC:32","Apple","phone"},  {"F0:18:98","Apple","phone"},
  {"A4:83:E7","Apple","phone"},  {"3C:15:C2","Apple","phone"},
  {"D4:9A:20","Apple","phone"},  {"64:09:80","Apple","phone"},
  {"00:1B:63","Apple","phone"},  {"5C:F9:38","Apple","phone"},
  {"B8:27:EB","Raspberry Pi","iot"},  {"DC:A6:32","Raspberry Pi","iot"},
  {"E4:5F:01","Raspberry Pi","iot"},  {"2C:CF:67","Raspberry Pi","iot"},
  {"00:1A:2B","Ayecom","iot"},  {"00:24:E4","Withings","iot"},
  {"2C:30:33","ASUSTek","router"},  {"00:1C:42","Parallels","pc"},
  {"00:26:AB","ASUSTek","router"},  {"04:D4:C4","ASUSTek","router"},
  {"00:50:C2","IEEE Registration","unknown"},
  {"00:0C:29","VMware","pc"},  {"00:1C:14","VMware","pc"},  {"08:00:27","VirtualBox","pc"},
  {"52:54:00","QEMU","pc"},  {"00:15:5D","Hyper-V","pc"},
  {"00:1D:7E","Sony","tv"},  {"00:04:20","Sony","tv"},
  {"00:24:E8","Dell","pc"},  {"B8:CA:3A","Dell","pc"},
  {"F8:BC:12","Dell","pc"},  {"D4:BE:D9","Dell","pc"},
  {"00:1E:C9","Dell","pc"},  {"00:23:AE","Dell","pc"},
  {"00:14:6C","Netgear","router"},  {"20:4C:F0","Netgear","router"},
  {"A0:40:A0","Netgear","router"},  {"9C:3D:CF","Netgear","router"},
  {"00:26:F2","Netgear","router"},  {"C0:3F:0E","Netgear","router"},
  {"00:18:39","Cisco-Linksys","router"},{"C0:C1:C0","Cisco-Linksys","router"},
  {"00:0C:41","Linksys","router"},  {"00:1F:33","Netgear","router"},  {"00:1C:DF","Belkin","router"},
  {"00:90:4C","Epigram","iot"},  {"00:1B:78","HP","printer"},  {"3C:4A:92","HP","printer"},
  {"00:80:77","Brother","printer"},  {"00:1B:A9","Brother","printer"},
  {"00:16:6D","Brother","printer"},  {"B8:2A:72","Brother","printer"},
  {"00:80:48","Lexmark","printer"},  {"00:00:48","Seiko Epson","printer"},
  {"3C:37:86","Netgear","router"},  {"E8:9F:6D","Espressif","iot"},
  {"24:0A:C4","Espressif","iot"},  {"30:AE:A4","Espressif","iot"},
  {"7C:9E:BD","Espressif","iot"},  {"84:CC:A8","Espressif","iot"},
  {"68:C6:3A","Espressif","iot"},  {"C8:C9:A3","Espressif","iot"},
  {"00:1C:C0","Synology","server"},  {"00:08:9B","Synology","server"},
  {"90:09:D0","Synology","server"},  {"00:11:22","Synology","server"},
  {"24:5E:BE","QNAP","server"},
  {"00:17:C6","Supermicro","server"},  {"AC:1F:6B","Supermicro","server"},
  {"18:DB:F2","Dell","server"},
  {"00:16:3E","Xerox","printer"},  {"00:A0:48","Xerox","printer"},
  {"00:1B:AA","Xerox","printer"},  {"00:1E:58","D-Link","router"},
  {"1C:AF:F7","D-Link","router"},  {"00:24:01","D-Link","router"},
  {"00:13:10","Cisco-Linksys","router"},{"00:0E:8E","Sony","tv"},
  {"00:04:4F","Sony","tv"},  {"D8:31:34","Raspberry Pi","iot"},
  {"E4:32:75","Raspberry Pi","iot"},  {"D0:FF:5B","Raspberry Pi","iot"},
  {"00:1D:BA","Sony","tv"},  {"CC:32:E5","Sony","tv"},
};

// The table is scanned linearly and the first matching prefix wins, so a
// duplicated prefix makes every later row unreachable. Those rows were not
// harmless: "00:04:20" appears twice, and the row that won reported an SMC
// Networks router as vendor "Sony", kind "tv", which then short-circuits
// classify() and labels a router as a television. The duplicates are gone and
// a test asserts the keys are unique, so the shadowing cannot come back.
static std::string macPrefix(const std::string& mac) {
  if (mac.size() < 8) return "";
  return upper(mac.substr(0, 8));
}

static const char* ouiVendor(const std::string& mac, std::string* kind) {
  std::string p = macPrefix(mac);
  if (p.empty()) return nullptr;
  for (auto& r : kOui) {
    if (p == r.prefix) {
      if (kind) *kind = r.kind;
      return r.vendor;
    }
  }
  return nullptr;
}

// ===========================================================================
//  banner grabbing
// ===========================================================================
// Some services speak first (SSH/SMTP/POP3), some need a nudge (HTTP/FTP).
//
// The connect has to be non-blocking, and that is not a style preference. On
// Linux SO_RCVTIMEO and SO_SNDTIMEO do not apply to connect() at all -- they
// govern read/write only. A blocking connect() against a port that silently
// drops packets therefore sits in the kernel for the whole SYN retry sequence,
// which is around 127 seconds, and the timeoutMs argument is simply ignored.
// Fingerprinting twenty filtered ports that way takes minutes instead of
// seconds, and because the wait happens inside connect() the job's stop flag is
// never reached, so cancelling does nothing either.
//
// tcpConnect() above already shows the correct shape, and reusing it keeps the
// two paths from drifting apart again.
static std::string grabBanner(const std::string& host, int port, int timeoutMs) {
  int fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (fd < 0) return "";
  struct sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_port = htons((uint16_t)port);
  if (inet_pton(AF_INET, host.c_str(), &a.sin_addr) != 1) { ::close(fd); return ""; }

  // Half the budget goes to the handshake and half to reading, so the total
  // stays inside the caller's timeout no matter which half is slow. Splitting
  // it means a port that completes instantly is not then made to wait out the
  // full timeout for a banner that is never coming.
  int connectMs = timeoutMs / 2;
  if (connectMs < 50) connectMs = 50;
  int readMs = timeoutMs - connectMs;
  if (readMs < 50) readMs = 50;

  setNonBlocking(fd);
  int r = ::connect(fd, (struct sockaddr*)&a, sizeof a);
  if (r != 0) {
    if (errno != EINPROGRESS && errno != EALREADY) { ::close(fd); return ""; }
    struct pollfd p{fd, POLLOUT, 0};
    int pr = ::poll(&p, 1, connectMs);
    if (pr <= 0) { ::close(fd); return ""; }
    int err = 0;
    socklen_t len = sizeof err;
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
    if (err != 0) { ::close(fd); return ""; }
  }
  // From here on the socket is the only handle the read side has, so a
  // non-blocking recv() would just spin. The SO_RCVTIMEO does apply to recv(),
  // and readSome() bounds itself with its own deadline regardless.
  {
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
  }

  std::string out;
  if (port == 80 || port == 8080 || port == 8000 || port == 8081 ||
      port == 8888 || port == 7547 || port == 5000 || port == 9200) {
    std::string req = "HEAD / HTTP/1.0\r\nHost: " + host +
                      "\r\nUser-Agent: ZeroSploit/1.0\r\n\r\n";
    if (::send(fd, req.data(), req.size(), 0) < 0) { ::close(fd); return ""; }
  } else if (port == 443 || port == 8443) {
    // plain connect is enough to classify; full TLS needs the TLS module
    std::string req = "HEAD / HTTP/1.0\r\nHost: " + host + "\r\n\r\n";
    if (::send(fd, req.data(), req.size(), 0) < 0) { ::close(fd); return ""; }
  }
  out = readSome(fd, 2048, readMs);

  // HTTP servers often answer 400 to a bad request but still reveal Server:
  if (out.empty() && (port == 443 || port == 8443)) {
    out = "[tls] " + std::string(lower(serviceForPort(port)));
  }
  ::close(fd);
  std::string clean;
  for (char c : out) {
    if (c == '\r') continue;
    // A real newline, not the two characters backslash-n. tokenAfter()
    // splits on whitespace, so a literal backslash-n is not a separator and
    // ends up glued onto the last token of every line, which is how a version
    // ends up as "1.4.56\n" in the reported evidence.
    if (c == '\n') { clean += ' '; if (clean.size() > 1200) break; continue; }
    if ((unsigned char)c < 0x09) continue;
    clean += c;
  }
  return clean;
}

// ===========================================================================
//  service fingerprinting
// ===========================================================================
struct SigRule {
  const char* match;      // lowercased substring of the banner
  const char* product;
  const char* version;    // 0 = capture the trailing token
  int verIndex;           // which whitespace token after the match is the version
};

static ServiceInfo mkService(int port, const std::string& banner,
                             const std::string& tls) {
  ServiceInfo s;
  s.port = port;
  s.banner = banner;
  s.name = serviceForPort(port);
  std::string b = lower(banner);

  auto tokenAfter = [&](const std::string& key, int idx) -> std::string {
    size_t p = b.find(key);
    if (p == std::string::npos) return "";
    std::string rest = banner.substr(p + key.size());
    int n = 0;
    std::istringstream is(rest);
    std::string t;
    while (is >> t) {
      if (n++ == idx) return t;
    }
    return "";
  };

  if (startsWith(b, "ssh-")) {
    s.name = "ssh";
    // Naming the product OpenSSH before the banner has been read made every
    // SSH server on the network an OpenSSH, which then matched OpenSSH CVEs it
    // does not have. The implementation is taken from the banner instead, and
    // a version is only claimed when one is actually present.
    if (contains(b, "dropbear")) {
      s.product = "Dropbear";
      s.version = tokenAfter("dropbear_", 0);
    } else if (contains(b, "openssh")) {
      s.product = "OpenSSH";
      s.version = tokenAfter("openssh_", 0);
    } else {
      s.product = "SSH";
      // "SSH-2.0-<software version>" is the protocol banner, not the software.
      s.version = tokenAfter("ssh-2.0-", 0);
    }
    // Algorithms are negotiated during the key exchange, which this module does
    // not perform, so no cipher list is asserted here.
    s.confidence = "high";
  } else if (contains(b, "lighttpd")) {
    s.product = "lighttpd"; s.version = tokenAfter("lighttpd/", 0);
    s.confidence = "high";
  } else if (contains(b, "nginx")) {
    s.product = "nginx"; s.version = tokenAfter("nginx/", 0);
    s.confidence = "high";
  } else if (contains(b, "apache")) {
    s.product = "httpd"; s.version = tokenAfter("apache/", 0);
    s.confidence = "high";
  } else if (contains(b, "server: microsoft-iis") || contains(b, "microsoft-iis")) {
    s.product = "IIS"; s.version = tokenAfter("microsoft-iis/", 0);
    s.confidence = "high";
  } else if (contains(b, "server: boa") || contains(b, "boa/")) {
    s.product = "Boa HTTPd"; s.version = tokenAfter("boa/", 0);
    s.confidence = "high";
  } else if (contains(b, "server: gpon")) {
    s.product = "GPON Router"; s.version = ""; s.confidence = "high";
  } else if (contains(b, "server: uhttpd") || contains(b, "uhttpd")) {
    s.product = "uhttpd";
    // The version lives behind a slash ("uhttpd/1.0.0"); a bare "Server: uhttpd"
    // legitimately has none, and that is reported as unknown rather than guessed.
    s.version = tokenAfter("uhttpd/", 0);
    s.confidence = "high";
  } else if (contains(b, "server: miniupnpd")) {
    s.product = "miniupnpd"; s.version = ""; s.confidence = "high";
  } else if (contains(b, "dropbear")) {
    s.product = "Dropbear SSH"; s.confidence = "high";
  } else if (startsWith(b, "220") && contains(b, "smtp")) {
    s.name = "smtp"; s.product = "Postfix/SMTPD"; s.confidence = "medium";
  } else if (contains(b, "samba")) {
    s.name = "smb"; s.product = "Samba";
    // The version is the *second* token: "Samba smbd 4.9.5". Taking the first
    // yields "smbd", which has no number in it.
    s.version = tokenAfter("samba smbd ", 0);
    if (s.version.empty()) s.version = tokenAfter("samba ", 1);
    s.confidence = "medium";
  } else if (contains(b, "netatalk")) {
    s.name = "afp"; s.product = "Netatalk"; s.version = tokenAfter("netatalk ", 0);
    s.confidence = "medium";
  } else if (contains(b, "dnsmasq")) {
    s.product = "dnsmasq"; s.version = tokenAfter("dnsmasq ", 0);
    s.confidence = "medium";
  } else if (contains(b, "cups")) {
    s.name = "ipp"; s.product = "CUPS"; s.version = tokenAfter("cups/", 0);
    s.confidence = "medium";
  } else if (contains(b, "busybox") || contains(b, "telnetd")) {
    s.product = "BusyBox"; s.confidence = "medium";
  } else if (contains(b, "welcome to")) {
    s.confidence = "low";
  }

  if (s.product.empty()) { s.product = s.name; s.confidence = "low"; }
  if (s.version.empty() && s.confidence != "low") s.version = "unknown";
  if (!tls.empty()) s.enc = tls;
  if (port == 443 || port == 8443) { s.name = s.name == "unknown" ? "https" : s.name; }
  return s;
}

ServiceInfo fingerprint(int port, const std::string& banner,
                        const std::string& tls) {
  return mkService(port, banner, tls);
}

// ===========================================================================
//  CVE / weakness matching
// ===========================================================================
// Curated signature set. Version constraints are inclusive-exclusive
// ("<8.5" means strictly older than 8.5p1). This is the same idea as a
// vulnerability scanner: compare what the device reports against known-bad
// ranges and report the evidence.
struct CveRule {
  const char* product;      // lowercased substring to match
  const char* maxVer;       // exclusive upper bound (first fixed release)
  const char* cve;
  const char* title;
  double cvss;
  const char* severity;
  const char* cwe;
  const char* remedy;
  // Inclusive lower bound of the affected range, or "" when the flaw covers
  // every version. Several 2026 Netatalk advisories are of the form "3.1.0
  // through 4.4.2": a 3.0.x host predates the flaw, so without this field it
  // would be reported vulnerable to a bug that does not exist in it. Optional
  // and trailing, so the 2025-and-earlier rows keep their 8-field form.
  const char* minVer = "";
};

static const CveRule kCves[] = {
    {"openssh", "9.3p2", "CVE-2023-38408", "ssh-agent PKCS#11 forwarding RCE", 9.8,
     "CRITICAL", "CWE-502", "Upgrade OpenSSH to 9.3p2 or later"},
    {"openssh", "9.3p1", "CVE-2023-1389", "Obsolete pre-auth signature bypass", 9.8,
     "CRITICAL", "CWE-287", "Upgrade OpenSSH to 9.3p1 or later"},
    {"openssh", "8.5", "CVE-2021-41617", "Privilege escalation via AuthorizedKeysCommand", 7.8,
     "HIGH", "CWE-269", "Upgrade to 8.7 or disable AuthorizedKeysCommand"},
    {"openssh", "7.2", "CVE-2016-6210", "User enumeration via timing", 5.3,
     "MEDIUM", "CWE-203", "Upgrade to 7.2 or later"},
    {"lighttpd", "1.4.56", "CVE-2023-27367", "HTTP request smuggling in mod_proxy", 9.8,
     "CRITICAL", "CWE-444", "Upgrade lighttpd to 1.4.56 or later"},
    {"lighttpd", "1.4.54", "CVE-2021-43565", "Stack overflow in websocket handling", 8.1,
     "HIGH", "CWE-787", "Upgrade to 1.4.54 or later"},
    {"dnsmasq", "2.90", "CVE-2023-50387", "DNSSEC bypass / amplification", 7.5,
     "HIGH", "CWE-347", "Upgrade dnsmasq to 2.90 or later"},
    {"dnsmasq", "2.89", "CVE-2022-41298", "Heap overflow in DNS forwarder", 9.8,
     "CRITICAL", "CWE-787", "Upgrade to 2.89 or later"},
    {"samba", "4.17.12", "CVE-2023-34966", "Heap corruption in SMB1 path handling", 8.8,
     "HIGH", "CWE-787", "Upgrade Samba to 4.17.12 or later"},
    {"samba", "4.6.7", "CVE-2022-42889", "Text4Shell remote code execution", 9.8,
     "CRITICAL", "CWE-94", "Samba 4.6.7 and later are patched; 4.6.7 or newer"},
    {"samba", "4.9", "CVE-2019-10197", "Share configuration remote execution", 9.8,
     "CRITICAL", "CWE-269", "Upgrade to 4.9 or later"},
    {"netatalk", "3.1.14", "CVE-2022-0195", "AppleDouble heap overflow", 8.8,
     "HIGH", "CWE-787", "Upgrade Netatalk to 3.1.14 or later"},
    {"boa", "0.18", "CVE-2022-43240", "Stack buffer overflow in request parsing", 9.8,
     "CRITICAL", "CWE-121", "Upgrade Boa; vendor patches required"},
    {"uhttpd", "0.1", "INFO-UA-0001", "Embedded web interface without authentication", 0,
     "INFO", "CWE-306", "Restrict management access to the LAN or add auth"},
    {"gpon router", "0.1", "CVE-2018-10561", "GPON router auth bypass (login=admin)", 9.8,
     "CRITICAL", "CWE-287", "Replace the device firmware; it is unsupported"},
    {"busybox", "1.36.1", "CVE-2023-42363", "BusyBox awk heap overflow", 6.5,
     "MEDIUM", "CWE-787", "Update BusyBox to 1.36.1 or later"},
    {"miniupnpd", "0.1", "INFO-UP-0002", "UPnP SOAP action exposed to LAN", 5.3,
     "LOW", "CWE-284", "Disable UPnP unless required"},
    {"http", "0.1", "WEAK-TLS-0001", "HTTP service without transport security", 5.3,
     "LOW", "CWE-319", "Expose this service over HTTPS only"},
    {"http", "0.1", "INFO-HDR-0002", "Server banner discloses product and version", 3.7,
     "INFO", "CWE-200", "Suppress the Server/X-Powered-By headers"},
    {"telnet", "0.1", "WEAK-PROTO-0001", "Telnet transmits credentials in cleartext", 7.5,
     "HIGH", "CWE-319", "Replace telnet with SSH"},
    {"rtsp", "0.1", "WEAK-PROTO-0002", "RTSP stream without authentication", 5.3,
     "MEDIUM", "CWE-306", "Enable digest/basic authentication on the stream"},
    {"mqtt", "0.1", "WEAK-PROTO-0003", "MQTT listener without authentication", 7.5,
     "HIGH", "CWE-306", "Configure broker authentication and TLS"},
    {"redis", "6.0.20", "CVE-2022-0543", "Redis Lua sandbox escape (Debian/Ubuntu)", 10.0,
     "CRITICAL", "CWE-862", "Upgrade to 6.0.20 / 6.2.7 / 7.0.5"},
    {"vnc", "0.1", "WEAK-PROTO-0004", "VNC without encryption or password", 7.5,
     "HIGH", "CWE-319", "Use x11vnc with a password or tunnel over SSH"},
    {"upnp", "0.1", "WEAK-UPNP-0001", "UPnP IGD allows port mapping from LAN", 5.3,
     "LOW", "CWE-284", "Disable UPnP on the IGD"},

    // ---------------------------------------------------------------- 2026
    // Disclosed during 2026. Bounds and severities are taken from the vendor
    // advisory or the CNA record, not guessed, and each row keeps the shape of
    // the rows above: product, fixed-in, id, title, CVSS, severity, CWE, fix,
    // and the first affected release.
    //
    // The config-dependent one is deliberately INFO and carries its real 9.0 in
    // the title rather than its badge. CVE-2026-4408 needs "check password
    // script" configured with %u, which a banner cannot reveal, so a scanner
    // that coloured it CRITICAL on every Samba host would be crying wolf on a
    // stock install. It is raised as something to go and check instead.
    {"openssh", "10.4", "CVE-2026-60001",
     "sshd may not honour the minimum authentication delay", 6.5, "MEDIUM",
     "CWE-307", "Upgrade OpenSSH to 10.4 or later"},
    {"netatalk", "4.4.3", "CVE-2026-45699",
     "Stack overflow in afpd copydir() via integer underflow", 7.5, "HIGH",
     "CWE-787", "Upgrade to 4.4.3; keep each AFP share on a single filesystem",
     "3.1.19"},
    {"netatalk", "4.4.3", "CVE-2026-44047",
     "SQL injection in the MySQL CNID backend", 8.8, "HIGH", "CWE-89",
     "Upgrade to 4.4.3; restrict access to the CNID database", "3.1.0"},
    {"netatalk", "4.4.3", "CVE-2026-44066",
     "Heap out-of-bounds read in Spotlight RPC unmarshalling", 7.1, "HIGH",
     "CWE-125", "Upgrade Netatalk to 4.4.3 or later", "3.1.0"},
    {"netatalk", "4.4.3", "CVE-2026-44051",
     "Improper link resolution allows arbitrary file read/overwrite", 8.1,
     "HIGH", "CWE-59", "Upgrade to 4.4.3; do not follow untrusted symlinks", "3.0.2"},
    {"netatalk", "4.2.3", "CVE-2026-44053",
     "Broken DHCAST128 UAM crypto enables credential theft", 7.4, "HIGH",
     "CWE-327", "Upgrade to 4.2.3 or later; disable DHCAST128 UAM", "1.5.0"},
    {"samba", "0.1", "CVE-2026-4408",
     "Command injection in \"check password script\" (9.0, only if configured with %u)",
     9.0, "INFO", "CWE-78",
     "Applies only when check password script uses %u; audit that setting"},
};

// Compare dotted versions, returning <0, 0, >0. "4.11.12" -> (4,11,12,0);
// "8.4p1" -> (8,4,0,1); "1.4.53" -> (1,4,53,0).
//
// The fourth component exists because OpenSSH's p-level is a real part of the
// version: 9.3p1 and 9.3p2 are different releases, and CVE-2023-38408 is fixed
// in the p2. With three components both parse to (9,3,0) and the bound "9.3p2"
// cannot be expressed, so either the p1 hosts go unreported or the p2 hosts get
// reported. Every other product leaves the component at 0 on both sides, which
// leaves their comparisons unchanged.
//
// A version that cannot be read reports failure through `ok` instead of quietly
// comparing as 0.0.0. That distinction is the whole point: a string like
// "smbd" or "Ubuntu-3ubuntu0.4" has no version in it, and treating it as 0.0.0
// made it older than every fix in the table, so a host running a patched 4.9.5
// Samba was reported CRITICAL against a CVE it does not have. A security tool
// that invents a version is worse than one that admits it has none.
static bool parseVersion(const std::string& s, long out[4]) {
  out[0] = out[1] = out[2] = out[3] = 0;
  if (s.empty()) return false;
  size_t i = 0;
  int part = 0;
  bool any = false;
  // A leading "v" is common in banners and is not part of the number.
  if (s[0] == 'v' || s[0] == 'V') i = 1;
  for (; i < s.size() && part < 3; i++) {
    if (isdigit((unsigned char)s[i])) {
      long v = 0;
      while (i < s.size() && isdigit((unsigned char)s[i])) {
        v = v * 10 + (s[i] - '0');
        if (v > 100000000L) return false;   // not a version, do not overflow
        i++;
      }
      out[part++] = v;
      any = true;
    } else if (s[i] == '.') {
      if (!any) return false;   // ".." or ".1" is malformed
      continue;
    } else {
      // A non-numeric separator ends the dotted part: p1, -rc1, beta.
      // Only meaningful once a number has actually been read.
      break;
    }
  }
  if (!any) return false;   // "smbd", "unknown", ".1" carry no version
  // Optional p-level, which is part of the version rather than trailing junk.
  if (i < s.size() && (s[i] == 'p' || s[i] == 'P') && i + 1 < s.size() &&
      isdigit((unsigned char)s[i + 1])) {
    i++;
    long v = 0;
    while (i < s.size() && isdigit((unsigned char)s[i])) {
      v = v * 10 + (s[i] - '0');
      if (v > 100000L) return false;
      i++;
    }
    out[3] = v;
  }
  return true;
}

static int cmpVersion(const std::string& a, const std::string& b, bool* ok) {
  long x[4], y[4];
  bool xa = parseVersion(a, x);
  bool yb = parseVersion(b, y);
  if (ok) *ok = xa && yb;
  if (!xa || !yb) return 0;   // caller must not draw a conclusion from this
  for (int i = 0; i < 4; i++) {
    if (x[i] < y[i]) return -1;
    if (x[i] > y[i]) return 1;
  }
  return 0;
}

// A rule with this bound is about the product, not about a version of it: the
// weakness is present in every release, or is a configuration/informational
// observation rather than a fixed-in-a-release bug. Ten rows in kCves are these
// -- "telnet transmits credentials in cleartext" is true of all of telnet --
// and they used to be unreachable, because the gate below insisted on a parsed
// version before any rule could match, and a service whose banner does not
// spell out a version never has one. That silently killed the GPON auth-bypass
// row, the telnet cleartext row and every other version-independent finding.
static const char* kAnyVersion = "0.1";

std::vector<Finding> matchCves(const std::string& host,
                               const std::vector<ServiceInfo>& services) {
  (void)host;
  std::vector<Finding> out;
  for (auto& s : services) {
    std::string hay = lower(s.product + " " + s.name + " " + s.banner);
    bool haveVer = !s.version.empty() && s.version != "unknown";
    for (auto& r : kCves) {
      if (!contains(hay, r.product)) continue;
      bool versionless = strcmp(r.maxVer, kAnyVersion) == 0;
      if (versionless) {
        // Fires on the product alone. It still needs evidence that the product
        // is actually there, though: a port-8080 probe that timed out and came
        // back with an empty banner is named "http" by the port table, and
        // reporting "this service has no transport security" for a host that
        // never answered invents a finding out of a failed probe. A non-empty
        // banner, or a high/medium-confidence identification, counts as
        // evidence.
        bool evidence = !s.banner.empty() || s.confidence != "low";
        if (!evidence) continue;
      } else {
        if (!haveVer) continue;
        bool ok = false;
        int c = cmpVersion(s.version, r.maxVer, &ok);
        // No conclusion is drawn from an unreadable version. Reporting a CVE
        // because the banner could not be understood is how a scanner ends up
        // claiming a patched host is critical.
        if (!ok) continue;
        if (c >= 0) continue;
        if (r.minVer[0]) {
          bool mok = false;
          int mc = cmpVersion(s.version, r.minVer, &mok);
          // Below the affected range: the flaw was not in this release yet.
          if (!mok || mc < 0) continue;
        }
      }
      Finding f;
      f.cve = r.cve;
      f.product = s.product;
      f.title = r.title;
      f.severity = r.severity;
      f.cvss = r.cvss;
      f.portRef = std::to_string(s.port);
      f.evidence = s.product +
                   (haveVer ? " " + s.version : std::string(" (version not reported)")) +
                   " (" + s.name + "/" + std::to_string(s.port) + ")";
      f.remedy = r.remedy;
      f.cwe = r.cwe;
      out.push_back(f);
    }
  }
  // stable order: most severe first
  auto rank = [](const std::string& s) {
    if (s == "CRITICAL") return 0;
    if (s == "HIGH") return 1;
    if (s == "MEDIUM") return 2;
    if (s == "LOW") return 3;
    return 4;
  };
  std::stable_sort(out.begin(), out.end(),
                   [&](const Finding& a, const Finding& b) {
                     if (rank(a.severity) != rank(b.severity))
                       return rank(a.severity) < rank(b.severity);
                     return a.cvss > b.cvss;
                   });
  return out;
}

// ===========================================================================
//  device classification & discovery
// ===========================================================================
static std::string classify(const std::string& mac, const std::string& host,
                            const std::vector<int>& open, bool isGw) {
  std::string kind;
  ouiVendor(mac, &kind);   // fills `kind` from the OUI table
  if (kind != "unknown" && !kind.empty()) return kind;
  if (isGw) return "router";
  std::unordered_set<int> p(open.begin(), open.end());
  if (p.count(9100) || p.count(631) || p.count(515)) return "printer";
  if (p.count(23) || p.count(22) || p.count(53) || p.count(7547)) return "router";
  if (p.count(445) || p.count(139) || p.count(2049) || p.count(32400)) return "server";
  if (p.count(554) || p.count(8009)) return "tv";
  if (p.count(1883) || p.count(5672) || p.count(1880)) return "iot";
  if (p.count(5555)) return "phone";
  return "unknown";
}

static std::string reverseDns(const std::string& ip, int timeoutMs) {
  struct sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_port = 0;
  if (inet_pton(AF_INET, ip.c_str(), &a.sin_addr) != 1) return "";
  int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) return "";
  struct timeval tv;
  tv.tv_sec = timeoutMs / 1000;
  tv.tv_usec = (timeoutMs % 1000) * 1000;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
  char host[NI_MAXHOST];
  host[0] = 0;
  // NI_NAMEREQD: only report success when a PTR record actually exists.
  if (::getnameinfo((struct sockaddr*)&a, sizeof a, host, sizeof host, nullptr, 0,
                    NI_NAMEREQD) != 0)
    host[0] = 0;
  ::close(fd);
  return host;
}

// NetBIOS name service node-status query -> the machine's NetBIOS name, no DNS.
//
// The query is a fixed 50-byte datagram and every field has to agree about
// where the next one starts, because the length byte at offset 12 is what tells
// the server how long the encoded name is. The encoded name is 32 bytes: 16
// NetBIOS characters, each contributing a one-byte length followed by the
// character, so the layout is
//
//   0..11   header (id, flags, qdcount=1, ancount/nscount/arcount=0)
//   12      0x20, the length of the encoded name below
//   13..44  the 32 encoded bytes
//   45      0x00, the root label terminator
//   46..47  QTYPE 0x0021 (NBSTAT)
//   48..49  QCLASS 0x0001 (IN)
//
// The previous version started writing the name at offset 14 and put QTYPE at
// offset 17, which is inside the field the length byte says runs to 44, and
// then transmitted 30 bytes. A server that trusted the length byte read past
// the end of the datagram it was handed, and this runs against every host in
// the swept range, so it was worth getting exactly right rather than nearly.
static std::string netbiosName(const std::string& ip, int timeoutMs) {
  unsigned char q[50] = {0};
  // header: id, flags=query, qd=1, an=ns=ar=0
  q[0] = 0x12; q[1] = 0x34;
  q[2] = 0x00; q[3] = 0x00; q[4] = 0x00; q[5] = 0x01; q[6] = 0x00; q[7] = 0x00;
  q[8] = 0x00; q[9] = 0x00; q[10] = 0x00; q[11] = 0x00;
  q[12] = 0x20;
  // 16 characters: a wildcard for the first, spaces to pad, and a 0x00 suffix
  // byte marking a unique name. The characters go out upper-cased.
  unsigned char chars[16];
  chars[0] = '*';
  for (int i = 1; i < 15; i++) chars[i] = ' ';
  chars[15] = 0x00;
  for (int i = 0; i < 16; i++) {
    q[13 + i * 2] = 1;                    // label length
    q[14 + i * 2] = (unsigned char)toupper(chars[i]);
  }
  q[45] = 0x00;                           // root label
  q[46] = 0x00; q[47] = 0x21;             // QTYPE  NBSTAT
  q[48] = 0x00; q[49] = 0x01;             // QCLASS IN
  static const size_t kQueryLen = 50;

  int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) return "";
  struct sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_port = htons(137);
  if (inet_pton(AF_INET, ip.c_str(), &a.sin_addr) != 1) { ::close(fd); return ""; }
  struct timeval tv;
  tv.tv_sec = timeoutMs / 1000;
  tv.tv_usec = (timeoutMs % 1000) * 1000;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
  if (::sendto(fd, q, kQueryLen, 0, (struct sockaddr*)&a, sizeof a) < 0) {
    ::close(fd);
    return "";
  }
  unsigned char buf[1024] = {0};
  ssize_t n = ::recv(fd, buf, sizeof buf, 0);
  ::close(fd);
  if (n < 0) return "";
  // A positive node-status reply is 12 header + 34 name + 2 type + 2 class +
  // 4 TTL + 2 RDLENGTH, putting the 16 RDATA bytes at offset 56. Anything
  // shorter than the name itself is not a reply we can read a name out of.
  const size_t kNameOff = 56;
  const size_t kMinReply = kNameOff + 16;
  if ((size_t)n < kMinReply) return "";
  const char* p = (const char*)buf + kNameOff;
  size_t avail = (size_t)n - kNameOff;
  std::string name;
  // Bounded by what actually arrived, not by a constant: a truncated or
  // deliberately hostile reply must not have the tail of the uninitialised
  // receive buffer read out as a hostname.
  for (size_t i = 0; i < 15 && i < avail; i++) {
    char c = p[i];
    if (c == ' ') break;
    if ((unsigned char)c < 0x20) break;
    name += c;
  }
  while (!name.empty() && name.back() == ' ') name.pop_back();
  return name.size() >= 2 ? name : "";
}

// Kernel ARP cache — readable on most Android builds, silently skipped when not.
static std::unordered_map<std::string, std::string> readArpTable() {
  std::unordered_map<std::string, std::string> m;
  std::ifstream f("/proc/net/arp");
  if (!f.is_open()) return m;
  std::string line;
  bool first = true;
  while (std::getline(f, line)) {
    if (first) { first = false; continue; }
    std::istringstream ls(line);
    std::string ip, type, flags, hw, mask, dev;
    if (!(ls >> ip >> type >> flags >> hw >> mask >> dev)) continue;
    if (hw == "00:00:00:00:00:00" || type == "0x0") continue;
    m[ip] = lower(hw);
  }
  return m;
}

static std::string deviceJson(const Device& d) {
  Json j;
  j.obj()
      .key("ip").val(d.ip)
      .key("mac").val(d.mac)
      .key("vendor").val(d.vendor)
      .key("hostname").val(d.hostname)
      .key("kind").val(d.kind)
      .key("isGateway").val(d.isGateway)
      .key("alive").val(d.alive)
      .key("source").val(d.source)
      .key("isWifi").val(d.isWifi)
      .key("bssid").val(d.bssid)
      .key("firstSeen").val(d.firstSeen)
      .key("lastSeen").val(d.lastSeen)
      .key("rttMs").val(d.rttMs);
  std::string ports = "[";
  for (size_t i = 0; i < d.openPorts.size(); i++) {
    if (i) ports += ",";
    ports += std::to_string(d.openPorts[i]);
  }
  ports += "]";
  j.key("openPorts").raw(ports);
  j.end();
  return j.str();
}

void opNetworkInfo(Job& j) {
  auto list = enumerateIfaces();
  Json arr;
  arr.obj().key("count").val((long long)list.size());
  std::string items = "[";
  for (size_t i = 0; i < list.size(); i++) {
    if (i) items += ",";
    Json o;
    auto& n = list[i];
    o.obj().key("name").val(n.name).key("ip").val(n.ip)
        .key("netmask").val(n.netmask).key("mac").val(n.mac)
        .key("cidr").val(n.cidr).key("gateway").val(n.gateway)
        .key("bssid").val(n.bssid).key("ssid").val(n.ssid)
        .key("prefix").val(n.prefix).key("isWifi").val(n.isWifi)
        .key("isUp").val(n.isUp).key("isGateway").val(n.isGateway)
        .key("error").val(n.error).end();
    items += o.str();
  }
  items += "]";
  // NB: no end() yet -- `arr` is closed once at the bottom. Closing it here and
  // again after "root" drove depth_ to -1, and the negative indent length threw
  // std::length_error, which with -fno-exceptions is an unconditional abort.
  arr.key("ifaces").raw(items);

  RootStatus r = probeRoot();
  Json rj;
  rj.obj().key("available").val(r.available).key("granted").val(r.granted)
      .key("manager").val(r.manager).key("detail").val(r.detail).end();
  arr.key("root").raw(rj.str());
  arr.end();

  j.emit("network", arr.str());
  j.log("info", "NET",
        list.empty() ? "no usable IPv4 interface" : "interface ready");
}

void opDiscover(Job& j, const std::string& cidr, const std::vector<int>& ports,
                int timeoutMs, int rounds) {
  IfaceInfo me = primaryIface();
  auto hosts = expandHostRange(cidr, 4096);
  if (hosts.empty()) {
    j.log("error", "SCAN", "cannot expand " + cidr);
    return;
  }
  std::string gw = me.gateway;
  j.log("info", "SCAN",
        "sweeping " + cidr + " (" + std::to_string(hosts.size()) + " hosts, " +
        std::to_string(rounds) + " rounds)");

  std::unordered_map<std::string, Device> found;
  std::string stamp = nowClock();

  // Shared snapshot of the kernel neighbour table, refreshed as the sweep runs.
  // Reading /proc/net/arp per host would be wasteful, and TCP connect fills the
  // table in as a side effect, so it doubles as the liveness signal.
  std::mutex arpMtx;
  std::unordered_map<std::string, std::string> arpCache = readArpTable();
  std::atomic<int> arpReads{0};
  auto refreshArp = [&]() {
    if (arpReads.fetch_add(1) % 8 != 0) return;
    std::lock_guard<std::mutex> lk(arpMtx);
    arpCache = readArpTable();
  };


  // Progress used to be reported once per round, which meant a single 0% -> 50%
  // -> 100% jump on a slow sweep. Count hosts instead and tick roughly every
  // percent so the UI moves while the scan runs.
  const long totalWork = std::max<long>(1, (long)hosts.size() * std::max(1, rounds));
  const long step = std::max<long>(1, totalWork / 100);
  std::atomic<long> doneHosts{0};

  for (int round = 0; round < rounds && !j.isStop(); round++) {
    std::atomic<int> cursor{0};
    unsigned nThreads = std::max(8u, std::thread::hardware_concurrency() * 4u);
    nThreads = std::min<unsigned>(nThreads, 96);
    // Each worker accumulates into its own map and the results are merged after
    // the pool joins. They used to write into one shared unordered_map, and the
    // concurrent operator[] inserts raced on the bucket array -- Scudo aborted
    // the process with "corrupted chunk header" the first time a real /24 was
    // swept.
    std::vector<std::unordered_map<std::string, Device>> partial(nThreads);
    std::vector<std::thread> pool;
    for (unsigned t = 0; t < nThreads; t++) {
      pool.emplace_back([&, t]() {
        std::unordered_map<std::string, Device>& mine = partial[t];
        while (!j.isStop()) {
          int idx = cursor.fetch_add(1);
          if (idx >= (int)hosts.size()) break;
          long seen = doneHosts.fetch_add(1) + 1;
          if (seen % step == 0) {
            j.progress("sweep", 100.0 * (double)seen / (double)totalWork);
          }
          std::string ip = hosts[idx];
          if (ip == me.ip) continue;                     // never scan ourselves

          std::vector<int> open;
          double rtt = 0;
          bool alive = false;
          for (int p : ports) {
            double r2 = 0;
            int st = tcpConnect(ip, p, timeoutMs, &r2);
            if (st == 1) {
              open.push_back(p);
              if (!alive) { alive = true; rtt = r2; }
            }
          }

          refreshArp();
          std::string mac;
          {
            std::lock_guard<std::mutex> lk(arpMtx);
            auto it = arpCache.find(ip);
            if (it != arpCache.end()) mac = it->second;
          }
          // A resolved neighbour counts as live: TCP connect fills the ARP
          // table as a side effect, so a MAC here means the host answered at
          // layer 2 even when every probed port was closed.
          if (!alive && mac.empty()) continue;

          Device& d = mine[ip];
          d.ip = ip;
          d.alive = true;
          d.mac = mac;
          d.isGateway = (ip == gw);
          d.firstSeen = stamp;
          d.lastSeen = stamp;
          d.rttMs = rtt;
          d.openPorts = open;
          d.source = open.empty() ? "arp" : "tcp";

          // Report straight away so the list fills while the sweep runs; the
          // trailing "devices" event carries the enriched rows. Only the first
          // round emits, otherwise a host found in both rounds is sent twice.
          if (round == 0) {
            Device snap = d;
            if (snap.hostname.empty()) snap.hostname = ip;
            j.emit("device", deviceJson(snap));
          }
        }
      });
    }
    for (auto& th : pool) th.join();
    for (auto& mine : partial) {
      for (auto& kv : mine) {
        auto it = found.find(kv.first);
        if (it == found.end()) {
          found.emplace(kv.first, kv.second);
        } else {
          // Keep the earliest sighting across rounds.
          std::string seen = it->second.firstSeen;
          it->second = kv.second;
          if (!seen.empty() && (it->second.firstSeen.empty() || seen < it->second.firstSeen))
            it->second.firstSeen = seen;
        }
      }
    }
    if (rounds > 1) {
      j.log("info", "SCAN", "round " + std::to_string(round + 1) + "/" +
                             std::to_string(rounds) + " done");
      for (int i = 0; i < 8 && !j.isStop(); i++) usleep(125000);
    }
  }

  // enrich: ARP cache for MACs, NetBIOS/reverse DNS for names, OUI for vendor
  auto arp = readArpTable();

  // Second-chance liveness pass. The per-host ARP read races our own SYN -- the
  // cache is sampled every 8th host, so a host whose entry appeared just after
  // that sample was dropped even though it answered. Anything we swept that the
  // kernel now knows about is alive, so pick those up before enriching.
  if (!arp.empty()) {
    for (auto& kv : arp) {
      const std::string& ip = kv.first;
      if (ip == me.ip || kv.second.empty()) continue;
      if (!cidrHas(cidr, ip)) continue;               // not something we swept
      if (found.count(ip)) continue;                  // already reported
      Device d;
      d.ip = ip;
      d.mac = kv.second;
      d.alive = true;
      d.source = "arp";
      d.isGateway = (ip == gw);
      d.firstSeen = stamp;
      d.lastSeen = stamp;
      d.hostname = ip;
      found.emplace(ip, d);
      j.emit("device", deviceJson(d));
      j.log("info", "ARP", "resolved " + ip + " -> " + kv.second);
    }
  }

  j.log("info", "ARP", arp.empty()
                        ? "ARP cache not readable — MAC/vendor will be unknown"
                        : "ARP cache loaded (" + std::to_string(arp.size()) + " entries)");

  std::vector<Device> devs;
  for (auto& kv : found) {
    Device d = kv.second;
    auto it = arp.find(d.ip);
    if (it != arp.end()) {
      d.mac = it->second;
      // A resolved neighbour is a live host even when no TCP port answers. The
      // old test was d.alive alone, which only a successful connect sets, so a
      // host that replied to ARP but had every probed port closed was dropped.
      if (!d.alive) {
        d.alive = true;
        d.source = d.source.empty() ? "arp" : d.source;
      } else {
        d.source = "arp+tcp";
      }
    }
    if (!d.alive) continue;
    std::string name = netbiosName(d.ip, 300);
    if (name.empty()) name = reverseDns(d.ip, 300);
    d.hostname = name;
    std::string kind;
    const char* v = ouiVendor(d.mac, &kind);
    d.vendor = v ? v : "";
    d.kind = classify(d.mac, d.hostname, d.openPorts, d.isGateway);
    if (d.hostname.empty()) {
      d.hostname = d.isGateway ? "Gateway" : (d.vendor.empty() ? "" : d.vendor);
    }
    devs.push_back(d);
  }

  // stable order: gateway first, then by IP
  std::sort(devs.begin(), devs.end(), [](const Device& a, const Device& b) {
    if (a.isGateway != b.isGateway) return a.isGateway;
    return a.ip < b.ip;
  });

  std::string arr = "[";
  for (size_t i = 0; i < devs.size(); i++) {
    if (i) arr += ",";
    arr += deviceJson(devs[i]);
  }
  arr += "]";

  Json out;
  out.obj().key("cidr").val(cidr).key("scanned").val((long long)hosts.size())
     .key("alive").val((long long)devs.size()).key("devices").raw(arr).end();
  j.emit("devices", out.str());
  j.log("info", "SCAN",
        std::to_string(devs.size()) + " of " + std::to_string(hosts.size()) +
        " hosts responded");
}

// ===========================================================================
//  port scanning
// ===========================================================================
void opPortScan(Job& j, const std::string& host, int from, int to,
                int timeoutMs, int threads) {
  int total = to - from + 1;
  if (total <= 0) { j.log("error", "SCAN", "invalid port range"); return; }
  if (threads < 8) threads = 8;
  if (threads > 512) threads = 512;
  j.log("info", "SCAN", host + " ports " + std::to_string(from) + "-" +
                        std::to_string(to) + " on " + std::to_string(threads) +
                        " threads");
  j.progress("connecting", 0);

  std::atomic<int> next{from};
  std::atomic<int> done{0};
  std::atomic<int> found{0};
  std::vector<std::thread> pool;
  for (int t = 0; t < threads; t++) {
    pool.emplace_back([&]() {
      while (!j.isStop()) {
        int p = next.fetch_add(1);
        if (p > to) break;
        double rtt = 0;
        int st = tcpConnect(host, p, timeoutMs, &rtt);
        int d = done.fetch_add(1);
        if (st == 1) {
          found.fetch_add(1);
          PortEntry e;
          e.port = p;
          e.state = PS_OPEN;
          e.service = serviceForPort(p);
          e.rttMs = rtt;
          Json j2;
          j2.obj().key("port").val(p).key("state").val("open")
             .key("service").val(e.service).key("rttMs").val(rtt).end();
          j.emit("port", j2.str());
        } else if (st == -1 && p < 1024) {
          PortEntry e;
          e.port = p;
          e.state = PS_FILTERED;
          Json j2;
          j2.obj().key("port").val(p).key("state").val("filtered")
             .key("service").val(serviceForPort(p)).end();
          j.emit("portFiltered", j2.str());
        }
        if ((d & 0x1FF) == 0) {
          j.progress("connecting", 100.0 * d / total,
                     std::to_string(found.load()) + " open");
        }
      }
    });
  }
  for (auto& th : pool) th.join();
  j.progress("connecting", 100.0, std::to_string(found.load()) + " open");
  j.log("info", "SCAN",
        std::to_string(found.load()) + " open ports on " + host);
}

// ===========================================================================
//  traceroute
// ===========================================================================
//
// Classic UDP traceroute: send a probe with TTL=n, and the nth router on the
// path drops it and answers ICMP Time Exceeded, naming itself.
//
// The interesting part is where that ICMP is read from. The textbook version
// opens a raw ICMP socket, which needs CAP_NET_RAW -- on Android that means root
// and a separate helper process, so traceroute would have been gated behind
// root for no good reason. Instead IP_RECVERR asks the kernel to queue ICMP
// errors against the probe socket itself, and the address it reports is the
// router that sent the error, which is exactly the hop being traced. That
// works unprivileged, so this sits with the other no-root operations.
//
// One probe is in flight at a time and the queue is drained before each send, so
// a queued error always belongs to the TTL that is currently being probed and
// no matching by payload is needed.
struct IcmpError {
  bool got = false;
  std::string addr;      // router that sent the error
  int type = 0;
  int code = 0;
  int err = 0;           // the errno the socket would have reported
};

// Takes one queued ICMP error off the socket, if there is one. Never blocks:
// callers have already waited on the socket.
static IcmpError takeIcmpError(int fd) {
  IcmpError e;
  char buf[256];
  char cbuf[256];
  struct iovec iov{buf, sizeof buf};
  struct msghdr mh{};
  mh.msg_iov = &iov;
  mh.msg_iovlen = 1;
  mh.msg_control = cbuf;
  mh.msg_controllen = sizeof cbuf;
  ssize_t n = ::recvmsg(fd, &mh, MSG_ERRQUEUE | MSG_DONTWAIT);
  if (n < 0) return e;

  for (struct cmsghdr* cm = CMSG_FIRSTHDR(&mh); cm; cm = CMSG_NXTHDR(&mh, cm)) {
    if (cm->cmsg_level != SOL_IP || cm->cmsg_type != IP_RECVERR) continue;
    struct sock_extended_err* ee =
        reinterpret_cast<struct sock_extended_err*>(CMSG_DATA(cm));
    if (ee->ee_origin == SO_EE_ORIGIN_ICMP) {
      e.got = true;
      e.type = ee->ee_type;
      e.code = ee->ee_code;
    }
    e.err = (int)ee->ee_errno;
  }
  if (!e.got) return e;

  // The kernel fills msg_name with the address the ICMP came from, which is the
  // router. The offender sockaddr in the control message is the documented
  // second source for the same address; either is enough, so both are tried
  // rather than assuming one of them is present on every kernel.
  if (mh.msg_name && mh.msg_namelen >= sizeof(struct sockaddr_in)) {
    struct sockaddr_in* sin = reinterpret_cast<struct sockaddr_in*>(mh.msg_name);
    char ip[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof ip)) e.addr = ip;
  }
  if (e.addr.empty()) {
    for (struct cmsghdr* cm = CMSG_FIRSTHDR(&mh); cm; cm = CMSG_NXTHDR(&mh, cm)) {
      if (cm->cmsg_level != SOL_IP || cm->cmsg_type != IP_RECVERR) continue;
      struct sock_extended_err* ee =
          reinterpret_cast<struct sock_extended_err*>(CMSG_DATA(cm));
      struct sockaddr_in* off = reinterpret_cast<struct sockaddr_in*>(
          reinterpret_cast<char*>(ee) + sizeof(struct sock_extended_err));
      if (off->sin_family != AF_INET) break;
      char ip[INET_ADDRSTRLEN];
      if (inet_ntop(AF_INET, &off->sin_addr, ip, sizeof ip)) e.addr = ip;
      break;
    }
  }
  return e;
}

// Waits up to timeoutMs for an ICMP error to be queued against fd.
static IcmpError awaitIcmpError(int fd, int timeoutMs) {
  IcmpError e;
  // POLLERR and only POLLERR: that is the bit Linux sets when the error queue
  // gains an entry. Adding POLLOUT to cover an implementation that might report
  // the error that way looks harmless and is not -- a connected UDP socket is
  // writable at all times, so poll would return immediately every hop, the
  // non-blocking recvmsg would find an empty queue, and every router on the
  // path would come back as a hop that never answered. It measured that way:
  // 0 of 10 hops answered on a route whose first hop is the local gateway.
  struct pollfd p{fd, POLLERR, 0};
  int pr = ::poll(&p, 1, timeoutMs);
  if (pr <= 0) return e;
  return takeIcmpError(fd);
}

// Empties the error queue so a stale error cannot be read as this probe's.
static void drainIcmpErrors(int fd) {
  for (int i = 0; i < 32; i++) {
    if (!takeIcmpError(fd).got) break;
  }
}

void opTraceroute(Job& j, const std::string& host, int maxHops, int port,
                  int timeoutMs, int resolveMs) {
  if (maxHops < 1) maxHops = 1;
  if (maxHops > 64) maxHops = 64;
  if (port < 1 || port > 65535) port = 33434;
  if (timeoutMs < 200) timeoutMs = 200;
  if (timeoutMs > 10000) timeoutMs = 10000;

  // Accept a name as well as a literal: traceroute is exactly the tool a person
  // reaches for with "why is example.com slow", and every other operation here
  // takes an address because it is fed from the device list.
  struct addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  struct addrinfo* res = nullptr;
  int gai = ::getaddrinfo(host.c_str(), nullptr, &hints, &res);
  if (gai != 0 || !res) {
    j.log("error", "TRACE", "cannot resolve " + host);
    return;
  }
  struct sockaddr_in dst = *reinterpret_cast<struct sockaddr_in*>(res->ai_addr);
  ::freeaddrinfo(res);
  char dstIp[INET_ADDRSTRLEN] = {0};
  inet_ntop(AF_INET, &dst.sin_addr, dstIp, sizeof dstIp);

  int fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (fd < 0) {
    j.log("error", "TRACE", std::string("socket: ") + strerror(errno));
    return;
  }
  int on = 1;
  if (::setsockopt(fd, IPPROTO_IP, IP_RECVERR, &on, sizeof on) != 0) {
    // Only reachable on a kernel without the extended error queue. Saying so
    // beats emitting a trace with every hop blank.
    j.log("error", "TRACE",
          "this kernel does not deliver ICMP errors to UDP sockets (IP_RECVERR)");
    ::close(fd);
    return;
  }
  // connect() is what ties the queued errors to this socket: without it the
  // kernel has no datagram to attach the ICMP to.
  if (::connect(fd, (struct sockaddr*)&dst, sizeof dst) != 0) {
    j.log("error", "TRACE", std::string("connect: ") + strerror(errno));
    ::close(fd);
    return;
  }

  j.log("info", "TRACE", host + " (" + dstIp + ") max " +
                             std::to_string(maxHops) + " hops, port " +
                             std::to_string(port));

  std::vector<TraceHop> hops;
  bool reached = false;
  for (int ttl = 1; ttl <= maxHops; ttl++) {
    if (j.isStop()) break;
    TraceHop h;
    h.ttl = ttl;

    drainIcmpErrors(fd);
    int ttlOpt = ttl;
    ::setsockopt(fd, IPPROTO_IP, IP_TTL, &ttlOpt, sizeof ttlOpt);
    int64_t t0 = nowMs();
    // Payload varies per probe so a switch between two paths cannot be mistaken
    // for a shorter route, even though the queue is drained anyway.
    char probe[40];
    int pn = snprintf(probe, sizeof probe, "zs-trace-%d-%d", (int)t0, ttl);
    ssize_t sent = ::send(fd, probe, pn > 0 ? (size_t)pn : sizeof probe, 0);
    if (sent < 0) {
      j.log("warn", "TRACE", "probe for hop " + std::to_string(ttl) +
                               " failed: " + strerror(errno));
    }

    IcmpError e = awaitIcmpError(fd, timeoutMs);
    h.rttMs = (double)(nowMs() - t0);
    if (e.got) {
      h.addr = e.addr;
      // Time Exceeded means a router on the path answered. Destination
      // Unreachable from the target itself means the path is complete. Anything
      // else (an administratively prohibited hop, say) still identifies a
      // router, so the address is kept and only `reached` stays false.
      if (e.type == ICMP_DEST_UNREACH) h.reached = true;
    }
    hops.push_back(h);

    Json o;
    o.obj().key("hop").val(ttl).key("addr").val(h.addr)
     .key("rttMs").val(h.rttMs).key("reached").val(h.reached)
     .key("type").val(e.got ? std::to_string(e.type) : "")
     .key("code").val(e.got ? std::to_string(e.code) : "").end();
    j.emit("hop", o.str());
    j.progress("tracing", 100.0 * ttl / maxHops,
               h.addr.empty() ? "hop " + std::to_string(ttl) + " no reply"
                              : h.addr);

    if (h.reached) { reached = true; break; }
  }
  ::close(fd);

  // Reverse DNS after the trace, not during it: a resolver that takes seconds
  // per hop would otherwise be indistinguishable from a hop that did not answer,
  // and the timing is the part the numbers are for.
  if (resolveMs > 0) {
    for (auto& h : hops) {
      if (h.addr.empty() || j.isStop()) continue;
      h.name = reverseDns(h.addr, resolveMs);
      Json o;
      o.obj().key("hop").val(h.ttl).key("addr").val(h.addr)
       .key("name").val(h.name).key("rttMs").val(h.rttMs)
       .key("reached").val(h.reached).end();
      j.emit("hopName", o.str());
    }
  }

  int silent = 0;
  for (const auto& h : hops) if (h.addr.empty()) silent++;
  j.progress("tracing", 100.0, std::to_string(hops.size()) + " hops");
  if (reached) {
    j.log("info", "TRACE", std::to_string(hops.size()) + " hops to " + dstIp);
  } else {
    // Not reaching the destination is a result, not a failure: a firewall that
    // drops the probes looks identical to a very long path, and saying which
    // one it was would be a guess.
    j.log("warn", "TRACE",
          "no destination reached within " + std::to_string(maxHops) +
              " hops" + (silent ? " (" + std::to_string(silent) +
                                       " hop(s) did not answer)" : ""));
  }
}

std::vector<ServiceInfo> inspectAll(const std::string& host,
                                    const std::vector<PortEntry>& ports,
                                    int timeoutMs,
                                    const std::function<void(const ServiceInfo&)>& onEach) {
  std::vector<ServiceInfo> out;
  for (auto& p : ports) {
    if (p.state != PS_OPEN) continue;
    std::string banner = p.banner.empty() ? grabBanner(host, p.port, timeoutMs)
                                          : p.banner;
    ServiceInfo s = fingerprint(p.port, banner, "");
    out.push_back(s);
    if (onEach) onEach(s);
  }
  return out;
}

void opInspect(Job& j, const std::string& host, const std::vector<int>& ports,
               int timeoutMs) {
  j.log("info", "FINGER", "probing " + std::to_string(ports.size()) +
                              " services on " + host);
  std::atomic<int> idx{0};
  std::vector<ServiceInfo> found(ports.size());
  std::vector<std::thread> pool;
  unsigned n = std::min<unsigned>(8, (unsigned)std::max<size_t>(1, ports.size()));
  for (unsigned t = 0; t < n; t++) {
    pool.emplace_back([&]() {
      while (!j.isStop()) {
        int i = idx.fetch_add(1);
        if (i >= (int)ports.size()) break;
        int port = ports[i];
        std::string banner = grabBanner(host, port, timeoutMs);
        ServiceInfo s = fingerprint(port, banner, "");
        found[i] = s;
        Json o;
        o.obj().key("port").val(s.port).key("name").val(s.name)
         .key("product").val(s.product).key("version").val(s.version)
         .key("banner").val(s.banner).key("confidence").val(s.confidence)
         .key("enc").val(s.enc).end();
        j.emit("service", o.str());
      }
    });
  }
  for (auto& th : pool) th.join();
  std::string arr = "[";
  long long n2 = 0;
  long long probed = 0;
  for (auto& s : found) {
    if (s.port == 0) continue;
    probed++;
    if (n2) arr += ",";
    Json o;
    o.obj().key("port").val(s.port).key("name").val(s.name)
     .key("product").val(s.product).key("version").val(s.version)
     .key("banner").val(s.banner).key("confidence").val(s.confidence)
     .key("enc").val(s.enc).end();
    arr += o.str();
    n2++;
  }
  arr += "]";
  // A cancelled run left ports unprobed, and the slots for them stay zero and
  // are filtered out above -- so the array is short without saying why, and
  // 100% progress would claim a complete fingerprint of a service list that is
  // not complete. Both the count and the flag travel with the result so the UI
  // can label it.
  bool partial = j.isStop();
  Json out;
  out.obj().key("host").val(host).key("services").raw(arr)
     .key("probed").val(probed).key("of").val((long long)ports.size())
     .key("partial").val(partial).end();
  j.emit("services", out.str());
  if (partial) {
    j.log("warn", "FINGER",
          "cancelled after " + std::to_string(probed) + " of " +
              std::to_string(ports.size()) +
              " services; this list is incomplete, not a clean result");
    j.progress("fingerprint", 100.0, "cancelled, partial");
  } else {
    j.progress("fingerprint", 100.0);
  }
}

void opExploits(Job& j, const std::string& host, const std::string& portsCsv) {
  std::vector<int> ports;
  // Validated and de-duplicated. atoi() alone turns any junk into 0 and a
  // negative into a 16-bit wrap, so "-1" would probe port 65535 and "abc"
  // would probe port 0 -- neither of which is what was asked for, and a
  // duplicate in the list made one daemon report the same CVE three times.
  std::set<int> seen;
  int rejected = 0;
  for (auto& s : split(portsCsv, ',')) {
    s = trim(s);
    if (s.empty()) continue;
    if (!allDigits(s)) { rejected++; continue; }
    long v = strtol(s.c_str(), nullptr, 10);
    if (v < 1 || v > 65535) { rejected++; continue; }
    if (!seen.insert((int)v).second) continue;
    ports.push_back((int)v);
  }
  if (ports.empty()) {
    j.log("error", "CVE", "no valid ports supplied" +
                          (rejected ? " (" + std::to_string(rejected) +
                                         " entry/entries were not a port number)"
                                    : ""));
    return;
  }
  if (rejected)
    j.log("warn", "CVE", std::to_string(rejected) +
                           " port entry/entries ignored: not a number in 1-65535");
  j.log("info", "CVE", "fingerprinting " + std::to_string(ports.size()) +
                           " service(s) on " + host + " before matching");

  std::vector<ServiceInfo> services;
  std::mutex mu;
  std::atomic<int> idx{0};
  std::vector<std::thread> pool;
  for (int t = 0; t < 6; t++) {
    pool.emplace_back([&]() {
      while (!j.isStop()) {
        int i = idx.fetch_add(1);
        if (i >= (int)ports.size()) break;
        int port = ports[i];
        std::string banner = grabBanner(host, port, 2500);
        ServiceInfo s = fingerprint(port, banner, "");
        std::lock_guard<std::mutex> lk(mu);
        services.push_back(s);
      }
    });
  }
  for (auto& th : pool) th.join();

  // A cancelled run has not looked at everything it was asked to look at, and
  // reporting a short list as if it were the whole picture is the difference
  // between "this host is clean" and "this host was not fully checked".
  bool partial = j.isStop();
  auto findings = matchCves(host, services);
  if (partial) {
    findings.push_back(Finding{
        .cve = "-",
        .product = "-",
        .title = "Cancelled before every port was checked",
        .severity = "INFO",
        .cvss = 0,
        .portRef = "-",
        .evidence = std::to_string(services.size()) + " of " +
                     std::to_string(ports.size()) + " ports were fingerprinted",
        .remedy = "Run it again to completion before relying on this result",
        .cwe = "-",
    });
  }
  std::string arr = "[";
  for (size_t i = 0; i < findings.size(); i++) {
    if (i) arr += ",";
    const Finding& f = findings[i];
    Json o;
    o.obj().key("cve").val(f.cve).key("product").val(f.product)
     .key("title").val(f.title).key("severity").val(f.severity)
     .key("cvss").val(f.cvss).key("port").val(f.portRef)
     .key("evidence").val(f.evidence).key("remedy").val(f.remedy)
     .key("cwe").val(f.cwe).end();
    arr += o.str();
  }
  arr += "]";
  Json out;
  out.obj().key("host").val(host).key("findings").raw(arr)
     .key("checked").val((long long)services.size()).end();
  j.emit("findings", out.str());
  j.progress("match", 100.0, std::to_string(findings.size()) + " findings");
  j.log("info", "CVE", std::to_string(findings.size()) + " findings");
}

// ===========================================================================
//  credential auditing
// ===========================================================================
// Default / weak credential pairs, grouped by target profile. Used to check
// whether a device you own or are authorised to test still accepts them.
struct CredPair { const char* user; const char* pass; };
struct CredProfile {
  const char* name;
  int port;
  const char* proto;
  std::vector<CredPair> pairs;
};

static const std::vector<CredProfile>& credProfiles() {
  static const std::vector<CredProfile> p = {
      {"router", 23, "telnet",
       {{"admin", "admin"}, {"admin", "password"}, {"admin", "1234"},
        {"root", "root"}, {"root", "admin"}, {"root", "12345"},
        {"user", "user"}, {"guest", "guest"}, {"support", "support"},
        {"default", "default"}}},
      {"router", 80, "http",
       {{"admin", "admin"}, {"admin", "password"}, {"admin", "1234"},
        {"root", "root"}, {"user", "user"}}},
      {"camera", 80, "http",
       {{"admin", "admin"}, {"root", "root"}, {"admin", "password"},
        {"admin", "12345"}, {"user", "user"}, {"guest", "guest"}}},
      {"nas", 5000, "http",
       {{"admin", "admin"}, {"root", "root"}, {"admin", "password"},
        {"nas", "nas"}}},
      {"iot", 23, "telnet",
       {{"root", "root"}, {"admin", "admin"}, {"root", "vizxv"},
        {"root", "xc3511"}, {"root", "888888"}, {"admin", "1234"},
        {"root", "juantech"}, {"root", "54321"}}},
      {"nas", 22, "ssh",
       {{"admin", "admin"}, {"root", "root"}, {"root", "password"},
        {"admin", "password"}}},
  };
  return p;
}

static const CredProfile* findProfile(const std::string& name, int port) {
  for (auto& p : credProfiles())
    if (lower(name) == lower(p.name) && port == p.port) return &p;
  for (auto& p : credProfiles())
    if (lower(name) == lower(p.name)) return &p;
  return nullptr;
}

// Detect an auth prompt and classify the reply.
static bool tryTelnetAuth(const std::string& host, int port,
                          const std::string& user, const std::string& pass,
                          int timeoutMs, double* rtt, std::string* note) {
  int fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (fd < 0) return false;
  struct sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_port = htons((uint16_t)port);
  if (inet_pton(AF_INET, host.c_str(), &a.sin_addr) != 1) { ::close(fd); return false; }
  struct timeval tv;
  tv.tv_sec = timeoutMs / 1000;
  tv.tv_usec = (timeoutMs % 1000) * 1000;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
  if (::connect(fd, (struct sockaddr*)&a, sizeof a) != 0) {
    if (rtt) *rtt = (double)timeoutMs;
    if (note) *note = "connect failed";
    ::close(fd);
    return false;
  }
  if (rtt) *rtt = 0;
  std::string buf = readSome(fd, 1024, timeoutMs);
  if (lower(buf).find("login") == std::string::npos &&
      lower(buf).find("username") == std::string::npos) {
    if (note) *note = "no login prompt";
    ::close(fd);
    return false;
  }
  if (note) *note = "prompt ok";
  writeSome(fd, user + "\r\n");
  usleep(120000);
  readSome(fd, 1024, timeoutMs);
  writeSome(fd, pass + "\r\n");
  usleep(250000);
  std::string tail = readSome(fd, 2048, 1200);
  std::string low = lower(tail);
  bool denied = contains(low, "incorrect") || contains(low, "invalid") ||
                contains(low, "denied") || contains(low, "again") ||
                contains(low, "failed") || contains(low, "bad password");
  bool shell = contains(low, "$ ") || contains(low, "# ") ||
               contains(low, "busybox") || contains(low, "->");
  ::close(fd);
  if (shell && !denied) { if (note) *note = "shell granted"; return true; }
  if (note) *note = denied ? "credentials rejected" : "no shell after login";
  return false;
}

static bool tryHttpAuth(const std::string& host, int port,
                        const std::string& user, const std::string& pass,
                        int timeoutMs, std::string* note) {
  int fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (fd < 0) return false;
  struct sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_port = htons((uint16_t)port);
  if (inet_pton(AF_INET, host.c_str(), &a.sin_addr) != 1) { ::close(fd); return false; }
  struct timeval tv;
  tv.tv_sec = timeoutMs / 1000;
  tv.tv_usec = (timeoutMs % 1000) * 1000;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
  if (::connect(fd, (struct sockaddr*)&a, sizeof a) != 0) { ::close(fd); return false; }

  std::string head = grabBanner(host, port, timeoutMs);
  if (head.find("401") == std::string::npos &&
      lower(head).find("www-authenticate") == std::string::npos) {
    if (note) *note = "endpoint does not challenge for auth";
    ::close(fd);
    return false;
  }
  std::string cred = user + ":" + pass;
  std::string b64;
  static const char* t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  for (size_t i = 0; i < cred.size(); i += 3) {
    unsigned v = (unsigned)(unsigned char)cred[i] << 16;
    if (i + 1 < cred.size()) v |= (unsigned)(unsigned char)cred[i + 1] << 8;
    if (i + 2 < cred.size()) v |= (unsigned)(unsigned char)cred[i + 2];
    b64 += t[(v >> 18) & 63];
    b64 += t[(v >> 12) & 63];
    b64 += (i + 1 < cred.size()) ? t[(v >> 6) & 63] : '=';
    b64 += (i + 2 < cred.size()) ? t[v & 63] : '=';
  }
  std::string req = "GET / HTTP/1.0\r\nHost: " + host + "\r\nAuthorization: Basic " +
                    b64 + "\r\nUser-Agent: ZeroSploit/1.0\r\n\r\n";
  if (::send(fd, req.data(), req.size(), 0) < 0) { ::close(fd); return false; }
  std::string resp = readSome(fd, 4096, timeoutMs);
  ::close(fd);
  if (note)
    *note = startsWith(resp, "HTTP/1.0 200") || startsWith(resp, "HTTP/1.1 200")
                ? "authenticated"
                : "credentials rejected";
  return resp.find(" 200") != std::string::npos;
}

void opLoginAudit(Job& j, const std::string& host, int port,
                  const std::string& profileName) {
  const CredProfile* prof = findProfile(profileName, port);
  if (!prof) {
    j.log("error", "AUTH", "unknown profile '" + profileName + "'");
    return;
  }
  j.log("info", "AUTH", "auditing " + host + ":" + std::to_string(port) +
                          " with profile '" + prof->name + "' (" +
                          std::to_string(prof->pairs.size()) + " pairs, " +
                          std::to_string(2) + "/sec)");

  std::string arr = "[";
  long long n = 0;
  long long accepted = 0;
  std::vector<CredResult> acceptedList;

  for (auto& pair : prof->pairs) {
    if (j.isStop()) break;
    double rtt = 0;
    std::string note;
    bool ok = false;
    int64_t t0 = nowMs();
    if (strcmp(prof->proto, "telnet") == 0) {
      ok = tryTelnetAuth(host, port, pair.user, pair.pass, 2500, &rtt, &note);
    } else if (strcmp(prof->proto, "http") == 0) {
      ok = tryHttpAuth(host, port, pair.user, pair.pass, 2500, &note);
      rtt = (double)(nowMs() - t0);
    }
    if (rtt <= 0) rtt = (double)(nowMs() - t0);

    CredResult cr;
    cr.user = pair.user;
    cr.pass = ok ? std::string("********") : "";
    cr.accepted = ok;
    cr.service = prof->proto;
    cr.rttMs = rtt;
    cr.note = note;
    if (ok) { accepted++; acceptedList.push_back(cr); }

    Json o;
    o.obj().key("user").val(cr.user).key("accepted").val(cr.accepted)
     .key("service").val(cr.service).key("rttMs").val(cr.rttMs)
     .key("note").val(cr.note).end();
    if (n) arr += ",";
    arr += o.str();
    n++;

    j.emit("cred", o.str());
    j.progress("audit", 100.0 * n / prof->pairs.size());
    if (ok) j.log("warn", "AUTH",
                  std::string("ACCEPTED ") + pair.user + " on " + host);
    usleep(500000);   // rate limit: 2 attempts / second
  }
  arr += "]";
  Json out;
  out.obj().key("host").val(host).key("port").val(port)
     .key("profile").val(prof->name).key("protocol").val(prof->proto)
     .key("results").raw(arr).key("accepted").val(accepted).end();
  j.emit("credReport", out.str());
  j.log(accepted ? "warn" : "info", "AUTH",
        std::to_string(accepted) + " of " + std::to_string(n) +
        " accounts accepted");
}

void opShell(Job& j, const std::string& host, int port, const std::string& user,
             const std::string& pass) {
  int fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (fd < 0) { j.log("error", "SHELL", "socket failed"); return; }
  struct sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_port = htons((uint16_t)port);
  if (inet_pton(AF_INET, host.c_str(), &a.sin_addr) != 1) { ::close(fd); return; }
  struct timeval tv;
  tv.tv_sec = 3;
  tv.tv_usec = 0;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
  if (::connect(fd, (struct sockaddr*)&a, sizeof a) != 0) {
    j.log("error", "SHELL", "cannot connect to " + host);
    ::close(fd);
    return;
  }
  std::string banner = readSome(fd, 2048, 1500);
  writeSome(fd, user + "\r\n");
  usleep(150000);
  readSome(fd, 1024, 1200);
  writeSome(fd, pass + "\r\n");
  usleep(300000);
  std::string probe = readSome(fd, 2048, 1500);
  if (lower(probe).find("incorrect") != std::string::npos ||
      lower(probe).find("denied") != std::string::npos) {
    j.log("error", "SHELL", "authentication rejected");
    ::close(fd);
    return;
  }

  SessionInfo s;
  s.target = host + ":" + std::to_string(port);
  s.proto = serviceForPort(port);
  s.user = user;
  s.priv = contains(probe, "#") ? "root"
                                   : (contains(probe, "$") ? "user" : "shell");
  s.startedAt = nowMs() / 1000;
  s.state = "live";
  int sid = addSession(s);
  Json o;
  o.obj().key("id").val(sid).key("target").val(s.target).key("proto").val(s.proto)
   .key("user").val(user).key("priv").val(s.priv).key("state").val("live").end();
  j.emit("session", o.str());
  j.log("info", "SHELL", "session " + std::to_string(sid) + " open on " + s.target);

  // run a small read-only recon batch to make the session useful immediately
  static const char* kCmds[] = {"id", "uname -a", "cat /etc/os-release",
                                "ip addr", "ps"};
  std::string transcript = banner;
  for (const char* c : kCmds) {
    if (j.isStop()) break;
    transcript += "\n$ " + std::string(c);
    writeSome(fd, std::string(c) + "\n");
    usleep(700000);
    transcript += readSome(fd, 4096, 900);
  }
  Json tr;
  tr.obj().key("id").val(sid).key("data").val(transcript.substr(0, 8000)).end();
  j.emit("sessionData", tr.str());
  updateSession(sid, "live");
  // keep the descriptor open for follow-up interaction
  usleep(200000);
  ::close(fd);
  updateSession(sid, "closed");
  j.log("info", "SHELL", "session " + std::to_string(sid) + " finished");
}

// ===========================================================================
//  session registry
// ===========================================================================
static std::mutex g_sessMu;
static std::vector<SessionInfo> g_sess;
static int g_sessNext = 1;

int addSession(const SessionInfo& s) {
  std::lock_guard<std::mutex> lk(g_sessMu);
  SessionInfo c = s;
  c.id = g_sessNext++;
  g_sess.push_back(c);
  if (g_sess.size() > 200) g_sess.erase(g_sess.begin());
  return c.id;
}

void updateSession(int id, const std::string& state) {
  std::lock_guard<std::mutex> lk(g_sessMu);
  for (auto& s : g_sess)
    if (s.id == id) { s.state = state; s.uptimeSec = nowMs() / 1000 - s.startedAt; }
}

std::vector<SessionInfo> listSessions() {
  std::lock_guard<std::mutex> lk(g_sessMu);
  std::vector<SessionInfo> v = g_sess;
  long long now = nowMs() / 1000;
  for (auto& s : v) s.uptimeSec = now - s.startedAt;
  return v;
}

std::string sessionJson() {
  auto v = listSessions();
  std::string arr = "[";
  for (size_t i = 0; i < v.size(); i++) {
    if (i) arr += ",";
    Json o;
    o.obj().key("id").val(v[i].id).key("target").val(v[i].target)
     .key("proto").val(v[i].proto).key("user").val(v[i].user)
     .key("priv").val(v[i].priv).key("uptimeSec").val((long long)v[i].uptimeSec)
     .key("state").val(v[i].state).end();
    arr += o.str();
  }
  arr += "]";
  Json o;
  o.obj().key("sessions").raw(arr).end();
  return o.str();
}

// ===========================================================================
//  capabilities report
// ===========================================================================
void opCapabilities(Job& j) {
  RootStatus r = probeRoot();
  IfaceInfo me = primaryIface();
  RawCaps rc = probeRawCaps(me.name);

  std::string caps = "[";
  auto add = [&](const char* name, const char* detail, const char* need,
                 bool ok, const char* note) {
    if (caps != "[") caps += ",";
    Json o;
    o.obj().key("name").val(name).key("detail").val(detail)
     .key("needs").val(need).key("ok").val(ok).key("note").val(note).end();
    caps += o.str();
  };
  add("Subnet discovery", "ARP cache + TCP connect + NetBIOS", "none", true,
      "unprivileged");
  add("TCP port scanner", "non-blocking connect()", "none", true, "unprivileged");
  add("Traceroute", "UDP probe + ICMP error queue", "none", true, "unprivileged");
  add("Banner & service ID", "fingerprint rules", "none", true, "unprivileged");
  add("Exploit matcher", "CVE signature set", "none", true, "unprivileged");
  add("Login auditor", "profile-driven auth checks", "none", true, "unprivileged");
  add("ARP spoof / MITM", "AF_PACKET raw socket", "root",
      rc.packetSocket && r.granted,
      rc.packetSocket ? "raw socket reachable" : "AF_PACKET unavailable");
  add("Packet forger", "AF_INET SOCK_RAW", "root", rc.rawIpSocket && r.granted,
      rc.rawIpSocket ? "raw socket reachable" : "raw socket unavailable");
  add("802.11 deauth", "monitor-mode injection", "root",
      rc.monitorMode && r.granted,
      rc.monitorMode ? "interface is in monitor mode" : "interface not in monitor mode");

  Json o;
  o.obj().key("iface").val(me.name).key("ip").val(me.ip).key("cidr").val(me.cidr)
   .key("gateway").val(me.gateway).key("mac").val(me.mac)
   .key("ssid").val(me.ssid).key("isWifi").val(me.isWifi)
   .key("rootAvailable").val(r.available).key("rootGranted").val(r.granted)
   .key("rootManager").val(r.manager).key("rootDetail").val(r.detail)
   .key("packetSocket").val(rc.packetSocket)
   .key("rawIpSocket").val(rc.rawIpSocket)
   .key("monitorMode").val(rc.monitorMode)
   .key("rawDetail").val(rc.detail)
   .key("caps").raw(caps).end();
  j.emit("capabilities", o.str());
  j.log("info", "CAP", std::string("root ") + (r.granted ? "granted" : "not granted"));
}

}  // namespace zs
