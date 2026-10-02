// Small helpers: strings, JSON writer, time, process exec, root probing,
// interface enumeration and subnet maths.
#include "zs.h"

#include <arpa/inet.h>
#include <atomic>
#include <dirent.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <sstream>

extern "C" {
#include <ifaddrs.h>
}

namespace zs {

// ------------------------------------------------------------------ strings
std::string jsonEscape(const std::string& s) {
  std::string o;
  o.reserve(s.size() + 8);
  for (unsigned char c : s) {
    switch (c) {
      case '"':  o += "\\\""; break;
      case '\\': o += "\\\\"; break;
      case '\n': o += "\\n";  break;
      case '\r': o += "\\r";  break;
      case '\t': o += "\\t";  break;
      case '\b': o += "\\b";  break;
      case '\f': o += "\\f";  break;
      default:
        if (c < 0x20) {
          char buf[8];
          snprintf(buf, sizeof buf, "\\u%04x", c);
          o += buf;
        } else {
          o += (char)c;
        }
    }
  }
  return o;
}

std::string jstr(const std::string& s) { return "\"" + jsonEscape(s) + "\""; }
std::string jnum(long long v) { return std::to_string(v); }

std::string trim(const std::string& s) {
  size_t a = s.find_first_not_of(" \t\r\n");
  if (a == std::string::npos) return "";
  size_t b = s.find_last_not_of(" \t\r\n");
  return s.substr(a, b - a + 1);
}

std::string lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(),
                 [](unsigned char c) { return (char)std::tolower(c); });
  return s;
}
std::string upper(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(),
                 [](unsigned char c) { return (char)std::toupper(c); });
  return s;
}
bool startsWith(const std::string& s, const std::string& p) {
  return s.size() >= p.size() && s.compare(0, p.size(), p) == 0;
}
bool contains(const std::string& s, const std::string& p) {
  return s.find(p) != std::string::npos;
}
bool allDigits(const std::string& s) {
  if (s.empty()) return false;
  for (char c : s)
    if (!isdigit((unsigned char)c)) return false;
  return true;
}
std::vector<std::string> split(const std::string& s, char sep) {
  std::vector<std::string> out;
  std::string cur;
  for (char c : s) {
    if (c == sep) { out.push_back(cur); cur.clear(); }
    else cur += c;
  }
  out.push_back(cur);
  return out;
}
std::string join(const std::vector<std::string>& v, const std::string& sep) {
  std::string o;
  for (size_t i = 0; i < v.size(); i++) { if (i) o += sep; o += v[i]; }
  return o;
}
std::string urlDecode(const std::string& s) {
  std::string o;
  for (size_t i = 0; i < s.size(); i++) {
    if (s[i] == '%' && i + 2 < s.size()) {
      o += (char)strtol(s.substr(i + 1, 2).c_str(), nullptr, 16);
      i += 2;
    } else if (s[i] == '+') {
      o += ' ';
    } else {
      o += s[i];
    }
  }
  return o;
}

// --------------------------------------------------------------------- json
void Json::sep() {
  if (needComma_) s_ += ",";
  s_ += "\n";
  s_.append(static_cast<size_t>(depth_ + 1) * 2, ' ');
  needComma_ = false;
}
Json& Json::key(const std::string& k) {
  sep();
  s_ += jstr(k);
  s_ += ": ";
  return *this;
}
Json& Json::val(const std::string& v) { s_ += jstr(v); needComma_ = true; return *this; }
Json& Json::val(long long v) { s_ += std::to_string(v); needComma_ = true; return *this; }
Json& Json::val(double v) {
  char b[32];
  snprintf(b, sizeof b, "%.2f", v);
  s_ += b;
  needComma_ = true;
  return *this;
}
Json& Json::val(bool v) { s_ += v ? "true" : "false"; needComma_ = true; return *this; }
Json& Json::raw(const std::string& v) { s_ += v; needComma_ = true; return *this; }
Json& Json::null() { s_ += "null"; needComma_ = true; return *this; }
Json& Json::obj() { s_ += "{"; depth_++; needComma_ = false; return *this; }
Json& Json::end() {
  // Clamp: an extra end() used to make depth_ negative, and the negative
  // indent length made std::string::append throw std::length_error. The build
  // disables exceptions, so that was an unconditional std::terminate -> SIGABRT
  // instead of a recoverable JSON mistake.
  if (depth_ > 0) depth_--;
  s_ += "\n";
  s_.append(static_cast<size_t>(depth_) * 2, ' ');
  s_ += "}";
  needComma_ = true;
  return *this;
}

// --------------------------------------------------------------------- time
int64_t nowMs() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

std::string nowIso8601() {
  time_t t = time(nullptr);
  struct tm tmv;
  localtime_r(&t, &tmv);
  char b[32];
  strftime(b, sizeof b, "%Y-%m-%dT%H:%M:%S", &tmv);
  return b;
}

std::string nowClock() {
  time_t t = time(nullptr);
  struct tm tmv;
  localtime_r(&t, &tmv);
  char b[16];
  strftime(b, sizeof b, "%H:%M:%S", &tmv);
  return b;
}

// -------------------------------------------------------------------- files
static bool readFile(const std::string& p, std::string& out) {
  std::ifstream f(p);
  if (!f.is_open()) return false;
  std::stringstream ss;
  ss << f.rdbuf();
  out = ss.str();
  return true;
}

// --------------------------------------------------------------------- exec
// Fallback is only used if nativeInit() never delivered a scratch dir; a
// writable fallback matters because system() output is redirected to a file
// because Android has no pipe capture in the C library.
static std::string g_scratchDir;

// Budget for an su call. Long enough to cover a Magisk superuser prompt, which
// the user has to answer by hand.
static const int kSuTimeoutMs = 120000;

void setScratchDir(std::string dir) {
  // Trailing slashes would produce "dir//tmp_exec" in shell redirects.
  while (dir.size() > 1 && dir.back() == '/') dir.pop_back();
  g_scratchDir = dir;
}

static std::atomic<unsigned> g_execSeq{0};

static std::string runCapture(const std::string& cmd, int timeoutMs) {
  std::string base = g_scratchDir.empty() ? std::string("/data/local/tmp")
                                          : g_scratchDir;
  // A per-call name: the root probe runs on its own thread while engine jobs
  // shell out too, and a shared file made them read each other's output.
  std::string path = base + "/zsexec_" + std::to_string((long)getpid()) + "_" +
                     std::to_string(g_execSeq.fetch_add(1));
  unlink(path.c_str());
  // The end marker separates "finished and printed nothing" from "still
  // running". Without it the poll returned on its first tick, because the shell
  // creates the redirect target immediately -- which is why an su call looked
  // like it had produced no output after 300ms.
  std::string full = "{ " + cmd + " ; echo __ZSEND__ ; } >" + path + " 2>&1 &";
  if (system(full.c_str()) != 0) return "";
  for (int i = 0; i < timeoutMs / 20; i++) {
    usleep(20000);
    std::string o;
    if (!readFile(path, o)) continue;
    size_t m = o.find("__ZSEND__");
    if (m == std::string::npos) continue;  // still running
    unlink(path.c_str());
    o.resize(m);
    return trim(o);
  }
  unlink(path.c_str());
  return "";
}

std::string execRoot(const std::string& cmd, int timeoutMs) {
  return runCapture("su -c '" + cmd + "'", timeoutMs);
}

// --------------------------------------------------------------------- root
RootStatus probeRoot() {
  RootStatus r;
  // --- identify the manager -------------------------------------------------
  // Magisk is detected by its data directory rather than by a binary name,
  // because on Android 11+ the real su lives at /debug_ramdisk/su and is
  // bind-mounted into place; the APK-visible /system/bin/su may be absent.
  if (access("/data/adb/magisk", F_OK) == 0) {
    r.manager = "magisk";
    r.detail = "Magisk data directory at /data/adb/magisk";
    // Kitsune (Magisk Delta) ships ksud and advertises itself as such.
    if (access("/data/adb/ksud", X_OK) == 0 ||
        runCapture("ksud --version 2>/dev/null", 1500) != "")
      r.detail += " (Kitsune/Magisk-Delta layout detected)";
  } else if (access("/data/adb/ap", F_OK) == 0 ||
             access("/data/adb/apd", X_OK) == 0) {
    r.manager = "apatch";
    r.detail = "APatch data directory present";
  } else if (access("/data/adb/su", F_OK) == 0) {
    r.manager = "supersu";
    r.detail = "legacy SuperSU data directory present";
  }

  // --- locate su ------------------------------------------------------------
  // /debug_ramdisk/su is where Magisk actually keeps the binary on modern
  // devices; the rest are the historical locations and PATH fallbacks.
  const char* suPaths[] = {"/debug_ramdisk/su", "/system/bin/su",
                           "/system/xbin/su",   "/sbin/su",
                           "/su/bin/su",        "/system/sbin/su",
                           "/vendor/bin/su"};
  std::string suBin;
  for (const char* p : suPaths) {
    if (access(p, X_OK) == 0) { suBin = p; break; }
  }
  if (suBin.empty() && runCapture("command -v su", 1500) != "")
    suBin = "su (from PATH)";

  if (r.manager.empty()) {
    // No recognised data directory: still worth reporting if su exists, since
    // the manager could be anything.
    for (const char* b : {"magisk", "ksud", "apd", "superuser"}) {
      std::string p = std::string("/system/bin/") + b;
      if (access(p.c_str(), X_OK) == 0) { r.manager = b; break; }
      p = std::string("/system/xbin/") + b;
      if (access(p.c_str(), X_OK) == 0) { r.manager = b; break; }
    }
  }

  if (suBin.empty()) {
    r.available = false;
    r.manager = r.manager.empty() ? "none" : r.manager;
    r.detail = "no su binary found in /debug_ramdisk, /system/bin, /system/xbin, "
               "/sbin or PATH";
    return r;
  }
  r.available = true;
  if (r.manager.empty()) r.manager = "unknown";
  r.detail += "; su at " + suBin;

  // --- version --------------------------------------------------------------
  std::string mv = runCapture("magisk -v 2>/dev/null", 2000);
  if (!mv.empty()) r.detail += "; Magisk " + mv;

  // --- is the request actually granted? ------------------------------------
  // This is the call that makes Magisk show its superuser prompt, so it gets a
  // timeout long enough for a human to read and tap Grant. The earlier 5s
  // budget (and a 2>/dev/null that hid the manager's own message) meant the
  // prompt was killed unanswered, which Magisk records as no policy at all.
  // stderr is kept because the denial text lives there.
  std::string out = runCapture("su -c 'id -u'", kSuTimeoutMs);
  std::string t = trim(out);
  if (t == "0") {
    r.granted = true;
    r.detail += "; uid=0 granted";
  } else if (t.empty()) {
    r.detail += "; su produced no output — grant the app in Magisk > Superuser, "
                "then tap Request root again";
  } else {
    r.detail += "; su output: " + t.substr(0, 160);
  }
  return r;
}

// ----------------------------------------------------------------- netinfo
static std::string macOf(const std::string& ifname) {
  std::string p = "/sys/class/net/" + ifname + "/address";
  std::ifstream f(p);
  if (f.is_open()) {
    std::string s;
    std::getline(f, s);
    return trim(s);
  }
  return "";
}

static int prefixFromMask(const std::string& mask) {
  struct in_addr a{};
  if (inet_pton(AF_INET, mask.c_str(), &a) != 1) return 24;
  uint32_t m = ntohl(a.s_addr);
  int p = 0;
  while (m & 0x80000000u) { p++; m <<= 1; }
  return p;
}

// default gateway from the kernel routing table
static std::string defaultGateway() {
  std::string tbl;
  if (!readFile("/proc/net/route", tbl)) return "";
  std::istringstream in(tbl);
  std::string line;
  bool first = true;
  while (std::getline(in, line)) {
    if (first) { first = false; continue; }
    std::istringstream ls(line);
    std::string iface, dest, gw, flags, ref, use, metric;
    if (!(ls >> iface >> dest >> gw)) continue;
    if (dest == "00000000") {                       // default route
      // little-endian hex
      unsigned long v = strtoul(gw.c_str(), nullptr, 16);
      if (v == 0) continue;
      struct in_addr a{};
      a.s_addr = htonl((uint32_t)v);
      char buf[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &a, buf, sizeof buf);
      return buf;
    }
  }
  return "";
}

static void wifiInfo(IfaceInfo& n) {
  // The wireless/ directory exists on every 802.11 interface, but its link file
  // only appears once the interface is associated. Testing for link therefore
  // mislabelled a disconnected wlan0 as a plain interface, which hid the radio
  // from the Wi-Fi and monitor workflows. phy80211 is an equivalent marker.
  std::string dir = "/sys/class/net/" + n.name + "/wireless";
  std::string phy = "/sys/class/net/" + n.name + "/phy80211";
  // A soft-AP interface (ap0) is wireless by construction and can exist with
  // neither directory while the driver is reloading, so the name decides too:
  // the hotspot is exactly the interface the Wi-Fi module has to offer.
  bool named = startsWith(n.name, "wlan") || startsWith(n.name, "ap0") ||
               startsWith(n.name, "ap1");
  if (access(dir.c_str(), F_OK) != 0 && access(phy.c_str(), F_OK) != 0 && !named)
    return;
  n.isWifi = true;
  std::string c;
  if (readFile(dir + "/link", c)) {
    // /sys/class/net/wlan0/wireless/link holds "<essid> <bssid>"
    auto parts = split(trim(c), ' ');
    if (parts.size() >= 2) { n.ssid = parts[0]; n.bssid = parts[1]; }
  } else {
    n.ssid = "(not associated)";
  }
}

std::vector<IfaceInfo> enumerateIfaces() {
  std::vector<IfaceInfo> out;
  struct ifaddrs* ifa = nullptr;
  if (getifaddrs(&ifa) != 0) return out;

  std::unordered_map<std::string, IfaceInfo> byName;
  for (struct ifaddrs* p = ifa; p; p = p->ifa_next) {
    if (!p->ifa_addr) continue;
    if (p->ifa_addr->sa_family != AF_INET) continue;
    if (!(p->ifa_flags & IFF_UP)) continue;
    char buf[INET_ADDRSTRLEN];
    auto* sin = (struct sockaddr_in*)p->ifa_addr;
    if (!inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof buf)) continue;
    std::string ip = buf;
    if (startsWith(ip, "127.")) continue;
    IfaceInfo& n = byName[p->ifa_name];
    n.name = p->ifa_name;
    n.ip = ip;
    n.isUp = true;
    if (p->ifa_netmask) {
      if (inet_ntop(AF_INET, &((struct sockaddr_in*)p->ifa_netmask)->sin_addr,
                    buf, sizeof buf))
        n.netmask = buf;
    }
  }
  freeifaddrs(ifa);

  // getifaddrs() only yields interfaces that carry an address, which drops
  // wlan0 whenever the radio is down or unassociated -- exactly the interface
  // the Wi-Fi and monitor modules need to show. Walk /sys/class/net as well so
  // address-less interfaces are still reported, flagged as having no IP.
  if (DIR* d = opendir("/sys/class/net")) {
    while (struct dirent* e = readdir(d)) {
      std::string name = e->d_name;
      if (name == "." || name == "..") continue;
      if (byName.count(name)) continue;
      int flags = 0;
      std::ifstream f("/sys/class/net/" + name + "/flags");
      if (f.is_open()) f >> std::hex >> flags;
      IfaceInfo n;
      n.name = name;
      n.isUp = (flags & 0x1) != 0;  // IFF_UP
      n.mac = macOf(name);
      byName[name] = n;
    }
    closedir(d);
  }

  std::string gw = defaultGateway();
  for (auto& kv : byName) {
    IfaceInfo& n = kv.second;
    n.mac = macOf(n.name);
    if (n.ip.empty()) {
      n.prefix = 0;
      n.cidr.clear();
    } else {
      n.prefix = n.netmask.empty() ? 24 : prefixFromMask(n.netmask);
      n.cidr = toCidr(n.ip, n.prefix);
    }
    wifiInfo(n);
    n.gateway = gw;
    n.isGateway = (!gw.empty() && n.ip == gw);
    out.push_back(n);
  }
  // wifi first, then by name
  std::sort(out.begin(), out.end(), [](const IfaceInfo& a, const IfaceInfo& b) {
    if (a.isWifi != b.isWifi) return a.isWifi;
    return a.name < b.name;
  });
  return out;
}

IfaceInfo primaryIface() {
  auto all = enumerateIfaces();
  for (auto& n : all) if (n.isGateway) return n;
  return all.empty() ? IfaceInfo() : all.front();
}

std::string toCidr(const std::string& ip, int prefix) {
  if (ip.empty()) return "";
  struct in_addr a{};
  if (inet_pton(AF_INET, ip.c_str(), &a) != 1) return ip + "/24";
  uint32_t host = ntohl(a.s_addr);
  uint32_t mask = (prefix <= 0) ? 0 : (prefix >= 32 ? 0xFFFFFFFFu
                                                     : (0xFFFFFFFFu << (32 - prefix)));
  uint32_t net = host & mask;
  struct in_addr n2{};
  n2.s_addr = htonl(net);
  char buf[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &n2, buf, sizeof buf);
  return std::string(buf) + "/" + std::to_string(prefix);
}

bool cidrHas(const std::string& cidr, const std::string& ip) {
  auto parts = split(cidr, '/');
  if (parts.empty()) return false;
  struct in_addr na{}, ia{};
  if (inet_pton(AF_INET, parts[0].c_str(), &na) != 1) return false;
  if (inet_pton(AF_INET, ip.c_str(), &ia) != 1) return false;
  int prefix = parts.size() > 1 ? atoi(parts[1].c_str()) : 24;
  if (prefix < 0) prefix = 0;
  if (prefix > 32) prefix = 32;
  uint32_t mask = prefix == 0 ? 0u : (0xFFFFFFFFu << (32 - prefix));
  return (ntohl(na.s_addr) & mask) == (ntohl(ia.s_addr) & mask);
}

std::vector<std::string> expandHostRange(const std::string& cidr, size_t cap) {
  std::vector<std::string> out;
  auto parts = split(cidr, '/');
  if (parts.empty()) return out;
  struct in_addr a{};
  if (inet_pton(AF_INET, parts[0].c_str(), &a) != 1) return out;
  int prefix = parts.size() > 1 ? atoi(parts[1].c_str()) : 24;
  if (prefix < 8) prefix = 8;
  if (prefix > 30) prefix = 30;
  uint32_t host = ntohl(a.s_addr);
  uint32_t mask = 0xFFFFFFFFu << (32 - prefix);
  uint32_t net = host & mask;
  uint32_t size = 1u << (32 - prefix);
  char buf[INET_ADDRSTRLEN];
  for (uint32_t i = 0; i < size && out.size() < cap; i++) {
    struct in_addr x{};
    x.s_addr = htonl(net + i);
    inet_ntop(AF_INET, &x, buf, sizeof buf);
    out.push_back(buf);
  }
  return out;
}

}  // namespace zs
