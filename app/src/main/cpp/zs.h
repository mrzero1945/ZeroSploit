// ZeroSploit native engine — public interface.
//
// Threading model
//   * every long-running operation is a `Job` owned by the JobManager
//   * jobs run on their own std::thread and stream `Event` records back to
//     Java through an EventSink, which the JNI layer marshals onto a
//     JavaVM-attached thread
//   * cancellation is cooperative (atomic flag polled between units of work)
//
// Privilege model
//   * passive/active-but-unprivileged work (interface discovery, TCP connect
//     scanning, banner grabbing, version fingerprinting, credential auditing)
//     works on any device
//   * anything needing AF_PACKET / AF_INET raw sockets or 802.11 monitor mode
//     (MITM, packet forging, deauth) is gated behind an explicit root check and
//     reports a clear reason when it is unavailable
#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace zs {

// ---------------------------------------------------------------- utilities
std::string jsonEscape(const std::string& s);
std::string nowIso8601();
std::string nowClock();
std::string trim(const std::string& s);
std::string lower(std::string s);
std::string upper(std::string s);
bool startsWith(const std::string& s, const std::string& p);
bool contains(const std::string& s, const std::string& p);
// True when the string is non-empty and every character is a decimal digit.
// Used wherever a value is about to be parsed as a number, so that junk is
// rejected up front instead of being silently read as zero by atoi().
bool allDigits(const std::string& s);
std::vector<std::string> split(const std::string& s, char sep);
std::string join(const std::vector<std::string>& v, const std::string& sep);
std::string urlDecode(const std::string& s);

class Json {
 public:
  Json& key(const std::string& k);
  Json& val(const std::string& v);
  // Required: a string literal would otherwise bind to val(bool), because the
  // pointer->bool standard conversion outranks the user-defined conversion to
  // std::string, so val("open") silently emitted `true`.
  Json& val(const char* v) { return val(std::string(v ? v : "")); }
  // Without the exact-width overloads below, an `int` argument is ambiguous:
  // int -> long long, int -> double and int -> bool are all standard
  // conversions of the same rank, so no overload wins.
  Json& val(int v) { return val(static_cast<long long>(v)); }
  Json& val(unsigned v) { return val(static_cast<long long>(v)); }
  Json& val(long v) { return val(static_cast<long long>(v)); }
  Json& val(unsigned long v) { return val(static_cast<long long>(v)); }
  Json& val(long long v);
  Json& val(double v);
  Json& val(bool v);
  Json& raw(const std::string& v);
  Json& null();
  Json& obj();   // opens a nested object
  Json& end();   // closes it
  const std::string& str() const { return s_; }
  void reset() { s_.clear(); }

 private:
  std::string s_;
  int depth_ = 0;
  bool needComma_ = false;
  void sep();
};

std::string jstr(const std::string& s);
std::string jnum(long long v);

// ------------------------------------------------------------------ netinfo
struct IfaceInfo {
  std::string name;
  std::string ip;         // dotted quad
  std::string netmask;
  std::string mac;
  std::string cidr;       // 192.168.1.0/24
  std::string gateway;    // dotted quad, empty if none
  std::string bssid;      // wifi AP mac, if wifi
  std::string ssid;
  int prefix = 24;
  bool isWifi = false;
  bool isUp = false;
  bool isGateway = false;   // this interface holds the default route
  std::string error;      // non-empty if the interface could not be read
};

std::vector<IfaceInfo> enumerateIfaces();
IfaceInfo primaryIface();
std::string toCidr(const std::string& ip, int prefix);
std::vector<std::string> expandHostRange(const std::string& cidr, size_t cap);
/** True when ip sits inside cidr; used to keep a second-chance ARP pass scoped. */
bool cidrHas(const std::string& cidr, const std::string& ip);

// ------------------------------------------------------------------- root
struct RootStatus {
  bool available = false;
  bool granted = false;
  std::string manager;    // magisk / supersu / apatch / none
  std::string detail;
};
RootStatus probeRoot();
std::string execRoot(const std::string& cmd, int timeoutMs = 5000);

// --------------------------------------------------------------- discovered
enum DevKind { DEV_ROUTER, DEV_SERVER, DEV_PHONE, DEV_LAPTOP, DEV_PRINTER,
               DEV_TV, DEV_CAMERA, DEV_IOT, DEV_UNKNOWN };

struct Device {
  std::string ip;
  std::string mac;          // from the kernel ARP table when readable
  std::string vendor;       // OUI lookup
  std::string hostname;     // reverse DNS / mDNS
  std::string kind = "unknown";
  std::string firstSeen;
  std::string lastSeen;
  std::vector<int> openPorts;
  bool isGateway = false;
  bool alive = false;
  std::string source;       // arp / tcp / udp / cache
  bool isWifi = false;      // seen on an 802.11 interface (bssid below)
  std::string bssid;        // AP this device was seen through
  double rttMs = 0;
};

// ------------------------------------------------------------------- ports
enum PortState { PS_CLOSED, PS_OPEN, PS_FILTERED };

struct PortEntry {
  int port = 0;
  PortState state = PS_CLOSED;
  std::string service;      // from the port table
  std::string banner;       // raw banner text
  std::string product;
  std::string version;
  double rttMs = 0;
};

// ------------------------------------------------------------------ service
struct ServiceInfo {
  int port = 0;
  std::string name;         // ssh, http, smb ...
  std::string product;      // OpenSSH
  std::string version;      // 8.4p1
  std::string extra;
  std::string banner;
  std::string os;           // best-effort OS guess
  std::string enc;          // tls info when applicable
  std::string confidence;   // high / medium / low
};

ServiceInfo fingerprint(int port, const std::string& banner, const std::string& tls);
std::string serviceForPort(int port);
std::vector<ServiceInfo> inspectAll(const std::string& host,
                                    const std::vector<PortEntry>& ports,
                                    int timeoutMs, const std::function<void(
                                        const ServiceInfo&)>& onEach);

// -------------------------------------------------------------------- CVE
struct Finding {
  std::string cve;
  std::string product;
  std::string title;
  std::string severity;     // CRITICAL / HIGH / MEDIUM / LOW / INFO
  double cvss = 0;
  std::string portRef;      // "22"
  std::string evidence;     // detected version
  std::string remedy;
  std::string cwe;
};
std::vector<Finding> matchCves(const std::string& host,
                               const std::vector<ServiceInfo>& services);

// ------------------------------------------------------------------- audit
struct CredResult {
  std::string user;
  std::string pass;
  bool accepted = false;
  std::string service;
  double rttMs = 0;
  std::string note;
};

// ------------------------------------------------------------------ session
struct SessionInfo {
  int id = 0;
  std::string target;
  std::string proto;        // telnet / ssh / http
  std::string user;
  std::string priv;         // root / admin / guest
  int64_t startedAt = 0;
  int64_t uptimeSec = 0;
  std::string state;        // live / closed
};

// ------------------------------------------------------------------ trace
struct TraceHop {
  int ttl = 0;
  std::string addr;      // empty when the hop did not answer
  std::string name;      // reverse DNS, empty when there is no PTR record
  double rttMs = 0;
  bool reached = false;  // the destination itself answered, not a router
};

// ----------------------------------------------------------------- raw net
struct RawCaps {
  bool packetSocket = false;   // AF_PACKET available
  bool rawIpSocket = false;    // AF_INET SOCK_RAW available
  bool monitorMode = false;    // current wifi iface is in monitor mode
  std::string iface;
  std::string detail;
};
RawCaps probeRawCaps(const std::string& iface);


struct MitmTarget {
  std::string ip;
  std::string mac;
  std::string victim;      // usually the default gateway
};
struct CraftSpec {
  int type = 0;            // 0 tcp 1 udp 2 icmp 3 arp 4 80211
  std::string srcMac, dstMac, bssid;
  std::string srcIp, dstIp;
  int sport = 0, dport = 0;
  int seq = 0, ack = 0;
  int flags = 0x02;        // tcp flags
  std::string payload;
  int reasonCode = 7;
  int durationSec = 10;
  int count = 1;
  int pps = 50;
  std::string channel;
};

// ------------------------------------------------------------------- events
struct Event {
  int jobId;
  std::string type;        // log / progress / device / port / service / ...
  std::string json;
};

class EventSink {
 public:
  virtual ~EventSink() = default;
  virtual void onEvent(const Event& e) = 0;
};

class Job {
 public:
  Job(int id, std::string kind, EventSink* sink);
  ~Job();
  void run(std::function<void(Job&)> body);
  void stop();
  bool isStop() const { return stop_.load(); }
  bool finished() const { return finished_.load(); }
  int id() const { return id_; }
  const std::string& kind() const { return kind_; }

  // helpers available to job bodies
  void log(const char* level, const std::string& tag, const std::string& msg);
  void emit(const std::string& type, const std::string& json);
  void progress(const std::string& phase, double pct, const std::string& extra = "");

 private:
  int id_;
  std::string kind_;
  EventSink* sink_;
  std::atomic<bool> stop_{false};
  std::atomic<bool> finished_{false};
  std::thread th_;
};

class JobManager {
 public:
  static JobManager& get();
  int submit(const std::string& kind, EventSink* sink,
             std::function<void(Job&)> body);
  void cancel(int id);
  void cancelAll();
  bool active() const;
  int activeCount() const;
  void reap();
  void shutdown();

 private:
  std::mutex m_;
  std::unordered_map<int, std::shared_ptr<Job>> jobs_;
  std::atomic<int> next_{1};
};

// ---------------------------------------------------------------- operations
// Each of these is designed to be used as a Job body.
void opNetworkInfo(Job& j);
void opDiscover(Job& j, const std::string& cidr, const std::vector<int>& ports,
                int timeoutMs, int rounds);
void opPortScan(Job& j, const std::string& host, int from, int to,
                int timeoutMs, int threads);
// UDP traceroute. `maxHops` caps the TTL, `port` is the closed port the probes
// aim at (the destination's ICMP port-unreachable is what ends the trace),
// `timeoutMs` per hop and `resolveMs` the reverse-DNS budget per hop (0 skips
// name resolution entirely).
void opTraceroute(Job& j, const std::string& host, int maxHops, int port,
                  int timeoutMs, int resolveMs);
void opInspect(Job& j, const std::string& host, const std::vector<int>& ports,
               int timeoutMs);
void opExploits(Job& j, const std::string& host, const std::string& portsCsv);
void opLoginAudit(Job& j, const std::string& host, int port,
                  const std::string& profile);
void opShell(Job& j, const std::string& host, int port, const std::string& user,
             const std::string& pass);
// spoofName/spoofIp are optional and only carry DNS-spoofing config. Spoofing
// rides on the same ARP poisoning because a resolver the victim does not
// believe is the gateway never gets asked a question worth answering.
void opMitmStart(Job& j, const std::string& iface, const std::string& targetsCsv,
                 int intervalMs, const std::string& spoofName = std::string(),
                 const std::string& spoofIp = std::string());
void opMitmStop(Job& j);
void opForge(Job& j, const std::string& specCsv);
void opWifiScan(Job& j, const std::string& iface);
// `clientMac` narrows a monitor-mode run to one station of `bssid`; empty means
// the broadcast deauth that reaches every client of that access point.
// `freqMhz` is the centre frequency `bssid` is on; a monitor radio handles one
// channel at a time, so 0 leaves the run likely to transmit into empty air.
void opDeauth(Job& j, const std::string& iface, const std::string& bssid,
              int intervalMs, int count, const std::string& clientMac, int freqMhz);
// `bssid` selects which access point to watch; required unless `iface` is a
// soft AP, which answers from hostapd instead. `listenMs` is how long the
// monitor-mode path listens before reporting, `freqMhz` which frequency.
void opStaList(Job& j, const std::string& iface, const std::string& bssid,
               int freqMhz, int listenMs);
void opRadio(Job& j, bool on);
void opCapabilities(Job& j);

// Root-gated helper process management (see zs_raw.cpp). The helper is a
// separate executable, unpacked from assets into the app's files dir and
// launched through Magisk's `su`, because `su` starts a new root process and
// cannot elevate the app process.
void setHelperPath(const std::string& path);

// Directory the app process may write to. runCapture() used to redirect into
// a hardcoded /data/data/com.zerosploit/tmp_exec, which does not exist for the
// debug applicationId, so every system() call failed and su was never run.
void setScratchDir(std::string dir);
void opMonitorMode(Job& j, const std::string& iface, bool on);
void shutdownHelpers();
std::string opMagiskInfo();

// session registry (process-wide)
int addSession(const SessionInfo& s);
void updateSession(int id, const std::string& state);
std::vector<SessionInfo> listSessions();
std::string sessionJson();
int64_t nowMs();

}  // namespace zs
