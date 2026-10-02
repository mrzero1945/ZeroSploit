// JNI bridge: Java (UI) <-> C++ engine.
//
// Every operation is asynchronous. A native method submits a Job and returns
// its id immediately; results arrive on the Java `Cb.onEvent` callback. The
// callback is invoked from the job's worker thread, so this file owns the
// JVM attach/detach dance and keeps one global ref to the listener.
//
// Callbacks are delivered synchronously from whichever thread produced the
// event, which keeps ordering intact and avoids a queue that could grow without
// bound during a long scan.
#include <jni.h>

#include <android/log.h>

#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "zs.h"

#define LOG_TAG "zerosploit"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace {

JavaVM* g_vm = nullptr;

jobject g_cb = nullptr;          // global ref to com.zerosploit.core.Native$Cb
jclass g_cbClass = nullptr;      // global ref to the same class
jmethodID g_onEvent = nullptr;
std::mutex g_cbMtx;

std::string jstr(JNIEnv* env, jstring s) {
  if (!s) return "";
  const char* c = env->GetStringUTFChars(s, nullptr);
  std::string out = c ? c : "";
  if (c) env->ReleaseStringUTFChars(s, c);
  return out;
}

jstring jnew(JNIEnv* env, const std::string& s) {
  return env->NewStringUTF(s.c_str());
}

std::vector<int> jints(JNIEnv* env, jintArray a) {
  std::vector<int> out;
  if (!a) return out;
  jsize n = env->GetArrayLength(a);
  out.resize((size_t)n);
  if (n > 0) env->GetIntArrayRegion(a, 0, n, (jint*)out.data());
  return out;
}

// Marshals engine events onto the Java listener.
class JavaSink : public zs::EventSink {
 public:
  void onEvent(const zs::Event& e) override {
    JNIEnv* env = nullptr;
    if (!g_vm || !g_onEvent) return;
    bool attached = false;
    if (g_vm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) {
      JavaVMAttachArgs args{JNI_VERSION_1_6, "zs-worker", nullptr};
      if (g_vm->AttachCurrentThread(&env, &args) != JNI_OK) return;
      attached = true;
    }
    jstring jtype = jnew(env, e.type);
    jstring jjson = jnew(env, e.json);
    env->CallVoidMethod(g_cb, g_onEvent, (jint)e.jobId, jtype, jjson);
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (jtype) env->DeleteLocalRef(jtype);
    if (jjson) env->DeleteLocalRef(jjson);
    if (attached) g_vm->DetachCurrentThread();
  }
};

JavaSink g_sink;
bool g_sinkReady = false;

void ensureSink() {
  std::lock_guard<std::mutex> lk(g_cbMtx);
  if (g_sinkReady) return;
  g_sinkReady = true;
  LOGI("engine ready");
}

std::string ifacesJson() {
  auto items = zs::enumerateIfaces();
  // "items" must be a JSON array. The previous version used a Json object and
  // pasted its text straight into the field, so the key held an object (and an
  // unterminated one, since end() was called on the wrapper). The Java side
  // reads it with Json.arr(), got null, and the UI showed zero interfaces.
  std::string body = "[";
  for (size_t k = 0; k < items.size(); k++) {
    auto& i = items[k];
    if (k) body += ",";
    zs::Json o;
    o.obj().key("name").val(i.name).key("ip").val(i.ip).key("netmask").val(i.netmask)
        .key("mac").val(i.mac).key("cidr").val(i.cidr).key("gateway").val(i.gateway)
        .key("bssid").val(i.bssid).key("ssid").val(i.ssid)
        .key("prefix").val((long long)i.prefix).key("isWifi").val(i.isWifi)
        .key("isUp").val(i.isUp).key("hasIp").val(i.ip.empty() ? false : true)
        .key("error").val(i.error).end();
    body += o.str();
  }
  body += "]";
  zs::Json j;
  j.obj().key("count").val((long long)items.size()).key("items").raw(body).end();
  return j.str();
}

std::string rootJson() {
  auto r = zs::probeRoot();
  zs::Json j;
  j.obj().key("available").val(r.available).key("granted").val(r.granted)
      .key("manager").val(r.manager).key("detail").val(r.detail).end();
  return j.str();
}

std::string rawCapsJson(const std::string& iface) {
  auto c = zs::probeRawCaps(iface);
  zs::Json j;
  j.obj().key("iface").val(c.iface).key("packetSocket").val(c.packetSocket)
      .key("rawIpSocket").val(c.rawIpSocket).key("monitorMode").val(c.monitorMode)
      .key("detail").val(c.detail).end();
  return j.str();
}

}  // namespace

extern "C" {

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
  g_vm = vm;
  return JNI_VERSION_1_6;
}

JNIEXPORT void JNICALL Java_com_zerosploit_core_Native_nativeInit(
    JNIEnv* env, jclass, jobject cb, jclass cbInterface, jstring helperPath,
    jstring scratchDir) {
  // ensureSink() locks g_cbMtx itself, so it must run *before* we take the
  // lock here -- taking it first and then calling ensureSink() deadlocked
  // the very first init() on the main thread.
  ensureSink();
  std::lock_guard<std::mutex> lk(g_cbMtx);
  if (g_cb) env->DeleteGlobalRef(g_cb);
  if (g_cbClass) env->DeleteGlobalRef(g_cbClass);
  g_cb = env->NewGlobalRef(cb);
  // Resolve the method on the *interface*, not on the concrete class. With a
  // lambda listener, GetObjectClass() returns a synthetic class that does not
  // declare onEvent with the interface descriptor, so the lookup failed and
  // the pending NoSuchMethodError took the whole process down on the next JNI
  // call. GetMethodID on the interface works for any implementation.
  jclass lookup = cbInterface ? cbInterface : env->GetObjectClass(cb);
  g_cbClass = (jclass)env->NewGlobalRef(lookup);
  // Cb.onEvent(int, String, String) -- the descriptor used to name only two
  // parameters, so the lookup always failed and the pending NoSuchMethodError
  // was then raised at the next JNI call, aborting the process.
  g_onEvent = env->GetMethodID(lookup, "onEvent", "(ILjava/lang/String;Ljava/lang/String;)V");
  if (env->ExceptionCheck() || !g_onEvent) {
    env->ExceptionDescribe();
    env->ExceptionClear();
    g_cb = nullptr;
    g_cbClass = nullptr;
    g_onEvent = nullptr;
    g_sinkReady = false;
    LOGE("nativeInit: could not resolve Cb.onEvent on %s",
         cbInterface ? "Native$Cb" : "the listener's concrete class");
    return;
  }
  if (helperPath) {
    const char* p = env->GetStringUTFChars(helperPath, nullptr);
    zs::setHelperPath(p ? p : "");
    if (p) env->ReleaseStringUTFChars(helperPath, p);
  }
  // runCapture() needs a directory the app process can actually write to.
  if (scratchDir) {
    const char* p = env->GetStringUTFChars(scratchDir, nullptr);
    zs::setScratchDir(p ? p : "");
    if (p) env->ReleaseStringUTFChars(scratchDir, p);
  }
  LOGI("nativeInit: listener bound (helper=%s)", helperPath ? "set" : "unset");
}

JNIEXPORT void JNICALL Java_com_zerosploit_core_Native_nativeShutdown(
    JNIEnv* env, jclass) {
  zs::shutdownHelpers();
  zs::JobManager::get().shutdown();
  std::lock_guard<std::mutex> lk(g_cbMtx);
  if (g_cb && env) env->DeleteGlobalRef(g_cb);
  if (g_cbClass && env) env->DeleteGlobalRef(g_cbClass);
  g_cb = nullptr;
  g_cbClass = nullptr;
  g_onEvent = nullptr;
  g_sinkReady = false;
  LOGI("nativeShutdown: helpers and jobs stopped");
}

JNIEXPORT jint JNICALL Java_com_zerosploit_core_Native_nativeCancel(
    JNIEnv*, jclass, jint id) {
  zs::JobManager::get().cancel(id);
  return 0;
}

JNIEXPORT jint JNICALL Java_com_zerosploit_core_Native_nativeCancelAll(
    JNIEnv*, jclass) {
  zs::JobManager::get().cancelAll();
  return 0;
}

JNIEXPORT jint JNICALL Java_com_zerosploit_core_Native_nativeActiveCount(
    JNIEnv*, jclass) {
  return (jint)zs::JobManager::get().activeCount();
}

// ------------------------------------------------------------ async starters
JNIEXPORT jint JNICALL Java_com_zerosploit_core_Native_nativeNetworkInfo(
    JNIEnv*, jclass) {
  ensureSink();
  return (jint)zs::JobManager::get().submit("network", &g_sink,
                                            [](zs::Job& j) { zs::opNetworkInfo(j); });
}

JNIEXPORT jint JNICALL Java_com_zerosploit_core_Native_nativeDiscover(
    JNIEnv* env, jclass, jstring cidr, jintArray ports, jint timeoutMs,
    jint rounds) {
  ensureSink();
  std::string c = jstr(env, cidr);
  std::vector<int> p = jints(env, ports);
  int t = timeoutMs, r = rounds;
  return (jint)zs::JobManager::get().submit(
      "discover", &g_sink, [c, p, t, r](zs::Job& j) { zs::opDiscover(j, c, p, t, r); });
}

JNIEXPORT jint JNICALL Java_com_zerosploit_core_Native_nativePortScan(
    JNIEnv* env, jclass, jstring host, jint from, jint to, jint timeoutMs,
    jint threads) {
  ensureSink();
  std::string h = jstr(env, host);
  int f = from, t2 = to, tm = timeoutMs, th = threads;
  return (jint)zs::JobManager::get().submit(
      "portscan", &g_sink, [h, f, t2, tm, th](zs::Job& j) {
        zs::opPortScan(j, h, f, t2, tm, th);
      });
}

JNIEXPORT jint JNICALL Java_com_zerosploit_core_Native_nativeTraceroute(
    JNIEnv* env, jclass, jstring host, jint maxHops, jint port, jint timeoutMs,
    jint resolveMs) {
  ensureSink();
  std::string h = jstr(env, host);
  int hops = maxHops, p = port, tm = timeoutMs, rs = resolveMs;
  return (jint)zs::JobManager::get().submit(
      "traceroute", &g_sink, [h, hops, p, tm, rs](zs::Job& j) {
        zs::opTraceroute(j, h, hops, p, tm, rs);
      });
}

JNIEXPORT jint JNICALL Java_com_zerosploit_core_Native_nativeInspect(
    JNIEnv* env, jclass, jstring host, jintArray ports, jint timeoutMs) {
  ensureSink();
  std::string h = jstr(env, host);
  std::vector<int> p = jints(env, ports);
  int t = timeoutMs;
  return (jint)zs::JobManager::get().submit(
      "inspect", &g_sink, [h, p, t](zs::Job& j) { zs::opInspect(j, h, p, t); });
}

JNIEXPORT jint JNICALL Java_com_zerosploit_core_Native_nativeExploits(
    JNIEnv* env, jclass, jstring host, jstring portsCsv) {
  ensureSink();
  std::string h = jstr(env, host), pc = jstr(env, portsCsv);
  return (jint)zs::JobManager::get().submit(
      "exploits", &g_sink,
      [h, pc](zs::Job& j) { zs::opExploits(j, h, pc); });
}

JNIEXPORT jint JNICALL Java_com_zerosploit_core_Native_nativeLoginAudit(
    JNIEnv* env, jclass, jstring host, jint port, jstring profile) {
  ensureSink();
  std::string h = jstr(env, host), pr = jstr(env, profile);
  int pt = port;
  return (jint)zs::JobManager::get().submit(
      "login", &g_sink, [h, pt, pr](zs::Job& j) { zs::opLoginAudit(j, h, pt, pr); });
}

JNIEXPORT jint JNICALL Java_com_zerosploit_core_Native_nativeShell(
    JNIEnv* env, jclass, jstring host, jint port, jstring user, jstring pass) {
  ensureSink();
  std::string h = jstr(env, host), u = jstr(env, user), p = jstr(env, pass);
  int pt = port;
  return (jint)zs::JobManager::get().submit(
      "session", &g_sink,
      [h, pt, u, p](zs::Job& j) { zs::opShell(j, h, pt, u, p); });
}

JNIEXPORT jint JNICALL Java_com_zerosploit_core_Native_nativeMitmStart(
    JNIEnv* env, jclass, jstring iface, jstring targets, jint intervalMs) {
  ensureSink();
  std::string i = jstr(env, iface), t = jstr(env, targets);
  int ms = intervalMs;
  return (jint)zs::JobManager::get().submit(
      "mitm", &g_sink, [i, t, ms](zs::Job& j) { zs::opMitmStart(j, i, t, ms); });
}

JNIEXPORT jint JNICALL Java_com_zerosploit_core_Native_nativeMitmSpoof(
    JNIEnv* env, jclass, jstring iface, jstring targets, jint intervalMs,
    jstring spoofName, jstring spoofIp) {
  ensureSink();
  std::string i = jstr(env, iface), t = jstr(env, targets);
  std::string n = jstr(env, spoofName), ip = jstr(env, spoofIp);
  int ms = intervalMs;
  return (jint)zs::JobManager::get().submit(
      "mitm", &g_sink,
      [i, t, ms, n, ip](zs::Job& j) { zs::opMitmStart(j, i, t, ms, n, ip); });
}

JNIEXPORT jint JNICALL Java_com_zerosploit_core_Native_nativeMitmStop(
    JNIEnv*, jclass) {
  ensureSink();
  return (jint)zs::JobManager::get().submit("mitmstop", &g_sink,
                                            [](zs::Job& j) { zs::opMitmStop(j); });
}

JNIEXPORT jint JNICALL Java_com_zerosploit_core_Native_nativeForge(
    JNIEnv* env, jclass, jstring specCsv) {
  ensureSink();
  std::string s = jstr(env, specCsv);
  return (jint)zs::JobManager::get().submit(
      "forge", &g_sink, [s](zs::Job& j) { zs::opForge(j, s); });
}

JNIEXPORT jint JNICALL Java_com_zerosploit_core_Native_nativeWifiScan(
    JNIEnv* env, jclass, jstring iface) {
  ensureSink();
  std::string i = jstr(env, iface);
  return (jint)zs::JobManager::get().submit(
      "wifi", &g_sink, [i](zs::Job& j) { zs::opWifiScan(j, i); });
}

JNIEXPORT jint JNICALL Java_com_zerosploit_core_Native_nativeDeauth(
    JNIEnv* env, jclass, jstring iface, jstring bssid, jint intervalMs,
    jint count, jstring clientMac, jint freqMhz) {
  ensureSink();
  std::string i = jstr(env, iface), b = jstr(env, bssid);
  std::string c = jstr(env, clientMac);
  int ms = intervalMs, n = count, f = freqMhz;
  return (jint)zs::JobManager::get().submit(
      "deauth", &g_sink, [i, b, ms, n, c, f](zs::Job& j) {
        zs::opDeauth(j, i, b, ms, n, c, f);
      });
}

JNIEXPORT jint JNICALL Java_com_zerosploit_core_Native_nativeRadio(
    JNIEnv* env, jclass, jboolean on) {
  ensureSink();
  bool v = on == JNI_TRUE;
  return (jint)zs::JobManager::get().submit(
      "radio", &g_sink, [v](zs::Job& j) { zs::opRadio(j, v); });
}

JNIEXPORT jint JNICALL Java_com_zerosploit_core_Native_nativeStaList(
    JNIEnv* env, jclass, jstring iface, jstring bssid, jint freqMhz,
    jint listenMs) {
  ensureSink();
  std::string i = jstr(env, iface), b = jstr(env, bssid);
  int ms = listenMs, f = freqMhz;
  return (jint)zs::JobManager::get().submit(
      "sta", &g_sink, [i, b, f, ms](zs::Job& j) { zs::opStaList(j, i, b, f, ms); });
}

JNIEXPORT jint JNICALL Java_com_zerosploit_core_Native_nativeMonitor(
    JNIEnv* env, jclass, jstring iface, jboolean on) {
  ensureSink();
  std::string i = jstr(env, iface);
  bool v = on == JNI_TRUE;
  return (jint)zs::JobManager::get().submit(
      "monitor", &g_sink, [i, v](zs::Job& j) { zs::opMonitorMode(j, i, v); });
}

JNIEXPORT jint JNICALL Java_com_zerosploit_core_Native_nativeCapabilities(
    JNIEnv*, jclass) {
  ensureSink();
  return (jint)zs::JobManager::get().submit(
      "caps", &g_sink, [](zs::Job& j) { zs::opCapabilities(j); });
}

// ------------------------------------------------------------- sync queries
// Used by the UI for state it needs immediately (root status, Magisk info,
// interface list) without spinning up a job.
JNIEXPORT jstring JNICALL Java_com_zerosploit_core_Native_nativeSync(
    JNIEnv* env, jclass, jstring op, jstring arg) {
  std::string o = jstr(env, op), a = jstr(env, arg);
  if (o == "root") return jnew(env, rootJson());
  if (o == "ifaces") return jnew(env, ifacesJson());
  if (o == "magisk") return jnew(env, zs::trim(zs::opMagiskInfo()));
  if (o == "rawcaps") return jnew(env, rawCapsJson(a));
  if (o == "sessions") return jnew(env, zs::sessionJson());
  if (o == "primary") {
    auto p = zs::primaryIface();
    zs::Json j;
    j.obj().key("name").val(p.name).key("ip").val(p.ip).key("cidr").val(p.cidr)
        .key("mac").val(p.mac).key("gateway").val(p.gateway).end();
    return jnew(env, j.str());
  }
  return jnew(env, "{\"error\":\"unknown op " + o + "\"}");
}

}  // extern "C"
