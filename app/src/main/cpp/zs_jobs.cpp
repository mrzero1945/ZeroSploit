// Job lifecycle: one detached thread per operation, cooperative cancellation,
// events fanned out to the EventSink.
#include "zs.h"

#include <algorithm>
#include <chrono>

namespace zs {

Job::Job(int id, std::string kind, EventSink* sink)
    : id_(id), kind_(std::move(kind)), sink_(sink) {}

Job::~Job() {
  // The worker thread captures `this`, so we must never let the object die
  // underneath it. Ask it to stop and wait it out.
  stop_.store(true);
  if (th_.joinable()) th_.join();
}

void Job::run(std::function<void(Job&)> body) {
  th_ = std::thread([this, body] {
    body(*this);
    emit("done", Json().obj().key("jobId").val(id_).key("kind").val(kind_)
                   .end().str());
    finished_.store(true);
  });
}

void Job::stop() {
  if (stop_.exchange(true)) return;   // only announce once
  emit("stopping", Json().obj().key("jobId").val(id_).end().str());
}

void Job::log(const char* level, const std::string& tag,
              const std::string& msg) {
  Json j;
  j.obj().key("t").val(nowClock()).key("level").val(level).key("tag").val(tag)
   .key("msg").val(msg).end();
  emit("log", j.str());
}

void Job::emit(const std::string& type, const std::string& json) {
  if (sink_) sink_->onEvent(Event{id_, type, json});
}

void Job::progress(const std::string& phase, double pct, const std::string& extra) {
  Json j;
  j.obj().key("jobId").val(id_).key("phase").val(phase).key("pct").val(pct);
  if (!extra.empty()) j.key("extra").val(extra);
  j.end();
  emit("progress", j.str());
}

// ---------------------------------------------------------------- manager
JobManager& JobManager::get() {
  static JobManager m;
  return m;
}

int JobManager::submit(const std::string& kind, EventSink* sink,
                       std::function<void(Job&)> body) {
  reap();
  int id = next_++;
  auto job = std::make_shared<Job>(id, kind, sink);
  {
    std::lock_guard<std::mutex> lk(m_);
    jobs_[id] = job;
  }
  job->run(std::move(body));
  return id;
}

void JobManager::reap() {
  std::vector<int> done;
  {
    std::lock_guard<std::mutex> lk(m_);
    for (auto& kv : jobs_)
      if (kv.second->finished()) done.push_back(kv.first);
  }
  if (done.empty()) return;
  std::lock_guard<std::mutex> lk(m_);
  for (int id : done) jobs_.erase(id);   // destructor joins an already-dead thread
}

void JobManager::cancel(int id) {
  std::shared_ptr<Job> j;
  {
    std::lock_guard<std::mutex> lk(m_);
    auto it = jobs_.find(id);
    if (it == jobs_.end()) return;
    j = it->second;
  }
  j->stop();                              // do not join here: keep the UI thread free
}

void JobManager::cancelAll() {
  std::vector<std::shared_ptr<Job>> all;
  {
    std::lock_guard<std::mutex> lk(m_);
    for (auto& kv : jobs_) all.push_back(kv.second);
  }
  for (auto& j : all) j->stop();
}

bool JobManager::active() const { return activeCount() > 0; }

int JobManager::activeCount() const {
  std::lock_guard<std::mutex> lk(const_cast<std::mutex&>(m_));
  int n = 0;
  for (auto& kv : jobs_) if (!kv.second->finished()) n++;
  return n;
}

void JobManager::shutdown() {
  std::vector<std::shared_ptr<Job>> all;
  {
    std::lock_guard<std::mutex> lk(m_);
    for (auto& kv : jobs_) all.push_back(kv.second);
  }
  for (auto& j : all) j->stop();
  for (auto& j : all) {
    if (j->finished()) continue;
    // bounded wait so process teardown cannot hang
    for (int i = 0; i < 200 && !j->finished(); i++)
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  std::lock_guard<std::mutex> lk(m_);
  jobs_.clear();
}

}  // namespace zs
