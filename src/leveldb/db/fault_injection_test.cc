// Copyright 2014 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.

// This test uses a custom Env to keep track of the state of a filesystem as of
// the last "sync". It then checks for data loss errors by purposely dropping
// file data (or entire files) not protected by a "sync".

#include <map>
#include <set>
// SYSCOIN BEGIN: Exercise a durability barrier while old WAL work is pending.
#include <atomic>
#include <thread>
#include <utility>
#include <vector>
// SYSCOIN END: Exercise a durability barrier while old WAL work is pending.

#include "db/db_impl.h"
#include "db/filename.h"
#include "db/log_format.h"
#include "db/version_set.h"
#include "leveldb/cache.h"
#include "leveldb/db.h"
#include "leveldb/env.h"
#include "leveldb/table.h"
#include "leveldb/write_batch.h"
#include "port/port.h"
#include "port/thread_annotations.h"
#include "util/logging.h"
#include "util/mutexlock.h"
#include "util/testharness.h"
#include "util/testutil.h"

namespace leveldb {

static const int kValueSize = 1000;
static const int kMaxNumValues = 2000;
static const size_t kNumIterations = 3;

class FaultInjectionTestEnv;

namespace {

// Assume a filename, and not a directory name like "/foo/bar/"
static std::string GetDirName(const std::string& filename) {
  size_t found = filename.find_last_of("/\\");
  if (found == std::string::npos) {
    return "";
  } else {
    return filename.substr(0, found);
  }
}

Status SyncDir(const std::string& dir) {
  // As this is a test it isn't required to *actually* sync this directory.
  return Status::OK();
}

// A basic file truncation function suitable for this test.
Status Truncate(const std::string& filename, uint64_t length) {
  leveldb::Env* env = leveldb::Env::Default();

  SequentialFile* orig_file;
  Status s = env->NewSequentialFile(filename, &orig_file);
  if (!s.ok()) return s;

  char* scratch = new char[length];
  leveldb::Slice result;
  s = orig_file->Read(length, &result, scratch);
  delete orig_file;
  if (s.ok()) {
    std::string tmp_name = GetDirName(filename) + "/truncate.tmp";
    WritableFile* tmp_file;
    s = env->NewWritableFile(tmp_name, &tmp_file);
    if (s.ok()) {
      s = tmp_file->Append(result);
      delete tmp_file;
      if (s.ok()) {
        s = env->RenameFile(tmp_name, filename);
      } else {
        env->DeleteFile(tmp_name);
      }
    }
  }

  delete[] scratch;

  return s;
}

struct FileState {
  std::string filename_;
  int64_t pos_;
  int64_t pos_at_last_sync_;
  int64_t pos_at_last_flush_;

  FileState(const std::string& filename)
      : filename_(filename),
        pos_(-1),
        pos_at_last_sync_(-1),
        pos_at_last_flush_(-1) {}

  FileState() : pos_(-1), pos_at_last_sync_(-1), pos_at_last_flush_(-1) {}

  bool IsFullySynced() const { return pos_ <= 0 || pos_ == pos_at_last_sync_; }

  Status DropUnsyncedData() const;
};

}  // anonymous namespace

// A wrapper around WritableFile which informs another Env whenever this file
// is written to or sync'ed.
class TestWritableFile : public WritableFile {
 public:
  TestWritableFile(const FileState& state, WritableFile* f,
                   FaultInjectionTestEnv* env);
  ~TestWritableFile() override;
  Status Append(const Slice& data) override;
  Status Close() override;
  Status Flush() override;
  Status Sync() override;
  std::string GetName() const override { return ""; }

 private:
  FileState state_;
  WritableFile* target_;
  bool writable_file_opened_;
  FaultInjectionTestEnv* env_;

  Status SyncParent();
};

class FaultInjectionTestEnv : public EnvWrapper {
 public:
  FaultInjectionTestEnv()
      : EnvWrapper(Env::Default()), filesystem_active_(true) {}
  ~FaultInjectionTestEnv() override = default;
  Status NewWritableFile(const std::string& fname,
                         WritableFile** result) override;
  Status NewAppendableFile(const std::string& fname,
                           WritableFile** result) override;
  Status DeleteFile(const std::string& f) override;
  Status RenameFile(const std::string& s, const std::string& t) override;

  // SYSCOIN: Include open, synced files when snapshotting durable bytes.
  void RecordFileState(const FileState& state);
  Status DropUnsyncedFileData();
  Status DeleteFilesCreatedAfterLastDirSync();
  void DirWasSynced();
  bool IsFileCreatedSinceLastDirSync(const std::string& filename);
  void ResetState();
  void UntrackFile(const std::string& f);
  // SYSCOIN BEGIN: Control compaction and copy only power-loss-surviving bytes.
  void Schedule(void (*function)(void*), void* arg) override;
  void SetBackgroundPaused(bool paused);
  bool HasDeferredBackgroundWork();
  bool HasUnsyncedLogData();
  Status CreateDurableSnapshot(const std::string& source,
                              const std::string& destination);
  std::atomic<bool> fail_log_sync_{false};
  // SYSCOIN END: Control compaction and copy only power-loss-surviving bytes.
  // Setting the filesystem to inactive is the test equivalent to simulating a
  // system reset. Setting to inactive will freeze our saved filesystem state so
  // that it will stop being recorded. It can then be reset back to the state at
  // the time of the reset.
  bool IsFilesystemActive() LOCKS_EXCLUDED(mutex_) {
    MutexLock l(&mutex_);
    return filesystem_active_;
  }
  void SetFilesystemActive(bool active) LOCKS_EXCLUDED(mutex_) {
    MutexLock l(&mutex_);
    filesystem_active_ = active;
  }

 private:
  port::Mutex mutex_;
  std::map<std::string, FileState> db_file_state_ GUARDED_BY(mutex_);
  std::set<std::string> new_files_since_last_dir_sync_ GUARDED_BY(mutex_);
  bool filesystem_active_ GUARDED_BY(mutex_);  // Record flushes, syncs, writes
  // SYSCOIN BEGIN: Hold immutable memtable compaction until the test releases it.
  bool background_paused_ GUARDED_BY(mutex_) = false;
  std::vector<std::pair<void (*)(void*), void*>> deferred_background_
      GUARDED_BY(mutex_);
  // SYSCOIN END: Hold immutable memtable compaction until the test releases it.
};

TestWritableFile::TestWritableFile(const FileState& state, WritableFile* f,
                                   FaultInjectionTestEnv* env)
    : state_(state), target_(f), writable_file_opened_(true), env_(env) {
  assert(f != nullptr);
}

TestWritableFile::~TestWritableFile() {
  if (writable_file_opened_) {
    Close();
  }
  delete target_;
}

Status TestWritableFile::Append(const Slice& data) {
  Status s = target_->Append(data);
  if (s.ok() && env_->IsFilesystemActive()) {
    state_.pos_ += data.size();
  }
  return s;
}

Status TestWritableFile::Close() {
  writable_file_opened_ = false;
  Status s = target_->Close();
  if (s.ok()) {
    env_->RecordFileState(state_);  // SYSCOIN: shared with live durability snapshots.
  }
  return s;
}

Status TestWritableFile::Flush() {
  Status s = target_->Flush();
  if (s.ok() && env_->IsFilesystemActive()) {
    state_.pos_at_last_flush_ = state_.pos_;
  }
  return s;
}

Status TestWritableFile::SyncParent() {
  Status s = SyncDir(GetDirName(state_.filename_));
  if (s.ok()) {
    env_->DirWasSynced();
  }
  return s;
}

Status TestWritableFile::Sync() {
  if (!env_->IsFilesystemActive()) {
    return Status::OK();
  }
  // SYSCOIN BEGIN: Inject a real WAL sync failure at the storage boundary.
  if (env_->fail_log_sync_.load(std::memory_order_acquire) &&
      state_.filename_.size() >= 4 &&
      state_.filename_.compare(state_.filename_.size() - 4, 4, ".log") == 0) {
    return Status::IOError("injected WAL sync failure");
  }
  // SYSCOIN END: Inject a real WAL sync failure at the storage boundary.
  // Ensure new files referred to by the manifest are in the filesystem.
  Status s = target_->Sync();
  if (s.ok()) {
    state_.pos_at_last_sync_ = state_.pos_;
  }
  if (env_->IsFileCreatedSinceLastDirSync(state_.filename_)) {
    Status ps = SyncParent();
    if (s.ok() && !ps.ok()) {
      s = ps;
    }
  }
  // SYSCOIN: A live snapshot must know the durable prefix of the active WAL too.
  if (s.ok()) env_->RecordFileState(state_);
  return s;
}

Status FaultInjectionTestEnv::NewWritableFile(const std::string& fname,
                                              WritableFile** result) {
  WritableFile* actual_writable_file;
  Status s = target()->NewWritableFile(fname, &actual_writable_file);
  if (s.ok()) {
    FileState state(fname);
    state.pos_ = 0;
    *result = new TestWritableFile(state, actual_writable_file, this);
    // NewWritableFile doesn't append to files, so if the same file is
    // opened again then it will be truncated - so forget our saved
    // state.
    UntrackFile(fname);
    MutexLock l(&mutex_);
    new_files_since_last_dir_sync_.insert(fname);
  }
  return s;
}

Status FaultInjectionTestEnv::NewAppendableFile(const std::string& fname,
                                                WritableFile** result) {
  WritableFile* actual_writable_file;
  Status s = target()->NewAppendableFile(fname, &actual_writable_file);
  if (s.ok()) {
    FileState state(fname);
    state.pos_ = 0;
    {
      MutexLock l(&mutex_);
      if (db_file_state_.count(fname) == 0) {
        new_files_since_last_dir_sync_.insert(fname);
      } else {
        state = db_file_state_[fname];
      }
    }
    *result = new TestWritableFile(state, actual_writable_file, this);
  }
  return s;
}

Status FaultInjectionTestEnv::DropUnsyncedFileData() {
  Status s;
  MutexLock l(&mutex_);
  for (const auto& kvp : db_file_state_) {
    if (!s.ok()) {
      break;
    }
    const FileState& state = kvp.second;
    if (!state.IsFullySynced()) {
      s = state.DropUnsyncedData();
    }
  }
  return s;
}

void FaultInjectionTestEnv::DirWasSynced() {
  MutexLock l(&mutex_);
  new_files_since_last_dir_sync_.clear();
}

bool FaultInjectionTestEnv::IsFileCreatedSinceLastDirSync(
    const std::string& filename) {
  MutexLock l(&mutex_);
  return new_files_since_last_dir_sync_.find(filename) !=
         new_files_since_last_dir_sync_.end();
}

void FaultInjectionTestEnv::UntrackFile(const std::string& f) {
  MutexLock l(&mutex_);
  db_file_state_.erase(f);
  new_files_since_last_dir_sync_.erase(f);
}

Status FaultInjectionTestEnv::DeleteFile(const std::string& f) {
  Status s = EnvWrapper::DeleteFile(f);
  ASSERT_OK(s);
  if (s.ok()) {
    UntrackFile(f);
  }
  return s;
}

Status FaultInjectionTestEnv::RenameFile(const std::string& s,
                                         const std::string& t) {
  Status ret = EnvWrapper::RenameFile(s, t);

  if (ret.ok()) {
    MutexLock l(&mutex_);
    if (db_file_state_.find(s) != db_file_state_.end()) {
      db_file_state_[t] = db_file_state_[s];
      db_file_state_.erase(s);
    }

    if (new_files_since_last_dir_sync_.erase(s) != 0) {
      assert(new_files_since_last_dir_sync_.find(t) ==
             new_files_since_last_dir_sync_.end());
      new_files_since_last_dir_sync_.insert(t);
    }
  }

  return ret;
}

void FaultInjectionTestEnv::ResetState() {
  // Since we are not destroying the database, the existing files
  // should keep their recorded synced/flushed state. Therefore
  // we do not reset db_file_state_ and new_files_since_last_dir_sync_.
  SetFilesystemActive(true);
}

Status FaultInjectionTestEnv::DeleteFilesCreatedAfterLastDirSync() {
  // Because DeleteFile access this container make a copy to avoid deadlock
  mutex_.Lock();
  std::set<std::string> new_files(new_files_since_last_dir_sync_.begin(),
                                  new_files_since_last_dir_sync_.end());
  mutex_.Unlock();
  Status status;
  for (const auto& new_file : new_files) {
    Status delete_status = DeleteFile(new_file);
    if (!delete_status.ok() && status.ok()) {
      status = std::move(delete_status);
    }
  }
  return status;
}

// SYSCOIN: Capture file state both when a file closes and when it is synced.
void FaultInjectionTestEnv::RecordFileState(const FileState& state) {
  MutexLock l(&mutex_);
  db_file_state_[state.filename_] = state;
}

// SYSCOIN BEGIN: Deterministic power-loss snapshots with paused compaction.
void FaultInjectionTestEnv::Schedule(void (*function)(void*), void* arg) {
  {
    MutexLock l(&mutex_);
    if (background_paused_) {
      deferred_background_.emplace_back(function, arg);
      return;
    }
  }
  target()->Schedule(function, arg);
}

void FaultInjectionTestEnv::SetBackgroundPaused(bool paused) {
  std::vector<std::pair<void (*)(void*), void*>> pending;
  {
    MutexLock l(&mutex_);
    background_paused_ = paused;
    if (!paused) pending.swap(deferred_background_);
  }
  for (const auto& job : pending) target()->Schedule(job.first, job.second);
}

bool FaultInjectionTestEnv::HasDeferredBackgroundWork() {
  MutexLock l(&mutex_);
  return !deferred_background_.empty();
}

bool FaultInjectionTestEnv::HasUnsyncedLogData() {
  MutexLock l(&mutex_);
  for (const auto& file : db_file_state_) {
    uint64_t number;
    FileType type;
    const std::string basename = file.first.substr(file.first.find_last_of("/\\") + 1);
    if (ParseFileName(basename, &number, &type) && type == kLogFile &&
        !file.second.IsFullySynced()) {
      return true;
    }
  }
  return false;
}

Status FaultInjectionTestEnv::CreateDurableSnapshot(
    const std::string& source, const std::string& destination) {
  std::map<std::string, FileState> states;
  {
    MutexLock l(&mutex_);
    states = db_file_state_;
  }
  Status status = target()->CreateDir(destination);
  if (!status.ok()) return status;
  std::vector<std::string> children;
  status = target()->GetChildren(source, &children);
  if (!status.ok()) return status;
  for (const auto& child : children) {
    uint64_t number;
    FileType type;
    if (!ParseFileName(child, &number, &type) ||
        (type != kLogFile && type != kTableFile &&
         type != kDescriptorFile && type != kCurrentFile)) {
      continue;
    }
    const std::string filename = source + "/" + child;
    const auto state = states.find(filename);
    // An unsynced new file has no durable content to copy.
    if (state == states.end() || state->second.pos_at_last_sync_ < 0) continue;
    std::string contents;
    status = ReadFileToString(target(), filename, &contents);
    if (!status.ok()) return status;
    const size_t durable_bytes =
        static_cast<size_t>(state->second.pos_at_last_sync_);
    if (durable_bytes > contents.size()) {
      return Status::Corruption("durable prefix exceeds file size");
    }
    contents.resize(durable_bytes);
    status = WriteStringToFile(target(), contents, destination + "/" + child);
    if (!status.ok()) return status;
  }
  return Status::OK();
}
// SYSCOIN END: Deterministic power-loss snapshots with paused compaction.

Status FileState::DropUnsyncedData() const {
  int64_t sync_pos = pos_at_last_sync_ == -1 ? 0 : pos_at_last_sync_;
  return Truncate(filename_, sync_pos);
}

class FaultInjectionTest {
 public:
  enum ExpectedVerifResult { VAL_EXPECT_NO_ERROR, VAL_EXPECT_ERROR };
  enum ResetMethod { RESET_DROP_UNSYNCED_DATA, RESET_DELETE_UNSYNCED_FILES };

  FaultInjectionTestEnv* env_;
  std::string dbname_;
  Cache* tiny_cache_;
  Options options_;
  DB* db_;

  FaultInjectionTest()
      : env_(new FaultInjectionTestEnv),
        tiny_cache_(NewLRUCache(100)),
        db_(nullptr) {
    dbname_ = test::TmpDir() + "/fault_test";
    DestroyDB(dbname_, Options());  // Destroy any db from earlier run
    options_.reuse_logs = true;
    options_.env = env_;
    options_.paranoid_checks = true;
    options_.block_cache = tiny_cache_;
    options_.create_if_missing = true;
  }

  ~FaultInjectionTest() {
    CloseDB();
    DestroyDB(dbname_, Options());
    delete tiny_cache_;
    delete env_;
  }

  void ReuseLogs(bool reuse) { options_.reuse_logs = reuse; }

  void Build(int start_idx, int num_vals) {
    std::string key_space, value_space;
    WriteBatch batch;
    for (int i = start_idx; i < start_idx + num_vals; i++) {
      Slice key = Key(i, &key_space);
      batch.Clear();
      batch.Put(key, Value(i, &value_space));
      WriteOptions options;
      ASSERT_OK(db_->Write(options, &batch));
    }
  }

  Status ReadValue(int i, std::string* val) const {
    std::string key_space, value_space;
    Slice key = Key(i, &key_space);
    Value(i, &value_space);
    ReadOptions options;
    return db_->Get(options, key, val);
  }

  Status Verify(int start_idx, int num_vals,
                ExpectedVerifResult expected) const {
    std::string val;
    std::string value_space;
    Status s;
    for (int i = start_idx; i < start_idx + num_vals && s.ok(); i++) {
      Value(i, &value_space);
      s = ReadValue(i, &val);
      if (expected == VAL_EXPECT_NO_ERROR) {
        if (s.ok()) {
          ASSERT_EQ(value_space, val);
        }
      } else if (s.ok()) {
        fprintf(stderr, "Expected an error at %d, but was OK\n", i);
        s = Status::IOError(dbname_, "Expected value error:");
      } else {
        s = Status::OK();  // An expected error
      }
    }
    return s;
  }

  // Return the ith key
  Slice Key(int i, std::string* storage) const {
    char buf[100];
    snprintf(buf, sizeof(buf), "%016d", i);
    storage->assign(buf, strlen(buf));
    return Slice(*storage);
  }

  // Return the value to associate with the specified key
  Slice Value(int k, std::string* storage) const {
    Random r(k);
    return test::RandomString(&r, kValueSize, storage);
  }

  Status OpenDB() {
    delete db_;
    db_ = nullptr;
    env_->ResetState();
    return DB::Open(options_, dbname_, &db_);
  }

  void CloseDB() {
    delete db_;
    db_ = nullptr;
  }

  void DeleteAllData() {
    Iterator* iter = db_->NewIterator(ReadOptions());
    for (iter->SeekToFirst(); iter->Valid(); iter->Next()) {
      ASSERT_OK(db_->Delete(WriteOptions(), iter->key()));
    }

    delete iter;
  }

  void ResetDBState(ResetMethod reset_method) {
    switch (reset_method) {
      case RESET_DROP_UNSYNCED_DATA:
        ASSERT_OK(env_->DropUnsyncedFileData());
        break;
      case RESET_DELETE_UNSYNCED_FILES:
        ASSERT_OK(env_->DeleteFilesCreatedAfterLastDirSync());
        break;
      default:
        assert(false);
    }
  }

  void PartialCompactTestPreFault(int num_pre_sync, int num_post_sync) {
    DeleteAllData();
    Build(0, num_pre_sync);
    db_->CompactRange(nullptr, nullptr);
    Build(num_pre_sync, num_post_sync);
  }

  void PartialCompactTestReopenWithFault(ResetMethod reset_method,
                                         int num_pre_sync, int num_post_sync) {
    env_->SetFilesystemActive(false);
    CloseDB();
    ResetDBState(reset_method);
    ASSERT_OK(OpenDB());
    ASSERT_OK(Verify(0, num_pre_sync, FaultInjectionTest::VAL_EXPECT_NO_ERROR));
    ASSERT_OK(Verify(num_pre_sync, num_post_sync,
                     FaultInjectionTest::VAL_EXPECT_ERROR));
  }

  void NoWriteTestPreFault() {}

  void NoWriteTestReopenWithFault(ResetMethod reset_method) {
    CloseDB();
    ResetDBState(reset_method);
    ASSERT_OK(OpenDB());
  }

  void DoTest() {
    Random rnd(0);
    ASSERT_OK(OpenDB());
    for (size_t idx = 0; idx < kNumIterations; idx++) {
      int num_pre_sync = rnd.Uniform(kMaxNumValues);
      int num_post_sync = rnd.Uniform(kMaxNumValues);

      PartialCompactTestPreFault(num_pre_sync, num_post_sync);
      PartialCompactTestReopenWithFault(RESET_DROP_UNSYNCED_DATA, num_pre_sync,
                                        num_post_sync);

      NoWriteTestPreFault();
      NoWriteTestReopenWithFault(RESET_DROP_UNSYNCED_DATA);

      PartialCompactTestPreFault(num_pre_sync, num_post_sync);
      // No new files created so we expect all values since no files will be
      // dropped.
      PartialCompactTestReopenWithFault(RESET_DELETE_UNSYNCED_FILES,
                                        num_pre_sync + num_post_sync, 0);

      NoWriteTestPreFault();
      NoWriteTestReopenWithFault(RESET_DELETE_UNSYNCED_FILES);
    }
  }
};

TEST(FaultInjectionTest, FaultTestNoLogReuse) {
  ReuseLogs(false);
  DoTest();
}

TEST(FaultInjectionTest, FaultTestWithLogReuse) {
  ReuseLogs(true);
  DoTest();
}

// SYSCOIN BEGIN: A mint replay barrier covers prior WALs, not just its own write.
TEST(FaultInjectionTest, SyncPreservesDeletionAcrossRotatedLog) {
  options_.write_buffer_size = 64 << 10;
  ReuseLogs(false);
  ASSERT_OK(OpenDB());
  WriteOptions synchronous;
  synchronous.sync = true;
  ASSERT_OK(db_->Put(synchronous, "minted-output", "original-utxo"));

  env_->SetBackgroundPaused(true);
  WriteBatch spent;
  spent.Delete("minted-output");
  spent.Put("padding", std::string(128 << 10, 'x'));
  ASSERT_OK(db_->Write(WriteOptions(), &spent));
  // This write rotates the prior unsynced deletion into an immutable memtable.
  ASSERT_OK(db_->Put(WriteOptions(), "coins-tip", "parent"));
  ASSERT_TRUE(env_->HasDeferredBackgroundWork());

  WriteBatch empty;
  ASSERT_OK(db_->Write(synchronous, &empty));
  ASSERT_TRUE(env_->HasUnsyncedLogData());
  const std::string weak_path = dbname_ + "_empty_sync_snapshot";
  Options snapshot_options = options_;
  snapshot_options.env = Env::Default();
  snapshot_options.block_cache = nullptr;
  ASSERT_OK(DestroyDB(weak_path, snapshot_options));
  ASSERT_OK(env_->CreateDurableSnapshot(dbname_, weak_path));
  DB* snapshot = nullptr;
  ASSERT_OK(DB::Open(snapshot_options, weak_path, &snapshot));
  std::string value;
  // The weak barrier durably publishes the parent but resurrects the mint.
  ASSERT_OK(snapshot->Get(ReadOptions(), "minted-output", &value));
  ASSERT_EQ("original-utxo", value);
  ASSERT_OK(snapshot->Get(ReadOptions(), "coins-tip", &value));
  ASSERT_EQ("parent", value);
  delete snapshot;
  ASSERT_OK(DestroyDB(weak_path, snapshot_options));

  std::atomic<bool> entered{false};
  std::atomic<bool> finished{false};
  bool old_logs_durable_at_return{false};
  Status barrier_status;
  std::thread barrier([&] {
    entered.store(true, std::memory_order_release);
    barrier_status = db_->Sync();
    old_logs_durable_at_return = !env_->HasUnsyncedLogData();
    finished.store(true, std::memory_order_release);
  });
  while (!entered.load(std::memory_order_acquire)) {
    env_->SleepForMicroseconds(1000);
  }
  env_->SleepForMicroseconds(100000);
  const bool returned_before_old_log_was_durable =
      finished.load(std::memory_order_acquire);
  env_->SetBackgroundPaused(false);
  barrier.join();
  ASSERT_TRUE(!returned_before_old_log_was_durable);
  ASSERT_OK(barrier_status);
  ASSERT_TRUE(old_logs_durable_at_return);

  // A later ordinary write must remain outside the durable snapshot.
  ASSERT_OK(db_->Put(WriteOptions(), "after-barrier", "volatile"));
  const std::string strong_path = dbname_ + "_strong_sync_snapshot";
  ASSERT_OK(DestroyDB(strong_path, snapshot_options));
  ASSERT_OK(env_->CreateDurableSnapshot(dbname_, strong_path));
  snapshot = nullptr;
  ASSERT_OK(DB::Open(snapshot_options, strong_path, &snapshot));
  ASSERT_TRUE(snapshot->Get(ReadOptions(), "minted-output", &value).IsNotFound());
  ASSERT_OK(snapshot->Get(ReadOptions(), "coins-tip", &value));
  ASSERT_EQ("parent", value);
  ASSERT_OK(snapshot->Get(ReadOptions(), "padding", &value));
  ASSERT_EQ(std::string(128 << 10, 'x'), value);
  ASSERT_TRUE(snapshot->Get(ReadOptions(), "after-barrier", &value).IsNotFound());
  delete snapshot;
  ASSERT_OK(DestroyDB(strong_path, snapshot_options));
}

TEST(FaultInjectionTest, SyncFailureRemainsFatalToWrites) {
  ASSERT_OK(OpenDB());
  ASSERT_OK(db_->Put(WriteOptions(), "pending", "value"));
  env_->fail_log_sync_.store(true, std::memory_order_release);
  ASSERT_TRUE(!db_->Sync().ok());
  env_->fail_log_sync_.store(false, std::memory_order_release);
  ASSERT_TRUE(!db_->Sync().ok());
  ASSERT_TRUE(!db_->Put(WriteOptions(), "later", "value").ok());
}

TEST(FaultInjectionTest, ConcurrentSyncBarriersAndSynchronousWriters) {
  options_.write_buffer_size = 64 << 10;
  ReuseLogs(false);
  ASSERT_OK(OpenDB());
  constexpr int kWriters = 2;
  constexpr int kBarriers = 2;
  constexpr int kOperations = 40;
  std::atomic<int> ready{0};
  std::atomic<bool> start{false};
  std::vector<std::thread> workers;
  for (int worker = 0; worker < kWriters + kBarriers; ++worker) {
    workers.emplace_back([&, worker] {
      ready.fetch_add(1, std::memory_order_release);
      while (!start.load(std::memory_order_acquire)) std::this_thread::yield();
      WriteOptions synchronous;
      synchronous.sync = true;
      for (int operation = 0; operation < kOperations; ++operation) {
        if (worker < kWriters) {
          const std::string key = std::to_string(worker) + "/" +
                                  std::to_string(operation);
          ASSERT_OK(db_->Put(synchronous, key, std::string(2048, 'a' + worker)));
        } else {
          // These barriers must complete independently even when queued behind
          // a synchronous writer that could otherwise absorb their null batch.
          ASSERT_OK(db_->Sync());
        }
      }
    });
  }
  while (ready.load(std::memory_order_acquire) != kWriters + kBarriers) {
    std::this_thread::yield();
  }
  start.store(true, std::memory_order_release);
  for (auto& worker : workers) worker.join();
  ASSERT_OK(db_->Sync());

  const std::string snapshot_path = dbname_ + "_concurrent_sync_snapshot";
  Options snapshot_options = options_;
  snapshot_options.env = Env::Default();
  snapshot_options.block_cache = nullptr;
  ASSERT_OK(DestroyDB(snapshot_path, snapshot_options));
  ASSERT_OK(env_->CreateDurableSnapshot(dbname_, snapshot_path));
  DB* snapshot = nullptr;
  ASSERT_OK(DB::Open(snapshot_options, snapshot_path, &snapshot));
  for (int writer = 0; writer < kWriters; ++writer) {
    for (int operation = 0; operation < kOperations; ++operation) {
      const std::string key = std::to_string(writer) + "/" +
                              std::to_string(operation);
      std::string value;
      ASSERT_OK(snapshot->Get(ReadOptions(), key, &value));
      ASSERT_EQ(std::string(2048, 'a' + writer), value);
    }
  }
  delete snapshot;
  ASSERT_OK(DestroyDB(snapshot_path, snapshot_options));
}
// SYSCOIN END: A mint replay barrier covers prior WALs, not just its own write.

}  // namespace leveldb

int main(int argc, char** argv) { return leveldb::test::RunAllTests(); }
