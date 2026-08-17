// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_mnauth.h>

#include <hash.h>
#include <streams.h>
#include <version.h>

#include <algorithm>
#include <limits>
#include <list>
#include <map>
#include <mutex>
#include <string_view>
#include <utility>

namespace llmq::pq {
namespace {

constexpr std::string_view CACHE_KEY_DOMAIN{"SYS_PQ_MNAUTH_CACHE_KEY_V1"};

template <typename Range>
bool HasNonZeroByte(const Range& range) noexcept
{
    return std::any_of(range.begin(), range.end(),
                       [](uint8_t byte) { return byte != 0; });
}

void SetError(MNAUTHVerificationError* error, MNAUTHVerificationError value)
{
    if (error != nullptr) *error = value;
}

void SetSigningError(MNAUTHSigningAdmissionError* error,
                     MNAUTHSigningAdmissionError value)
{
    if (error != nullptr) *error = value;
}

bool IsKnownRole(MNAUTHSignerRole role) noexcept
{
    return role == MNAUTHSignerRole::INITIATOR ||
           role == MNAUTHSignerRole::RESPONDER;
}

uint64_t SaturatingAdd(uint64_t left, uint64_t right) noexcept
{
    if (right > std::numeric_limits<uint64_t>::max() - left) {
        return std::numeric_limits<uint64_t>::max();
    }
    return left + right;
}

uint256 GetCacheKey(const uint256& authorization_hash,
                    const GlobalSignature& signature)
{
    CHashWriter writer{SER_GETHASH, 0};
    writer.write(AsBytes(Span{CACHE_KEY_DOMAIN.data(), CACHE_KEY_DOMAIN.size()}));
    writer << authorization_hash << signature;
    return writer.GetHash();
}

struct RateWindow {
    uint64_t start{0};
    uint64_t last_seen{0};
    uint32_t attempts{0};
    bool initialized{false};
};

bool WindowExpired(const RateWindow& window,
                   uint64_t now,
                   uint64_t window_seconds) noexcept
{
    return window.initialized && now >= window.start &&
           now - window.start >= window_seconds;
}

bool CanConsume(const RateWindow& window,
                uint64_t now,
                uint64_t window_seconds,
                uint32_t limit) noexcept
{
    return !window.initialized || WindowExpired(window, now, window_seconds) ||
           window.attempts < limit;
}

void Consume(RateWindow& window, uint64_t now, uint64_t window_seconds) noexcept
{
    if (!window.initialized || WindowExpired(window, now, window_seconds)) {
        window.start = now;
        window.attempts = 0;
        window.initialized = true;
    }
    ++window.attempts;
    window.last_seen = now;
}

} // namespace

struct MNAUTHVerificationState {
    struct SuccessEntry {
        uint64_t expires_at{0};
        std::list<uint256>::iterator lru;
    };

    explicit MNAUTHVerificationState(MNAUTHRuntimeConfig config_in)
        : config(std::move(config_in)), valid_config(config.IsValid())
    {
    }

    void Cleanup(uint64_t now)
    {
        while (!replay_expiry.empty() && replay_expiry.front().first <= now) {
            const auto [expiry, digest] = replay_expiry.front();
            replay_expiry.pop_front();
            const auto it = replay_entries.find(digest);
            if (it != replay_entries.end() && it->second == expiry) {
                replay_entries.erase(it);
            }
        }

        for (auto it = success_cache.begin(); it != success_cache.end();) {
            if (it->second.expires_at <= now) {
                success_lru.erase(it->second.lru);
                it = success_cache.erase(it);
            } else {
                ++it;
            }
        }

        for (auto it = rate_sources.begin(); it != rate_sources.end();) {
            if (!it->second.initialized ||
                WindowExpired(it->second, now, config.rate_window_seconds)) {
                it = rate_sources.erase(it);
            } else {
                ++it;
            }
        }
    }

    bool IsCached(const uint256& cache_key)
    {
        const auto it = success_cache.find(cache_key);
        if (it == success_cache.end()) return false;
        if (it->second.expires_at <= last_now) {
            success_lru.erase(it->second.lru);
            success_cache.erase(it);
            return false;
        }
        success_lru.splice(success_lru.end(), success_lru, it->second.lru);
        return true;
    }

    void Complete(const uint256& cache_key, uint64_t expires_at, bool success)
    {
        std::lock_guard lock{mutex};
        if (inflight != 0) --inflight;
        if (!success || expires_at <= last_now) return;

        const auto existing = success_cache.find(cache_key);
        if (existing != success_cache.end()) {
            existing->second.expires_at = expires_at;
            success_lru.splice(success_lru.end(), success_lru,
                               existing->second.lru);
            return;
        }
        while (success_cache.size() >= config.max_success_cache_entries) {
            const uint256 oldest{success_lru.front()};
            success_lru.pop_front();
            success_cache.erase(oldest);
        }
        success_lru.push_back(cache_key);
        auto lru = std::prev(success_lru.end());
        success_cache.emplace(cache_key, SuccessEntry{expires_at, lru});
    }

    void Abandon() noexcept
    {
        std::lock_guard lock{mutex};
        if (inflight != 0) --inflight;
    }

    MNAUTHRuntimeConfig config;
    bool valid_config{false};
    mutable std::mutex mutex;
    uint64_t last_now{0};
    bool has_time{false};
    std::size_t inflight{0};
    RateWindow global_rate;
    std::map<uint64_t, RateWindow> rate_sources;
    std::map<int64_t, uint256> peer_sessions;
    std::map<uint256, uint64_t> replay_entries;
    std::list<std::pair<uint64_t, uint256>> replay_expiry;
    std::map<uint256, SuccessEntry> success_cache;
    std::list<uint256> success_lru;
};

bool PQMNAUTHMessage::IsHeaderValid() const noexcept
{
    return version == PQ_MNAUTH_WIRE_VERSION &&
           !signer_pro_tx_hash.IsNull() && signer_global_key_version != 0 &&
           IsKnownRole(signer_role);
}

bool PQMNAUTHMessage::IsStructurallyValid() const noexcept
{
    return IsHeaderValid() && HasNonZeroByte(signature);
}

bool DecodePQMNAUTHMessage(CDataStream& stream,
                           PQMNAUTHMessage& message) noexcept
{
    if (stream.size() != PQMNAUTHMessage::WIRE_SIZE) return false;
    try {
        PQMNAUTHMessage candidate;
        stream >> candidate;
        if (!stream.empty()) return false;
        message = std::move(candidate);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

bool DecodePQMNAUTHMessage(const std::vector<unsigned char>& encoded,
                           PQMNAUTHMessage& message) noexcept
{
    if (encoded.size() != PQMNAUTHMessage::WIRE_SIZE) return false;
    try {
        CDataStream stream(encoded, SER_NETWORK, PROTOCOL_VERSION);
        return DecodePQMNAUTHMessage(stream, message);
    } catch (const std::exception&) {
        return false;
    }
}

bool MNAUTHRuntimeConfig::IsValid() const noexcept
{
    if (max_inflight == 0 || max_peer_sessions == 0 || max_rate_sources == 0 ||
        max_replay_entries == 0 || max_success_cache_entries == 0 ||
        global_attempts_per_window == 0 || source_attempts_per_window == 0 ||
        source_attempts_per_window > global_attempts_per_window ||
        rate_window_seconds == 0 ||
        replay_retention_seconds < rate_window_seconds ||
        max_replay_entries < max_inflight ||
        max_peer_sessions < max_inflight ||
        max_rate_sources < global_attempts_per_window) {
        return false;
    }

    const uint64_t full_windows{
        replay_retention_seconds / rate_window_seconds +
        (replay_retention_seconds % rate_window_seconds != 0)};
    if (full_windows > std::numeric_limits<std::size_t>::max() /
                           global_attempts_per_window) {
        return false;
    }
    const std::size_t admitted_during_retention{
        static_cast<std::size_t>(full_windows) * global_attempts_per_window};
    return admitted_during_retention <= max_replay_entries - max_inflight;
}

MNAUTHSignatureCheck::MNAUTHSignatureCheck(
    uint256 genesis_hash,
    GlobalKeyRecord initiator_key,
    GlobalKeyRecord responder_key,
    MNAUTHTranscript transcript,
    uint64_t required_service_flags,
    GlobalSignature signature)
    : m_genesis_hash(std::move(genesis_hash)),
      m_initiator_key(std::move(initiator_key)),
      m_responder_key(std::move(responder_key)),
      m_transcript(std::move(transcript)),
      m_required_service_flags(required_service_flags),
      m_signature(std::move(signature))
{
}

bool MNAUTHSignatureCheck::operator()() const
{
    return VerifyMNAUTHAuthorization(
        m_genesis_hash, m_initiator_key, m_responder_key, m_transcript,
        m_required_service_flags, m_signature);
}

MNAUTHVerificationTask::MNAUTHVerificationTask(
    std::shared_ptr<MNAUTHVerificationState> state,
    MNAUTHSignatureCheck check,
    uint256 authorization_hash,
    uint256 cache_key,
    uint64_t expires_at)
    : m_state(std::move(state)),
      m_check(std::make_unique<MNAUTHSignatureCheck>(std::move(check))),
      m_authorization_hash(std::move(authorization_hash)),
      m_cache_key(std::move(cache_key)),
      m_expires_at(expires_at),
      m_active(true)
{
}

MNAUTHVerificationTask::MNAUTHVerificationTask(
    MNAUTHVerificationTask&& other) noexcept
    : m_state(std::move(other.m_state)),
      m_check(std::move(other.m_check)),
      m_authorization_hash(std::move(other.m_authorization_hash)),
      m_cache_key(std::move(other.m_cache_key)),
      m_expires_at(other.m_expires_at),
      m_active(other.m_active)
{
    other.m_active = false;
}

MNAUTHVerificationTask& MNAUTHVerificationTask::operator=(
    MNAUTHVerificationTask&& other) noexcept
{
    if (this == &other) return *this;
    Abandon();
    m_state = std::move(other.m_state);
    m_check = std::move(other.m_check);
    m_authorization_hash = std::move(other.m_authorization_hash);
    m_cache_key = std::move(other.m_cache_key);
    m_expires_at = other.m_expires_at;
    m_active = other.m_active;
    other.m_active = false;
    return *this;
}

MNAUTHVerificationTask::~MNAUTHVerificationTask()
{
    Abandon();
}

void MNAUTHVerificationTask::Abandon() noexcept
{
    if (!m_active) return;
    m_active = false;
    if (m_state) m_state->Abandon();
    m_check.reset();
}

bool MNAUTHVerificationTask::operator()()
{
    if (!m_active || !m_state || !m_check) return false;

    bool result{false};
    {
        std::lock_guard lock{m_state->mutex};
        result = m_state->IsCached(m_cache_key);
    }
    if (!result) result = (*m_check)();

    m_state->Complete(m_cache_key, m_expires_at, result);
    m_active = false;
    m_check.reset();
    return result;
}

bool VerifyMNAUTHTasks(std::vector<MNAUTHVerificationTask>&& tasks,
                       MNAUTHCheckQueue* queue)
{
    if (tasks.empty()) return false;
    if (queue == nullptr) {
        for (auto& task : tasks) {
            if (!task()) return false;
        }
        return true;
    }
    CCheckQueueControl<MNAUTHVerificationTask> control{queue};
    control.Add(std::move(tasks));
    return control.Wait();
}

MNAUTHVerificationManager::MNAUTHVerificationManager(MNAUTHRuntimeConfig config)
    : m_state(std::make_shared<MNAUTHVerificationState>(std::move(config)))
{
}

std::optional<MNAUTHVerificationTask> MNAUTHVerificationManager::Prepare(
    int64_t peer_id,
    uint64_t source_key,
    const uint256& genesis_hash,
    const GlobalKeyRecord& initiator_key,
    const GlobalKeyRecord& responder_key,
    const MNAUTHTranscript& transcript,
    MNAUTHSignerRole expected_signer_role,
    uint64_t required_service_flags,
    const PQMNAUTHMessage& message,
    uint64_t now_seconds,
    MNAUTHVerificationError* error)
{
    SetError(error, MNAUTHVerificationError::NONE);
    if (!m_state->valid_config) {
        SetError(error, MNAUTHVerificationError::INVALID_CONFIGURATION);
        return std::nullopt;
    }
    if (peer_id < 0 || !message.IsStructurallyValid()) {
        SetError(error, MNAUTHVerificationError::INVALID_MESSAGE);
        return std::nullopt;
    }
    if (!transcript.IsStructurallyValid(required_service_flags)) {
        SetError(error, MNAUTHVerificationError::INVALID_TRANSCRIPT);
        return std::nullopt;
    }
    if (!IsKnownRole(expected_signer_role) ||
        message.signer_role != expected_signer_role ||
        transcript.signer_role != expected_signer_role) {
        SetError(error, MNAUTHVerificationError::WRONG_SIGNER_ROLE);
        return std::nullopt;
    }

    const bool initiator{message.signer_role == MNAUTHSignerRole::INITIATOR};
    const uint256& expected_pro_tx_hash{initiator
        ? transcript.initiator_pro_tx_hash
        : transcript.responder_pro_tx_hash};
    const uint32_t expected_key_version{initiator
        ? transcript.initiator_global_key_version
        : transcript.responder_global_key_version};
    if (message.signer_pro_tx_hash != expected_pro_tx_hash ||
        message.signer_global_key_version != expected_key_version) {
        SetError(error, MNAUTHVerificationError::WRONG_SIGNER_IDENTITY);
        return std::nullopt;
    }

    const auto authorization_hash{GetMNAUTHAuthorizationHash(
        genesis_hash, initiator_key, responder_key, transcript,
        required_service_flags)};
    if (!authorization_hash) {
        SetError(error, MNAUTHVerificationError::INVALID_AUTHORIZATION);
        return std::nullopt;
    }
    const uint256 cache_key{GetCacheKey(*authorization_hash, message.signature)};

    uint64_t expires_at{0};
    {
        std::lock_guard lock{m_state->mutex};
        if (m_state->has_time && now_seconds < m_state->last_now) {
            SetError(error, MNAUTHVerificationError::INVALID_TIME);
            return std::nullopt;
        }
        m_state->has_time = true;
        m_state->last_now = now_seconds;
        m_state->Cleanup(now_seconds);

        if (m_state->peer_sessions.count(peer_id) != 0) {
            SetError(error, MNAUTHVerificationError::DUPLICATE_PEER);
            return std::nullopt;
        }
        if (m_state->replay_entries.count(*authorization_hash) != 0) {
            SetError(error, MNAUTHVerificationError::REPLAY);
            return std::nullopt;
        }
        if (m_state->peer_sessions.size() >=
            m_state->config.max_peer_sessions) {
            SetError(error, MNAUTHVerificationError::PEER_STATE_LIMIT);
            return std::nullopt;
        }
        if (m_state->replay_entries.size() >=
            m_state->config.max_replay_entries) {
            SetError(error, MNAUTHVerificationError::REPLAY_STATE_LIMIT);
            return std::nullopt;
        }
        if (m_state->inflight >= m_state->config.max_inflight) {
            SetError(error, MNAUTHVerificationError::INFLIGHT_LIMIT);
            return std::nullopt;
        }
        if (!CanConsume(m_state->global_rate, now_seconds,
                        m_state->config.rate_window_seconds,
                        m_state->config.global_attempts_per_window)) {
            SetError(error, MNAUTHVerificationError::RATE_LIMIT);
            return std::nullopt;
        }

        auto source_rate = m_state->rate_sources.find(source_key);
        if (source_rate == m_state->rate_sources.end()) {
            if (m_state->rate_sources.size() >=
                m_state->config.max_rate_sources) {
                SetError(error, MNAUTHVerificationError::RATE_STATE_LIMIT);
                return std::nullopt;
            }
            source_rate = m_state->rate_sources
                              .emplace(source_key, RateWindow{})
                              .first;
        }
        if (!CanConsume(source_rate->second, now_seconds,
                        m_state->config.rate_window_seconds,
                        m_state->config.source_attempts_per_window)) {
            SetError(error, MNAUTHVerificationError::RATE_LIMIT);
            return std::nullopt;
        }

        Consume(m_state->global_rate, now_seconds,
                m_state->config.rate_window_seconds);
        Consume(source_rate->second, now_seconds,
                m_state->config.rate_window_seconds);
        expires_at = SaturatingAdd(
            now_seconds, m_state->config.replay_retention_seconds);
        m_state->peer_sessions.emplace(peer_id, *authorization_hash);
        m_state->replay_entries.emplace(*authorization_hash, expires_at);
        m_state->replay_expiry.emplace_back(expires_at, *authorization_hash);
        ++m_state->inflight;
    }

    return MNAUTHVerificationTask{
        m_state,
        MNAUTHSignatureCheck{genesis_hash, initiator_key, responder_key,
                             transcript, required_service_flags,
                             message.signature},
        *authorization_hash, cache_key, expires_at};
}

void MNAUTHVerificationManager::ForgetPeer(int64_t peer_id) noexcept
{
    std::lock_guard lock{m_state->mutex};
    m_state->peer_sessions.erase(peer_id);
}

MNAUTHRuntimeStats MNAUTHVerificationManager::GetStats() const noexcept
{
    std::lock_guard lock{m_state->mutex};
    return MNAUTHRuntimeStats{
        m_state->inflight,
        m_state->peer_sessions.size(),
        m_state->rate_sources.size(),
        m_state->replay_entries.size(),
        m_state->success_cache.size()};
}

bool MNAUTHVerificationManager::HasCachedSuccess(
    const uint256& authorization_hash,
    const GlobalSignature& signature) const noexcept
{
    if (authorization_hash.IsNull()) return false;
    const uint256 cache_key{GetCacheKey(authorization_hash, signature)};
    std::lock_guard lock{m_state->mutex};
    return m_state->IsCached(cache_key);
}

struct MNAUTHSigningAdmissionState {
    explicit MNAUTHSigningAdmissionState(MNAUTHSigningRuntimeConfig config_in)
        : config(std::move(config_in)), valid_config(config.IsValid())
    {
    }

    void Cleanup(uint64_t now)
    {
        for (auto it = source_rates.begin(); it != source_rates.end();) {
            if (!it->second.initialized ||
                WindowExpired(it->second, now, config.rate_window_seconds)) {
                it = source_rates.erase(it);
            } else {
                ++it;
            }
        }
        for (auto it = identity_rates.begin(); it != identity_rates.end();) {
            if (!it->second.initialized ||
                WindowExpired(it->second, now, config.rate_window_seconds)) {
                it = identity_rates.erase(it);
            } else {
                ++it;
            }
        }
    }

    MNAUTHSigningRuntimeConfig config;
    bool valid_config{false};
    mutable std::mutex mutex;
    uint64_t last_now{0};
    bool has_time{false};
    RateWindow global_rate;
    std::map<uint64_t, RateWindow> source_rates;
    std::map<uint256, RateWindow> identity_rates;
};

bool MNAUTHSigningRuntimeConfig::IsValid() const noexcept
{
    return max_source_records != 0 && max_identity_records != 0 &&
           global_attempts_per_window != 0 &&
           source_attempts_per_window != 0 &&
           identity_attempts_per_window != 0 &&
           source_attempts_per_window <= global_attempts_per_window &&
           identity_attempts_per_window <= global_attempts_per_window &&
           rate_window_seconds != 0;
}

MNAUTHSigningAdmissionManager::MNAUTHSigningAdmissionManager(
    MNAUTHSigningRuntimeConfig config)
    : m_state{
          std::make_shared<MNAUTHSigningAdmissionState>(std::move(config))}
{
}

bool MNAUTHSigningAdmissionManager::Admit(
    uint64_t source_key,
    const uint256& attributed_pro_tx_hash,
    uint64_t now_seconds,
    MNAUTHSigningAdmissionError* error)
{
    SetSigningError(error, MNAUTHSigningAdmissionError::NONE);
    if (!m_state->valid_config) {
        SetSigningError(
            error, MNAUTHSigningAdmissionError::INVALID_CONFIGURATION);
        return false;
    }
    if (attributed_pro_tx_hash.IsNull()) {
        SetSigningError(error, MNAUTHSigningAdmissionError::INVALID_IDENTITY);
        return false;
    }

    std::lock_guard lock{m_state->mutex};
    if (m_state->has_time && now_seconds < m_state->last_now) {
        SetSigningError(error, MNAUTHSigningAdmissionError::INVALID_TIME);
        return false;
    }
    m_state->has_time = true;
    m_state->last_now = now_seconds;
    m_state->Cleanup(now_seconds);

    if (!CanConsume(m_state->global_rate, now_seconds,
                    m_state->config.rate_window_seconds,
                    m_state->config.global_attempts_per_window)) {
        SetSigningError(error, MNAUTHSigningAdmissionError::RATE_LIMIT);
        return false;
    }

    const auto source_it{m_state->source_rates.find(source_key)};
    if (source_it == m_state->source_rates.end() &&
        m_state->source_rates.size() >=
            m_state->config.max_source_records) {
        SetSigningError(
            error, MNAUTHSigningAdmissionError::SOURCE_STATE_LIMIT);
        return false;
    }
    const auto identity_it{
        m_state->identity_rates.find(attributed_pro_tx_hash)};
    if (identity_it == m_state->identity_rates.end() &&
        m_state->identity_rates.size() >=
            m_state->config.max_identity_records) {
        SetSigningError(
            error, MNAUTHSigningAdmissionError::IDENTITY_STATE_LIMIT);
        return false;
    }

    const RateWindow empty;
    const RateWindow& source_rate{
        source_it == m_state->source_rates.end() ? empty
                                                 : source_it->second};
    const RateWindow& identity_rate{
        identity_it == m_state->identity_rates.end() ? empty
                                                     : identity_it->second};
    if (!CanConsume(source_rate, now_seconds,
                    m_state->config.rate_window_seconds,
                    m_state->config.source_attempts_per_window) ||
        !CanConsume(identity_rate, now_seconds,
                    m_state->config.rate_window_seconds,
                    m_state->config.identity_attempts_per_window)) {
        SetSigningError(error, MNAUTHSigningAdmissionError::RATE_LIMIT);
        return false;
    }

    RateWindow& mutable_source{
        m_state->source_rates.try_emplace(source_key).first->second};
    RateWindow& mutable_identity{
        m_state->identity_rates.try_emplace(attributed_pro_tx_hash)
            .first->second};
    Consume(m_state->global_rate, now_seconds,
            m_state->config.rate_window_seconds);
    Consume(mutable_source, now_seconds,
            m_state->config.rate_window_seconds);
    Consume(mutable_identity, now_seconds,
            m_state->config.rate_window_seconds);
    return true;
}

MNAUTHSigningRuntimeStats MNAUTHSigningAdmissionManager::GetStats() const
    noexcept
{
    std::lock_guard lock{m_state->mutex};
    return {m_state->source_rates.size(), m_state->identity_rates.size()};
}

} // namespace llmq::pq
