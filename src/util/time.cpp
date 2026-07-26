// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/syscoin-config.h>
#endif

#include <compat/compat.h>
#include <tinyformat.h>
#include <util/time.h>
#include <util/check.h>

#include <atomic>
#include <chrono>
#include <ctime>
#include <limits>
#include <locale>
#include <thread>
#include <sstream>
#include <string>

void UninterruptibleSleep(const std::chrono::microseconds& n) { std::this_thread::sleep_for(n); }

static std::atomic<int64_t> nMockTime(0); //!< For testing

bool ChronoSanityCheck()
{
    // std::chrono::system_clock.time_since_epoch and time_t(0) are not guaranteed
    // to use the Unix epoch timestamp, prior to C++20, but in practice they almost
    // certainly will. Any differing behavior will be assumed to be an error, unless
    // certain platforms prove to consistently deviate, at which point we'll cope
    // with it by adding offsets.

    // Create a new clock from time_t(0) and make sure that it represents 0
    // seconds from the system_clock's time_since_epoch. Then convert that back
    // to a time_t and verify that it's the same as before.
    const time_t time_t_epoch{};
    auto clock = std::chrono::system_clock::from_time_t(time_t_epoch);
    if (std::chrono::duration_cast<std::chrono::seconds>(clock.time_since_epoch()).count() != 0) {
        return false;
    }

    time_t time_val = std::chrono::system_clock::to_time_t(clock);
    if (time_val != time_t_epoch) {
        return false;
    }

    // Check that the above zero time is actually equal to the known unix timestamp.
    struct tm epoch;
#ifdef HAVE_GMTIME_R
    if (gmtime_r(&time_val, &epoch) == nullptr) {
#else
    if (gmtime_s(&epoch, &time_val) != 0) {
#endif
        return false;
    }

    if ((epoch.tm_sec != 0)  ||
       (epoch.tm_min  != 0)  ||
       (epoch.tm_hour != 0)  ||
       (epoch.tm_mday != 1)  ||
       (epoch.tm_mon  != 0)  ||
       (epoch.tm_year != 70)) {
        return false;
    }
    return true;
}

NodeClock::time_point NodeClock::now() noexcept
{
    const std::chrono::seconds mocktime{nMockTime.load(std::memory_order_relaxed)};
    const auto ret{
        mocktime.count() ?
            mocktime :
            std::chrono::system_clock::now().time_since_epoch()};
    assert(ret > 0s);
    return time_point{ret};
};

void SetMockTime(int64_t nMockTimeIn)
{
    Assert(nMockTimeIn >= 0);
    nMockTime.store(nMockTimeIn, std::memory_order_relaxed);
}

void SetMockTime(std::chrono::seconds mock_time_in)
{
    nMockTime.store(mock_time_in.count(), std::memory_order_relaxed);
}

std::chrono::seconds GetMockTime()
{
    return std::chrono::seconds(nMockTime.load(std::memory_order_relaxed));
}

int64_t GetTime() { return GetTime<std::chrono::seconds>().count(); }

namespace {
struct CivilTime {
    int year;
    unsigned int month;
    unsigned int day;
    unsigned int hour;
    unsigned int minute;
    unsigned int second;
};

bool ToCivilTime(int64_t timestamp, CivilTime& result)
{
    static constexpr int64_t SECONDS_PER_DAY{24 * 60 * 60};

    int64_t days{timestamp / SECONDS_PER_DAY};
    int64_t seconds{timestamp % SECONDS_PER_DAY};
    if (seconds < 0) {
        seconds += SECONDS_PER_DAY;
        --days;
    }

    // Convert days since 1970-01-01 to a proleptic Gregorian date without
    // relying on the platform CRT. In particular, Windows gmtime_s rejects
    // otherwise representable dates after 3000-12-31.
    const int64_t shifted_days{days + 719468};
    const int64_t era{(shifted_days >= 0 ? shifted_days : shifted_days - 146096) / 146097};
    const unsigned int day_of_era{static_cast<unsigned int>(shifted_days - era * 146097)};
    const unsigned int year_of_era{
        (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146096) / 365};
    const int64_t year_base{static_cast<int64_t>(year_of_era) + era * 400};
    const unsigned int day_of_year{
        day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100)};
    const unsigned int month_prime{(5 * day_of_year + 2) / 153};
    const unsigned int day{day_of_year - (153 * month_prime + 2) / 5 + 1};
    const unsigned int month{month_prime < 10 ? month_prime + 3 : month_prime - 9};
    const int64_t year{year_base + (month <= 2)};
    if (year < std::numeric_limits<int>::min() || year > std::numeric_limits<int>::max()) {
        return false;
    }

    result = {
        static_cast<int>(year),
        month,
        day,
        static_cast<unsigned int>(seconds / 3600),
        static_cast<unsigned int>((seconds % 3600) / 60),
        static_cast<unsigned int>(seconds % 60),
    };
    return true;
}
} // namespace

std::string FormatISO8601DateTime(int64_t nTime) {
    CivilTime time;
    if (!ToCivilTime(nTime, time)) {
        return {};
    }
    return strprintf("%04i-%02u-%02uT%02u:%02u:%02uZ", time.year, time.month, time.day, time.hour, time.minute, time.second);
}

std::string FormatISO8601Date(int64_t nTime) {
    CivilTime time;
    if (!ToCivilTime(nTime, time)) {
        return {};
    }
    return strprintf("%04i-%02u-%02u", time.year, time.month, time.day);
}
// SYSCOIN
std::string DurationToDHMS(int64_t nDurationTime)
{
	int seconds = nDurationTime % 60;
	nDurationTime /= 60;
	int minutes = nDurationTime % 60;
	nDurationTime /= 60;
	int hours = nDurationTime % 24;
	int days = nDurationTime / 24;
	if (days)
		return strprintf("%dd %02dh:%02dm:%02ds", days, hours, minutes, seconds);
	if (hours)
		return strprintf("%02dh:%02dm:%02ds", hours, minutes, seconds);
	return strprintf("%02dm:%02ds", minutes, seconds);
}

struct timeval MillisToTimeval(int64_t nTimeout)
{
    struct timeval timeout;
    timeout.tv_sec  = nTimeout / 1000;
    timeout.tv_usec = (nTimeout % 1000) * 1000;
    return timeout;
}

struct timeval MillisToTimeval(std::chrono::milliseconds ms)
{
    return MillisToTimeval(count_milliseconds(ms));
}
