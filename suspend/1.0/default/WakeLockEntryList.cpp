/*
 * Copyright (C) 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "WakeLockEntryList.h"

#include <android-base/logging.h>

namespace android {
namespace system {
namespace suspend {
namespace V1_0 {

WakeLockEntryList::WakeLockEntryList(size_t capacity) : mCapacity(capacity) {}

void WakeLockEntryList::updateOnAcquire(const std::string& name, int pid,
                                        TimestampType epochTimeNow) {
    std::lock_guard<std::mutex> lock(mStatsLock);

    auto key = std::make_pair(name, pid);
    auto it = mLookupTable.find(key);
    if (it == mLookupTable.end()) {
        // Evict LRU from back of list if stats is at capacity
        if (mStats.size() == mCapacity) {
            auto evictIt = mStats.end();
            std::advance(evictIt, -1);
            auto evictKey = std::make_pair(evictIt->name, evictIt->pid);
            mLookupTable.erase(evictKey);
            mStats.erase(evictIt);
            LOG(ERROR) << "WakeLock Stats: Stats capacity met, consider adjusting capacity to "
                          "avoid stats eviction.";
        }
        // Insert new entry as MRU
        mStats.emplace_front(createEntry(name, pid, epochTimeNow));
        mLookupTable[key] = mStats.begin();
    } else {
        // Update existing entry
        WakeLockInfo updatedEntry = *(it->second);
        updatedEntry.isActive = true;
        updatedEntry.activeSince = epochTimeNow;
        updatedEntry.activeCount++;
        updatedEntry.lastChange = epochTimeNow;

        // Make updated entry MRU
        mStats.erase(it->second);
        mStats.emplace_front(updatedEntry);
        mLookupTable[key] = mStats.begin();
    }
}

void WakeLockEntryList::updateOnRelease(const std::string& name, int pid,
                                        TimestampType epochTimeNow) {
    std::lock_guard<std::mutex> lock(mStatsLock);

    auto key = std::make_pair(name, pid);
    auto it = mLookupTable.find(key);
    if (it == mLookupTable.end()) {
        LOG(INFO) << "WakeLock Stats: A stats entry for, \"" << name
                  << "\" was not found. This is most likely due to it being evicted.";
    } else {
        // Update existing entry
        WakeLockInfo updatedEntry = *(it->second);
        updatedEntry.isActive = false;
        updatedEntry.maxTime =
            std::max(updatedEntry.maxTime, epochTimeNow - updatedEntry.activeSince);
        updatedEntry.totalTime += epochTimeNow - updatedEntry.activeSince;
        updatedEntry.lastChange = epochTimeNow;

        // Make updated entry MRU
        mStats.erase(it->second);
        mStats.emplace_front(updatedEntry);
        mLookupTable[key] = mStats.begin();
    }
}

void WakeLockEntryList::getWakeLockStats(std::vector<WakeLockInfo>* aidl_return) const {
    std::lock_guard<std::mutex> lock(mStatsLock);

    for (const WakeLockInfo& entry : mStats) {
        aidl_return->emplace_back(entry);
    }
}

WakeLockInfo WakeLockEntryList::createEntry(const std::string& name, int pid,
                                            TimestampType epochTimeNow) {
    WakeLockInfo info;
    info.name = name;
    info.pid = pid;
    info.activeCount = 1;
    info.maxTime = 0;
    info.totalTime = 0;
    info.isActive = true;
    info.activeSince = epochTimeNow;
    info.lastChange = epochTimeNow;
    return info;
}

}  // namespace V1_0
}  // namespace suspend
}  // namespace system
}  // namespace android
