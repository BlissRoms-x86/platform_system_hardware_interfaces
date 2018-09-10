/*
 * Copyright 2018 The Android Open Source Project
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

#ifndef ANDROID_SYSTEM_SYSTEM_SUSPEND_V1_0_H
#define ANDROID_SYSTEM_SYSTEM_SUSPEND_V1_0_H

#include <android-base/unique_fd.h>
#include <android/system/suspend/1.0/ISystemSuspend.h>
#include <android/system/suspend/1.0/ISystemSuspendCallback.h>
#include <hidl/HidlTransportSupport.h>
#include <system/hardware/interfaces/suspend/1.0/default/SystemSuspendStats.pb.h>

#include <condition_variable>
#include <mutex>
#include <string>

namespace android {
namespace system {
namespace suspend {
namespace V1_0 {

using ::android::base::unique_fd;
using ::android::hardware::hidl_death_recipient;
using ::android::hardware::hidl_handle;
using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;
using ::android::hardware::interfacesEqual;
using ::android::hardware::Return;

using WakeLockIdType = uint64_t;

class SystemSuspend;

std::string readFd(int fd);

class WakeLock : public IWakeLock {
   public:
    WakeLock(SystemSuspend* systemSuspend);
    ~WakeLock();

    Return<void> release();

   private:
    inline void releaseOnce();
    std::once_flag mReleased;

    SystemSuspend* mSystemSuspend;
};

class SystemSuspend : public ISystemSuspend, public hidl_death_recipient {
   public:
    SystemSuspend(unique_fd wakeupCountFd, unique_fd stateFd);
    Return<bool> enableAutosuspend() override;
    Return<sp<IWakeLock>> acquireWakeLock(const hidl_string& name) override;
    Return<bool> registerCallback(const sp<ISystemSuspendCallback>& cb) override;
    Return<void> debug(const hidl_handle& handle, const hidl_vec<hidl_string>& options) override;
    void serviceDied(uint64_t /* cookie */, const wp<IBase>& service);
    void incSuspendCounter();
    void decSuspendCounter();
    void deleteWakeLockStatsEntry(WakeLockIdType id);

   private:
    void initAutosuspend();

    std::mutex mCounterLock;
    std::condition_variable mCounterCondVar;
    uint32_t mSuspendCounter;
    unique_fd mWakeupCountFd;
    unique_fd mStateFd;

    // mStats can be inconsistent with with mSuspendCounter since we use two separate locks to
    // protect these. However, since mStats is only for debugging we prioritize performance.
    // Never hold both locks at the same time to avoid deadlock.
    std::mutex mStatsLock;
    SystemSuspendStats mStats;

    using CbType = sp<ISystemSuspendCallback>;
    std::mutex mCallbackLock;
    std::vector<CbType> mCallbacks;
    std::vector<CbType>::iterator findCb(const sp<IBase>& cb) {
        return std::find_if(mCallbacks.begin(), mCallbacks.end(),
                            [&cb](const CbType& i) { return interfacesEqual(i, cb); });
    }
};

}  // namespace V1_0
}  // namespace suspend
}  // namespace system
}  // namespace android

#endif  // ANDROID_SYSTEM_SYSTEM_SUSPEND_V1_0_H
