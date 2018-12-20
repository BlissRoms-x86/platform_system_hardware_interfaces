#include "SystemSuspend.h"

#include <android-base/logging.h>
#include <cutils/native_handle.h>
#include <hidl/HidlTransportSupport.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <fcntl.h>
#include <unistd.h>

using android::sp;
using android::status_t;
using android::base::Socketpair;
using android::base::unique_fd;
using android::hardware::configureRpcThreadpool;
using android::hardware::joinRpcThreadpool;
using android::system::suspend::V1_0::ISystemSuspend;
using android::system::suspend::V1_0::SystemSuspend;
using namespace std::chrono_literals;

static constexpr char kSysPowerWakeupCount[] = "/sys/power/wakeup_count";
static constexpr char kSysPowerState[] = "/sys/power/state";

int main() {
    unique_fd wakeupCountFd{TEMP_FAILURE_RETRY(open(kSysPowerWakeupCount, O_CLOEXEC | O_RDWR))};
    if (wakeupCountFd < 0) {
        PLOG(ERROR) << "error opening " << kSysPowerWakeupCount;
    }
    unique_fd stateFd{TEMP_FAILURE_RETRY(open(kSysPowerState, O_CLOEXEC | O_RDWR))};
    if (stateFd < 0) {
        PLOG(ERROR) << "error opening " << kSysPowerState;
    }

    // If either /sys/power/wakeup_count or /sys/power/state fail to open, we construct
    // SystemSuspend with blocking fds. This way this process will keep running, handle wake lock
    // requests, collect stats, but won't suspend the device. We want this behavior on devices
    // (hosts) where system suspend should not be handles by Android platform e.g. ARC++, Android
    // virtual devices.
    if (wakeupCountFd < 0 || stateFd < 0) {
        // This will block all reads/writes to these fds from the suspend thread.
        Socketpair(SOCK_STREAM, &wakeupCountFd, &stateFd);
    }

    configureRpcThreadpool(1, true /* callerWillJoin */);
    sp<ISystemSuspend> suspend =
        new SystemSuspend(std::move(wakeupCountFd), std::move(stateFd), 100 /* maxStatsEntries */,
                          100ms /* baseSleepTime */);
    status_t status = suspend->registerAsService();
    if (android::OK != status) {
        LOG(FATAL) << "Unable to register service: " << status;
    }
    joinRpcThreadpool();
    std::abort(); /* unreachable */
}
