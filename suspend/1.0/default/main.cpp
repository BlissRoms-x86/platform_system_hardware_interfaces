#include "SystemSuspend.h"

#include <android-base/logging.h>
#include <cutils/native_handle.h>
#include <hidl/HidlTransportSupport.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <fcntl.h>
#include <unistd.h>

using android::sp;
using android::status_t;
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
        return 1;
    }
    unique_fd stateFd{TEMP_FAILURE_RETRY(open(kSysPowerState, O_CLOEXEC | O_RDWR))};
    if (stateFd < 0) {
        PLOG(ERROR) << "error opening " << kSysPowerState;
        return 1;
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
