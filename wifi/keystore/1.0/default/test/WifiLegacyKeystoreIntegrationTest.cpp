/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <aidl/android/security/legacykeystore/ILegacyKeystore.h>
#include <aidl/android/system/keystore2/IKeystoreOperation.h>
#include <aidl/android/system/keystore2/IKeystoreSecurityLevel.h>
#include <aidl/android/system/keystore2/IKeystoreService.h>
#include <aidl/android/system/keystore2/ResponseCode.h>
#include <android/binder_manager.h>
#include <android/system/wifi/keystore/1.0/IKeystore.h>
#include <binder/IServiceManager.h>
#include <cutils/properties.h>
#include <gtest/gtest.h>
#include <hidl/GtestPrinter.h>
#include <hidl/ServiceManagement.h>
#include <private/android_filesystem_config.h>
#include <utils/String16.h>

using namespace std;
using namespace ::testing;
using namespace android;
using android::system::wifi::keystore::V1_0::IKeystore;

namespace lks = ::aidl::android::security::legacykeystore;
namespace ks2 = ::aidl::android::system::keystore2;

int main(int argc, char** argv) {
    InitGoogleTest(&argc, argv);
    int status = RUN_ALL_TESTS();
    return status;
}

namespace {

enum KeyPurpose {
    ENCRYPTION,
    SIGNING,
};

// The fixture for testing the Wifi Keystore HAL legacy keystore integration.
class WifiLegacyKeystoreTest : public TestWithParam<std::string> {
   protected:
    void SetUp() override {
        wifiKeystoreHal = IKeystore::getService(GetParam());
        ASSERT_TRUE(wifiKeystoreHal);

        myRUid = getuid();
    }

    void TearDown() override {
        if (getuid() != myRUid) {
            ASSERT_EQ(0, seteuid(myRUid));
        }
    }

    bool isDebuggableBuild() {
        char value[PROPERTY_VALUE_MAX] = {0};
        property_get("ro.system.build.type", value, "");
        if (strcmp(value, "userdebug") == 0) {
            return true;
        }
        if (strcmp(value, "eng") == 0) {
            return true;
        }
        return false;
    }

    sp<IKeystore> wifiKeystoreHal;
    uid_t myRUid;
};

INSTANTIATE_TEST_SUITE_P(
    PerInstance, WifiLegacyKeystoreTest,
    testing::ValuesIn(android::hardware::getAllHalInstanceNames(IKeystore::descriptor)),
    android::hardware::PrintInstanceNameToString);

constexpr const char kLegacyKeystoreServiceName[] = "android.security.legacykeystore";

static bool LegacyKeystoreRemove(const std::string& alias,
                                 int uid = lks::ILegacyKeystore::UID_SELF) {
    ::ndk::SpAIBinder keystoreBinder(AServiceManager_checkService(kLegacyKeystoreServiceName));
    auto legacyKeystore = lks::ILegacyKeystore::fromBinder(keystoreBinder);

    EXPECT_TRUE((bool)legacyKeystore);
    if (!legacyKeystore) {
        return false;
    }

    auto rc = legacyKeystore->remove(alias, uid);
    // Either the entry was successfully removed or the entry was not found.
    bool outcome =
        rc.isOk() || rc.getServiceSpecificError() == lks::ILegacyKeystore::ERROR_ENTRY_NOT_FOUND;
    EXPECT_TRUE(outcome) << "Description: " << rc.getDescription();
    return outcome;
}

static bool LegacyKeystorePut(const std::string& alias, const std::vector<uint8_t>& blob,
                              int uid = lks::ILegacyKeystore::UID_SELF) {
    ::ndk::SpAIBinder keystoreBinder(AServiceManager_checkService(kLegacyKeystoreServiceName));
    auto legacyKeystore = lks::ILegacyKeystore::fromBinder(keystoreBinder);

    EXPECT_TRUE((bool)legacyKeystore);
    if (!legacyKeystore) {
        return false;
    }

    auto rc = legacyKeystore->put(alias, uid, blob);
    EXPECT_TRUE(rc.isOk()) << "Description: " << rc.getDescription();
    return rc.isOk();
}

static std::optional<std::vector<uint8_t>> LegacyKeystoreGet(
    const std::string& alias, int uid = lks::ILegacyKeystore::UID_SELF) {
    ::ndk::SpAIBinder keystoreBinder(AServiceManager_checkService(kLegacyKeystoreServiceName));
    auto legacyKeystore = lks::ILegacyKeystore::fromBinder(keystoreBinder);

    EXPECT_TRUE((bool)legacyKeystore);
    if (!legacyKeystore) {
        return std::nullopt;
    }

    std::optional<std::vector<uint8_t>> blob(std::vector<uint8_t>{});
    auto rc = legacyKeystore->get(alias, uid, &*blob);
    EXPECT_TRUE(rc.isOk()) << "Description: " << rc.getDescription();
    return blob;
}

TEST_P(WifiLegacyKeystoreTest, Put_get_test) {
    if (!isDebuggableBuild() || getuid() != 0) {
        GTEST_SKIP() << "Device not running a debuggable build or not running as root. "
                     << "Cannot transition to AID_SYSTEM.";
    }

    // Only AID_SYSTEM (and AID_WIFI) is allowed to manipulate
    ASSERT_EQ(0, seteuid(AID_SYSTEM)) << "Failed to set uid to AID_SYSTEM: " << strerror(errno);

    const std::vector<uint8_t> TESTBLOB{1, 2, 3, 4};
    const std::string TESTALIAS = "LegacyKeystoreTestAlias";
    ASSERT_TRUE(LegacyKeystoreRemove(TESTALIAS, AID_WIFI));
    ASSERT_TRUE(LegacyKeystorePut(TESTALIAS, TESTBLOB));
    auto blob = LegacyKeystoreGet(TESTALIAS);
    ASSERT_TRUE((bool)blob);
    ASSERT_EQ(*blob, TESTBLOB);
    ASSERT_TRUE(LegacyKeystoreRemove(TESTALIAS, AID_WIFI));
}

TEST_P(WifiLegacyKeystoreTest, GetLegacyKeystoreTest) {
    if (!isDebuggableBuild() || getuid() != 0) {
        GTEST_SKIP() << "Device not running a debuggable build or not running as root. "
                     << "Cannot transition to AID_SYSTEM.";
    }

    // Only AID_SYSTEM (and AID_WIFI) is allowed to manipulate
    ASSERT_EQ(0, seteuid(AID_SYSTEM)) << "Failed to set uid to AID_SYSTEM: " << strerror(errno);

    const std::vector<uint8_t> TESTBLOB{1, 2, 3, 5};
    const std::string TESTALIAS = "LegacyKeystoreWifiTestAlias";

    ASSERT_TRUE(LegacyKeystoreRemove(TESTALIAS, AID_WIFI));
    ASSERT_TRUE(LegacyKeystorePut(TESTALIAS, TESTBLOB, AID_WIFI));

    IKeystore::KeystoreStatusCode statusCode;
    std::vector<uint8_t> blob;
    auto rc = wifiKeystoreHal->getBlob(TESTALIAS,
                                       [&](IKeystore::KeystoreStatusCode status,
                                           const ::android::hardware::hidl_vec<uint8_t>& value) {
                                           statusCode = status;
                                           blob = value;
                                       });

    ASSERT_TRUE(rc.isOk()) << "Description: " << rc.description();
    ASSERT_EQ(IKeystore::KeystoreStatusCode::SUCCESS, statusCode);
    ASSERT_EQ(TESTBLOB, blob);

    ASSERT_TRUE(LegacyKeystoreRemove(TESTALIAS, AID_WIFI));
}

}  // namespace
