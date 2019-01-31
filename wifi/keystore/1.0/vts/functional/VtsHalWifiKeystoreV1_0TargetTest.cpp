/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <android-base/logging.h>

#include <VtsHalHidlTargetTestBase.h>
#include <binder/ProcessState.h>
#include <keymasterV4_0/authorization_set.h>
#include <keystore/keystore_promises.h>
#include <private/android_filesystem_config.h>
#include <utils/String16.h>
#include <wifikeystorehal/keystore.h>

using namespace std;
using namespace ::testing;
using namespace android;
using namespace android::binder;
using namespace android::security::keystore;
using namespace android::security::keymaster;
using namespace android::system::wifi::keystore::V1_0;

int main(int argc, char** argv) {
    // Start thread pool for Binder
    android::ProcessState::self()->startThreadPool();

    InitGoogleTest(&argc, argv);
    int status = RUN_ALL_TESTS();
    return status;
}

namespace {

enum KeyPurpose {
    ENCRYPTION,
    SIGNING,
};

// The fixture for testing the Wifi Keystore HAL
class WifiKeystoreHalTest : public Test {
   protected:
    void SetUp() override {
        keystore = implementation::HIDL_FETCH_IKeystore(nullptr);

        sp<android::IServiceManager> service_manager = android::defaultServiceManager();
        sp<android::IBinder> keystore_binder =
            service_manager->getService(String16(kKeystoreServiceName));
        service = interface_cast<IKeystoreService>(keystore_binder);

        EXPECT_NE(nullptr, service.get());

        deleteKey(kTestKeyName);
    }

    void TearDown() override { deleteKey(kTestKeyName); }

    /**
     * Delete a key if it exists.
     *
     * @param keyName: name of the key to delete
     *
     * @return true iff the key existed and is now deleted, false otherwise.
     */
    bool deleteKey(std::string keyName) {
        String16 keyName16(keyName.data(), keyName.size());
        int32_t result;
        auto binder_result = service->del(keyName16, -1 /* process' uid*/, &result);
        if (!binder_result.isOk()) {
            cout << "deleteKey: failed binder call" << endl;
            return false;
        }

        keystore::KeyStoreNativeReturnCode wrappedResult(result);
        return wrappedResult.isOk();
    }

    /**
     * Generate a key for a specific purpose.
     *
     * This generates a key which can be used either for signing
     * or encryption. The signing key is setup to be used in
     * the Wifi Keystore HAL's sign() call. The data
     * about the key returning from its generation is discarded.
     * If this returns 'true' the key generation has completed
     * and the key is ready for use.
     *
     * @param keyName: name of the key to generate
     * @param purpose: the purpose the generated key will support
     *
     * @return true iff the key was successfully generated and is
     * ready for use, false otherwise.
     */
    bool generateKey(std::string keyName, KeyPurpose purpose) {
        constexpr uint32_t kAESKeySize = 256;

        int32_t aidl_return;
        vector<uint8_t> entropy;
        keystore::AuthorizationSetBuilder key_parameters;
        if (purpose == KeyPurpose::SIGNING) {
            key_parameters.EcdsaSigningKey(kAESKeySize);
        }

        if (purpose == KeyPurpose::ENCRYPTION) {
            key_parameters.AesEncryptionKey(kAESKeySize);
        }

        key_parameters.NoDigestOrPadding()
            .Authorization(keystore::keymaster::TAG_BLOCK_MODE, keystore::keymaster::BlockMode::CBC)
            .Authorization(keystore::keymaster::TAG_NO_AUTH_REQUIRED);

        sp<keystore::KeyCharacteristicsPromise> promise(new keystore::KeyCharacteristicsPromise);
        auto future = promise->get_future();

        String16 keyName16(keyName.data(), keyName.size());

        fflush(stdout);
        auto binder_result = service->generateKey(
            promise, keyName16, KeymasterArguments(key_parameters.hidl_data()), entropy,
            -1,  // create key for process' uid
            0,   // empty flags; pick default key provider
            &aidl_return);

        if (!binder_result.isOk()) {
            cout << "generateKey: Failed binder call" << endl;
            return false;
        }

        keystore::KeyStoreNativeReturnCode rc(aidl_return);
        if (!rc.isOk()) {
            cout << "generateKey: Failed to generate key" << endl;
            return false;
        }

        auto [km_response, characteristics] = future.get();

        return true;
    }

    /**
     * Creates a TYPE_GENERIC key blob. This cannot be used for signing.
     *
     * @param keyName: name of the key to generate.
     *
     * @returns true iff the key was successfully created, false otherwise.
     */
    bool insert(std::string keyName) {
        int32_t aidl_return;
        vector<uint8_t> item;

        String16 keyName16(keyName.data(), keyName.size());
        auto binder_result = service->insert(keyName16, item,
                                             -1,  // Use process' uid
                                             0,   // empty flags; pick default key provider
                                             &aidl_return);

        if (!binder_result.isOk()) {
            cout << "insert: Failed binder call" << endl;
            return false;
        }

        keystore::KeyStoreNativeReturnCode rc(aidl_return);
        if (!rc.isOk()) {
            cout << "insert: Failed to generate key" << endl;
            return false;
        }

        return true;
    }

    constexpr static const char kKeystoreServiceName[] = "android.security.keystore";
    constexpr static const char kTestKeyName[] = "TestKeyName";

    IKeystore* keystore = nullptr;
    sp<IKeystoreService> service;
};

/**
 * Test for the Wifi Keystore HAL's sign() call.
 */
TEST_F(WifiKeystoreHalTest, Sign) {
    IKeystore::KeystoreStatusCode statusCode;

    auto callback = [&statusCode](IKeystore::KeystoreStatusCode status,
                                  const ::android::hardware::hidl_vec<uint8_t>& /*value*/) {
        statusCode = status;
        return;
    };

    ::android::hardware::hidl_vec<uint8_t> dataToSign;

    // These attempts do not include an existing key to use

    keystore->sign(nullptr, dataToSign, callback);
    EXPECT_EQ(IKeystore::KeystoreStatusCode::ERROR_UNKNOWN, statusCode);

    keystore->sign("", dataToSign, callback);
    EXPECT_EQ(IKeystore::KeystoreStatusCode::ERROR_UNKNOWN, statusCode);

    bool result = generateKey(kTestKeyName, KeyPurpose::SIGNING);
    EXPECT_EQ(result, true);

    // The data to sign is empty, and a failure is expected

    keystore->sign(kTestKeyName, dataToSign, callback);
    EXPECT_EQ(IKeystore::KeystoreStatusCode::ERROR_UNKNOWN, statusCode);

    // With data the signing attempt should succeed

    dataToSign.resize(100);
    keystore->sign(kTestKeyName, dataToSign, callback);
    EXPECT_EQ(IKeystore::KeystoreStatusCode::SUCCESS, statusCode);

    // Create a key which cannot sign; any signing attempt should fail.

    result = deleteKey(kTestKeyName);
    EXPECT_EQ(result, true);

    result = generateKey(kTestKeyName, KeyPurpose::ENCRYPTION);
    EXPECT_EQ(result, true);

    keystore->sign(kTestKeyName, dataToSign, callback);
    EXPECT_EQ(IKeystore::KeystoreStatusCode::ERROR_UNKNOWN, statusCode);

    // Generate a TYPE_GENERIC key instead of a TYPE_KEYMASTER_10 key.
    // This also cannot be used to sign.

    result = deleteKey(kTestKeyName);
    EXPECT_EQ(result, true);

    result = insert(kTestKeyName);
    EXPECT_EQ(result, true);

    keystore->sign(kTestKeyName, dataToSign, callback);
    EXPECT_EQ(IKeystore::KeystoreStatusCode::ERROR_UNKNOWN, statusCode);
}

}  // namespace
