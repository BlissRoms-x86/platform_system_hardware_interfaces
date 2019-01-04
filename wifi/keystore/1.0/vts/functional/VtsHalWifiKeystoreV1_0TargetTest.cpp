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

        resetState();
    }

    void TearDown() override { resetState(); }

    /**
     * Resets the relevant state of the system between tests
     */
    void resetState() {
        for (uid_t uid : {UID_SELF, AID_WIFI}) {
            deleteKey(kTestKeyName, uid);
        }
    }

    /**
     * Delete a key if it exists.
     *
     * @param keyName: name of the key to delete
     * @param uid: the uid to delete the key on behalf of. Use
     *        UID_SELF to use the process' uid.
     *
     * @return true iff the key existed and is now deleted, false otherwise.
     */
    bool deleteKey(std::string keyName, uid_t uid) {
        String16 keyName16(keyName.data(), keyName.size());
        int32_t result;
        auto binder_result = service->del(keyName16, uid, &result);
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
     * @param uid: the uid to generate the key on behalf of. Use
     *        UID_SELF to use the process' uid.
     *
     * @return true iff the key was successfully generated and is
     * ready for use, false otherwise.
     */
    bool generateKey(std::string keyName, KeyPurpose purpose, uid_t uid) {
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
            uid,  // create key for process' uid
            0,    // empty flags; pick default key provider
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
     * @param uid: the uid to insert the key on behalf of. Use
     *        UID_SELF to use the process' uid.
     *
     * @returns true iff the key was successfully created, false otherwise.
     */
    bool insert(std::string keyName, uid_t uid) {
        int32_t aidl_return;
        vector<uint8_t> item;

        String16 keyName16(keyName.data(), keyName.size());
        auto binder_result = service->insert(keyName16, item,
                                             uid,  // Use process' uid
                                             0,    // empty flags; pick default key provider
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
    constexpr static const int32_t UID_SELF = -1;

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

    bool result = generateKey(kTestKeyName, KeyPurpose::SIGNING, UID_SELF);
    EXPECT_EQ(result, true);

    // The data to sign is empty, and a failure is expected

    keystore->sign(kTestKeyName, dataToSign, callback);
    EXPECT_EQ(IKeystore::KeystoreStatusCode::ERROR_UNKNOWN, statusCode);

    // With data the signing attempt should succeed

    dataToSign.resize(100);
    keystore->sign(kTestKeyName, dataToSign, callback);
    EXPECT_EQ(IKeystore::KeystoreStatusCode::SUCCESS, statusCode);

    // Create a key which cannot sign; any signing attempt should fail.

    result = deleteKey(kTestKeyName, UID_SELF);
    EXPECT_EQ(result, true);

    result = generateKey(kTestKeyName, KeyPurpose::ENCRYPTION, UID_SELF);
    EXPECT_EQ(result, true);

    keystore->sign(kTestKeyName, dataToSign, callback);
    EXPECT_EQ(IKeystore::KeystoreStatusCode::ERROR_UNKNOWN, statusCode);

    // Generate a TYPE_GENERIC key instead of a TYPE_KEYMASTER_10 key.
    // This also cannot be used to sign.

    result = deleteKey(kTestKeyName, UID_SELF);
    EXPECT_EQ(result, true);

    result = insert(kTestKeyName, UID_SELF);
    EXPECT_EQ(result, true);

    keystore->sign(kTestKeyName, dataToSign, callback);
    EXPECT_EQ(IKeystore::KeystoreStatusCode::ERROR_UNKNOWN, statusCode);
}

/**
 * Test for the Wifi Keystore HAL's getBlob() call.
 */
TEST_F(WifiKeystoreHalTest, GetBlob) {
    IKeystore::KeystoreStatusCode statusCode;

    auto callback = [&statusCode](IKeystore::KeystoreStatusCode status,
                                  const ::android::hardware::hidl_vec<uint8_t>& /*value*/) {
        statusCode = status;
        return;
    };

    // Attempting to get a blob on a non-existent key should fail.

    statusCode = IKeystore::KeystoreStatusCode::SUCCESS;
    keystore->getBlob(nullptr, callback);
    EXPECT_EQ(IKeystore::KeystoreStatusCode::ERROR_UNKNOWN, statusCode);

    statusCode = IKeystore::KeystoreStatusCode::SUCCESS;
    keystore->getBlob("", callback);
    EXPECT_EQ(IKeystore::KeystoreStatusCode::ERROR_UNKNOWN, statusCode);

    statusCode = IKeystore::KeystoreStatusCode::SUCCESS;
    keystore->getBlob(kTestKeyName, callback);
    EXPECT_EQ(IKeystore::KeystoreStatusCode::ERROR_UNKNOWN, statusCode);

    // The HAL is expecting the key to belong to the wifi user.
    // If the key belongs to another user's space it should fail.

    bool result = insert(kTestKeyName, UID_SELF);
    EXPECT_EQ(result, true);

    keystore->getBlob(kTestKeyName, callback);
    EXPECT_EQ(IKeystore::KeystoreStatusCode::ERROR_UNKNOWN, statusCode);

    result = deleteKey(kTestKeyName, UID_SELF);
    EXPECT_EQ(result, true);

    // Accessing the key belonging to the wifi user should succeed.

    result = insert(kTestKeyName, AID_WIFI);
    EXPECT_EQ(result, true);

    keystore->getBlob(kTestKeyName, callback);
    EXPECT_EQ(IKeystore::KeystoreStatusCode::SUCCESS, statusCode);

    result = deleteKey(kTestKeyName, AID_WIFI);
    EXPECT_EQ(result, true);
}

/**
 * Test for the Wifi Keystore HAL's getPublicKey() call.
 */
TEST_F(WifiKeystoreHalTest, GetPublicKey) {
    IKeystore::KeystoreStatusCode statusCode;

    auto callback = [&statusCode](IKeystore::KeystoreStatusCode status,
                                  const ::android::hardware::hidl_vec<uint8_t>& /*value*/) {
        statusCode = status;
        return;
    };

    // Attempting to export a non-existent key should fail.

    statusCode = IKeystore::KeystoreStatusCode::SUCCESS;
    keystore->getPublicKey(nullptr, callback);
    EXPECT_EQ(IKeystore::KeystoreStatusCode::ERROR_UNKNOWN, statusCode);

    statusCode = IKeystore::KeystoreStatusCode::SUCCESS;
    keystore->getPublicKey("", callback);
    EXPECT_EQ(IKeystore::KeystoreStatusCode::ERROR_UNKNOWN, statusCode);

    statusCode = IKeystore::KeystoreStatusCode::SUCCESS;
    keystore->getPublicKey(kTestKeyName, callback);
    EXPECT_EQ(IKeystore::KeystoreStatusCode::ERROR_UNKNOWN, statusCode);

    // The HAL is expecting the key to belong to the process' user.
    // If the key belongs to another user's space (e.g. wifi) it should
    // not be accessible and should fail.

    bool result = generateKey(kTestKeyName, KeyPurpose::SIGNING, AID_WIFI);
    EXPECT_EQ(result, true);

    keystore->getPublicKey(kTestKeyName, callback);
    EXPECT_EQ(IKeystore::KeystoreStatusCode::ERROR_UNKNOWN, statusCode);

    result = deleteKey(kTestKeyName, AID_WIFI);
    EXPECT_EQ(result, true);

    // Accessing the key belonging to the process' uid should succeed.

    result = generateKey(kTestKeyName, KeyPurpose::SIGNING, UID_SELF);
    EXPECT_EQ(result, true);

    keystore->getPublicKey(kTestKeyName, callback);
    EXPECT_EQ(IKeystore::KeystoreStatusCode::SUCCESS, statusCode);

    result = deleteKey(kTestKeyName, UID_SELF);
    EXPECT_EQ(result, true);

    // A TYPE_GENERIC key (instead of a TYPE_KEYMASTER_10 key)
    // should also fail.

    result = insert(kTestKeyName, UID_SELF);
    EXPECT_EQ(result, true);

    keystore->getPublicKey(kTestKeyName, callback);
    EXPECT_EQ(IKeystore::KeystoreStatusCode::ERROR_UNKNOWN, statusCode);

    result = deleteKey(kTestKeyName, UID_SELF);
    EXPECT_EQ(result, true);
}

}  // namespace
