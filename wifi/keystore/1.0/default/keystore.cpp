#include <aidl/android/system/keystore2/IKeystoreService.h>
#include <android-base/logging.h>
#include <android-base/strings.h>
#include <android/binder_manager.h>
#include <binder/IServiceManager.h>
#include <private/android_filesystem_config.h>

#include <future>
#include <vector>
#include "include/wifikeystorehal/keystore.h"

#include <ctype.h>
#include <openssl/base.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AT __func__ << ":" << __LINE__ << " "

namespace ks2 = ::aidl::android::system::keystore2;
namespace KMV1 = ::aidl::android::hardware::security::keymint;

namespace {

constexpr const int64_t KS2_NAMESPACE_WIFI = 102;

constexpr const char kKeystore2ServiceName[] = "android.system.keystore2";

const std::string keystore2_grant_id_prefix("ks2_keystore-engine_grant_id:");

// Helper method to extract public key from the certificate.
std::vector<uint8_t> extractPubKey(const std::vector<uint8_t>& cert_bytes) {
    bssl::UniquePtr<BIO> cert_bio(BIO_new_mem_buf(cert_bytes.data(), cert_bytes.size()));
    if (!cert_bio) {
        LOG(ERROR) << AT << "Failed to create BIO";
        return {};
    }
    bssl::UniquePtr<X509> decoded_cert(d2i_X509_bio(cert_bio.get(), nullptr));
    if (!decoded_cert) {
        LOG(INFO) << AT << "Could not decode the cert, trying decoding as PEM";
        decoded_cert =
            bssl::UniquePtr<X509>(PEM_read_bio_X509(cert_bio.get(), nullptr, nullptr, nullptr));
    }
    if (!decoded_cert) {
        LOG(ERROR) << AT << "Could not decode the cert.";
        return {};
    }
    bssl::UniquePtr<EVP_PKEY> pub_key(X509_get_pubkey(decoded_cert.get()));
    if (!pub_key) {
        LOG(ERROR) << AT << "Could not extract public key.";
        return {};
    }
    bssl::UniquePtr<BIO> pub_key_bio(BIO_new(BIO_s_mem()));
    if (!pub_key_bio || i2d_PUBKEY_bio(pub_key_bio.get(), pub_key.get()) <= 0) {
        LOG(ERROR) << AT << "Could not serialize public key.";
        return {};
    }
    const uint8_t* pub_key_bytes;
    size_t pub_key_len;
    if (!BIO_mem_contents(pub_key_bio.get(), &pub_key_bytes, &pub_key_len)) {
        LOG(ERROR) << AT << "Could not get bytes from BIO.";
        return {};
    }

    return {pub_key_bytes, pub_key_bytes + pub_key_len};
}

ks2::KeyDescriptor mkKeyDescriptor(const std::string& alias) {
    // If the key_id starts with the grant id prefix, we parse the following string as numeric
    // grant id. We can then use the grant domain without alias to load the designated key.
    if (android::base::StartsWith(alias, keystore2_grant_id_prefix)) {
        std::stringstream s(alias.substr(keystore2_grant_id_prefix.size()));
        uint64_t tmp;
        s >> std::hex >> tmp;
        if (s.fail() || !s.eof()) {
            LOG(ERROR) << AT << "Couldn't parse grant name: " << alias;
        }
        return {
            .nspace = static_cast<int64_t>(tmp),
            .domain = ks2::Domain::GRANT,
            .alias = std::nullopt,
            .blob = std::nullopt,
        };
    } else {
        return {
            .domain = ks2::Domain::SELINUX,
            .nspace = KS2_NAMESPACE_WIFI,
            .alias = alias,
            .blob = std::nullopt,
        };
    }
}

using android::hardware::hidl_string;
using android::hardware::hidl_vec;

std::optional<std::vector<uint8_t>> keyStore2GetCert(const hidl_string& key) {
    ::ndk::SpAIBinder keystoreBinder(AServiceManager_checkService(kKeystore2ServiceName));
    auto keystore2 = ks2::IKeystoreService::fromBinder(keystoreBinder);

    if (!keystore2) {
        LOG(WARNING) << AT << "Unable to connect to Keystore 2.0.";
        return {};
    }

    bool ca_cert = false;
    std::string alias = key.c_str();
    if (android::base::StartsWith(alias, "CACERT_")) {
        alias = alias.substr(7);
        ca_cert = true;
    } else if (android::base::StartsWith(alias, "USRCERT_")) {
        alias = alias.substr(8);
    }

    ks2::KeyDescriptor descriptor = mkKeyDescriptor(alias);

    // If the key_id starts with the grant id prefix, we parse the following string as numeric
    // grant id. We can then use the grant domain without alias to load the designated key.
    if (android::base::StartsWith(alias, keystore2_grant_id_prefix)) {
        std::stringstream s(alias.substr(keystore2_grant_id_prefix.size()));
        uint64_t tmp;
        s >> std::hex >> tmp;
        if (s.fail() || !s.eof()) {
            LOG(ERROR) << AT << "Couldn't parse grant name: " << alias;
        }
        descriptor.nspace = static_cast<int64_t>(tmp);
        descriptor.domain = ks2::Domain::GRANT;
        descriptor.alias = std::nullopt;
    }

    ks2::KeyEntryResponse response;
    auto rc = keystore2->getKeyEntry(descriptor, &response);
    if (!rc.isOk()) {
        auto exception_code = rc.getExceptionCode();
        if (exception_code == EX_SERVICE_SPECIFIC) {
            LOG(ERROR) << AT << "Keystore getKeyEntry returned service specific error: "
                       << rc.getServiceSpecificError();
        } else {
            LOG(ERROR) << AT << "Communication with Keystore getKeyEntry failed error: "
                       << exception_code;
        }
        return {};
    }

    if (ca_cert && response.metadata.certificateChain) {
        return std::move(*response.metadata.certificateChain);
    } else if (!ca_cert && response.metadata.certificate) {
        return std::move(*response.metadata.certificate);
    } else {
        LOG(ERROR) << AT << "No " << (ca_cert ? "CA" : "client") << " certificate found.";
        return {};
    }
}

std::optional<std::vector<uint8_t>> keyStore2GetPubKey(const hidl_string& key) {
    ::ndk::SpAIBinder keystoreBinder(AServiceManager_checkService(kKeystore2ServiceName));
    auto keystore2 = ks2::IKeystoreService::fromBinder(keystoreBinder);

    if (!keystore2) {
        LOG(WARNING) << AT << "Unable to connect to Keystore 2.0.";
        return std::nullopt;
    }

    std::string alias = key.c_str();
    if (android::base::StartsWith(alias, "USRPKEY_")) {
        alias = alias.substr(8);
    }

    ks2::KeyDescriptor descriptor = mkKeyDescriptor(alias);

    ks2::KeyEntryResponse response;
    auto rc = keystore2->getKeyEntry(descriptor, &response);
    if (!rc.isOk()) {
        auto exception_code = rc.getExceptionCode();
        if (exception_code == EX_SERVICE_SPECIFIC) {
            LOG(ERROR) << AT << "Keystore getKeyEntry returned service specific error: "
                       << rc.getServiceSpecificError();
        } else {
            LOG(ERROR) << AT << "Communication with Keystore getKeyEntry failed error: "
                       << exception_code;
        }
        return std::nullopt;
    }

    if (!response.metadata.certificate) {
        LOG(ERROR) << AT << "No public key found.";
        return std::nullopt;
    }

    std::optional<std::vector<uint8_t>> pub_key(extractPubKey(*response.metadata.certificate));
    return std::move(pub_key);
}

std::optional<std::vector<uint8_t>> keyStore2Sign(const hidl_string& key,
                                                  const hidl_vec<uint8_t>& dataToSign) {
    ::ndk::SpAIBinder keystoreBinder(AServiceManager_checkService(kKeystore2ServiceName));
    auto keystore2 = ks2::IKeystoreService::fromBinder(keystoreBinder);

    if (!keystore2) {
        LOG(WARNING) << AT << "Unable to connect to Keystore 2.0.";
        return std::nullopt;
    }

    std::string alias = key.c_str();
    if (android::base::StartsWith(alias, "USRPKEY_")) {
        alias = alias.substr(8);
    }

    ks2::KeyDescriptor descriptor = mkKeyDescriptor(alias);

    ks2::KeyEntryResponse response;
    auto rc = keystore2->getKeyEntry(descriptor, &response);
    if (!rc.isOk()) {
        auto exception_code = rc.getExceptionCode();
        if (exception_code == EX_SERVICE_SPECIFIC) {
            LOG(ERROR) << AT << "Keystore getKeyEntry returned service specific error: "
                       << rc.getServiceSpecificError();
        } else {
            LOG(ERROR) << AT << "Communication with Keystore getKeyEntry failed error: "
                       << exception_code;
        }
        return std::nullopt;
    }

    std::optional<KMV1::Algorithm> algorithm;
    for (auto& element : response.metadata.authorizations) {
        if (element.keyParameter.tag == KMV1::Tag::ALGORITHM) {
            algorithm = element.keyParameter.value.get<KMV1::KeyParameterValue::algorithm>();
        }
    }

    if (!algorithm) {
        LOG(ERROR) << AT << "Could not find signing algorithm.";
        return std::nullopt;
    }

    auto sec_level = response.iSecurityLevel;

    std::vector<KMV1::KeyParameter> op_params(4);
    op_params[0] = KMV1::KeyParameter{
        .tag = KMV1::Tag::PURPOSE,
        .value = KMV1::KeyParameterValue::make<KMV1::KeyParameterValue::keyPurpose>(
            KMV1::KeyPurpose::SIGN)};
    op_params[1] = KMV1::KeyParameter{
        .tag = KMV1::Tag::ALGORITHM,
        .value = KMV1::KeyParameterValue::make<KMV1::KeyParameterValue::algorithm>(*algorithm)};
    op_params[2] = KMV1::KeyParameter{
        .tag = KMV1::Tag::PADDING,
        .value = KMV1::KeyParameterValue::make<KMV1::KeyParameterValue::paddingMode>(
            KMV1::PaddingMode::NONE)};
    op_params[3] = KMV1::KeyParameter{
        .tag = KMV1::Tag::DIGEST,
        .value =
            KMV1::KeyParameterValue::make<KMV1::KeyParameterValue::digest>(KMV1::Digest::NONE)};

    ks2::CreateOperationResponse op_response;

    rc = sec_level->createOperation(descriptor, op_params, false /* forced */, &op_response);
    if (!rc.isOk()) {
        auto exception_code = rc.getExceptionCode();
        if (exception_code == EX_SERVICE_SPECIFIC) {
            LOG(ERROR) << AT << "Keystore createOperation returned service specific error: "
                       << rc.getServiceSpecificError();
        } else {
            LOG(ERROR) << AT << "Communication with Keystore createOperation failed error: "
                       << exception_code;
        }
        return std::nullopt;
    }

    auto op = op_response.iOperation;
    std::optional<std::vector<uint8_t>> output = std::nullopt;

    rc = op->finish(dataToSign, {}, &output);
    if (!rc.isOk()) {
        auto exception_code = rc.getExceptionCode();
        if (exception_code == EX_SERVICE_SPECIFIC) {
            LOG(ERROR) << AT << "Keystore finish returned service specific error: "
                       << rc.getServiceSpecificError();
        } else {
            LOG(ERROR) << AT
                       << "Communication with Keystore finish failed error: " << exception_code;
        }
        return std::nullopt;
    }

    if (!output) {
        LOG(ERROR) << AT << "Could not get a signature from Keystore.";
    }

    return output;
}

};  // namespace


namespace android {
namespace system {
namespace wifi {
namespace keystore {
namespace V1_0 {
namespace implementation {

// Methods from ::android::hardware::wifi::keystore::V1_0::IKeystore follow.
Return<void> Keystore::getBlob(const hidl_string& key, getBlob_cb _hidl_cb) {
    ::std::vector<uint8_t> value;

    if (auto ks2_cert = keyStore2GetCert(key)) {
        value = std::move(*ks2_cert);
    } else {
        LOG(ERROR) << AT << "Failed to get certificate.";
        _hidl_cb(KeystoreStatusCode::ERROR_UNKNOWN, {});
    }
    return Void();
}

Return<void> Keystore::getPublicKey(const hidl_string& keyId, getPublicKey_cb _hidl_cb) {
    if (auto ks2_pubkey = keyStore2GetPubKey(keyId)) {
        _hidl_cb(KeystoreStatusCode::SUCCESS, std::move(*ks2_pubkey));
    } else {
        LOG(ERROR) << AT << "Failed to get public key.";
        _hidl_cb(KeystoreStatusCode::ERROR_UNKNOWN, {});
    }
    return Void();
}

Return<void> Keystore::sign(const hidl_string& keyId, const hidl_vec<uint8_t>& dataToSign,
                            sign_cb _hidl_cb) {
    if (auto ks2_result = keyStore2Sign(keyId, dataToSign)) {
        _hidl_cb(KeystoreStatusCode::SUCCESS, std::move(*ks2_result));
    } else {
        LOG(ERROR) << AT << "Failed to sign.";
        _hidl_cb(KeystoreStatusCode::ERROR_UNKNOWN, {});
    }
    return Void();
}

IKeystore* HIDL_FETCH_IKeystore(const char* /* name */) {
    return new Keystore();
}
}  // namespace implementation
}  // namespace V1_0
}  // namespace keystore
}  // namespace wifi
}  // namespace system
}  // namespace android
