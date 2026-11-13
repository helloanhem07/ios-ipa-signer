//
//  openssl.cpp
//  iOSApp
//
//  Cryptographic engine implementation using OpenSSL for in-process iOS signing.
//

#include "openssl.h"
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/cms.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
static OSSL_PROVIDER *g_legacyProvider = nullptr;
static OSSL_PROVIDER *g_defaultProvider = nullptr;
#endif

void ZSignAsset::InitializeProviders() {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (!g_legacyProvider) {
        g_legacyProvider = OSSL_PROVIDER_load(NULL, "legacy");
    }
    if (!g_defaultProvider) {
        g_defaultProvider = OSSL_PROVIDER_load(NULL, "default");
    }
#endif
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

ZSignAsset::ZSignAsset()
    : m_pKey(nullptr), m_pCert(nullptr), m_pCAChain(nullptr) {}

ZSignAsset::~ZSignAsset() {
    Free();
}

void ZSignAsset::Free() {
    if (m_pKey) {
        EVP_PKEY_free(m_pKey);
        m_pKey = nullptr;
    }
    if (m_pCert) {
        X509_free(m_pCert);
        m_pCert = nullptr;
    }
    if (m_pCAChain) {
        sk_X509_pop_free(reinterpret_cast<STACK_OF(X509) *>(m_pCAChain), X509_free);
        m_pCAChain = nullptr;
    }
}

bool ZSignAsset::Init(const std::string &strP12File,
                      const std::string &strP12Password,
                      const std::string &strProvisionFile,
                      const std::string &strEntitlements) {
    Free();
    InitializeProviders();

    // 1. Read .p12 binary file
    BIO *p12Bio = BIO_new_file(strP12File.c_str(), "rb");
    if (!p12Bio) {
        m_strLastError = "Failed to open PKCS#12 certificate file at: " + strP12File;
        return false;
    }

    PKCS12 *p12 = d2i_PKCS12_bio(p12Bio, NULL);
    BIO_free(p12Bio);
    if (!p12) {
        m_strLastError = "Failed to deserialize PKCS#12 container (corrupt or invalid format).";
        return false;
    }

    // 2. Parse PKCS#12 with password
    EVP_PKEY *pKey = NULL;
    X509 *pCert = NULL;
    STACK_OF(X509) *pCAStack = NULL;

    int parseRes = PKCS12_parse(p12, strP12Password.c_str(), &pKey, &pCert, &pCAStack);
    PKCS12_free(p12);

    if (parseRes != 1 || !pKey || !pCert) {
        char errBuf[256] = {0};
        ERR_error_string_n(ERR_get_error(), errBuf, sizeof(errBuf));
        m_strLastError = std::string("PKCS#12 decryption failed. Incorrect password or cipher: ") + errBuf;
        if (pKey) EVP_PKEY_free(pKey);
        if (pCert) X509_free(pCert);
        if (pCAStack) sk_X509_pop_free(pCAStack, X509_free);
        return false;
    }

    m_pKey = pKey;
    m_pCert = pCert;
    m_pCAChain = pCAStack;

    // Extract Team Identifier from subject OU if present
    X509_NAME *pSubject = X509_get_subject_name(pCert);
    if (pSubject) {
        int nid = NID_organizationalUnitName;
        int index = X509_NAME_get_index_by_NID(pSubject, nid, -1);
        if (index >= 0) {
            X509_NAME_ENTRY *entry = X509_NAME_get_entry(pSubject, index);
            if (entry) {
                ASN1_STRING *data = X509_NAME_ENTRY_get_data(entry);
                if (data && data->data) {
                    m_strTeamID = std::string((char *)data->data, data->length);
                }
            }
        }
    }

    // 3. Load Provisioning Profile Entitlements
    if (!LoadProvisioningProfile(strProvisionFile)) {
        return false;
    }

    // 4. Override with Custom Entitlements if specified
    if (!strEntitlements.empty()) {
        std::string customXML;
        if (ReadFile(strEntitlements.c_str(), customXML)) {
            m_strEntitlementsData = customXML;
        }
    }

    // 5. Generate DER-encoded entitlements for iOS 15+
    GenerateDEREntitlements(m_strEntitlementsData, m_derEntitlementsData);

    return true;
}

bool ZSignAsset::LoadProvisioningProfile(const std::string &strProvisionFile) {
    std::string profileData;
    if (!ReadFile(strProvisionFile.c_str(), profileData)) {
        m_strLastError = "Failed to read provisioning profile from: " + strProvisionFile;
        return false;
    }

    // Provisioning profiles are CMS signed data. Extract the inner XML plist.
    BIO *inBio = BIO_new_mem_buf(profileData.data(), (int)profileData.size());
    if (!inBio) {
        m_strLastError = "Failed to allocate memory buffer for provisioning profile.";
        return false;
    }

    CMS_ContentInfo *cms = d2i_CMS_bio(inBio, NULL);
    BIO_free(inBio);

    std::string xmlPlist;
    if (cms) {
        BIO *outBio = BIO_new(BIO_s_mem());
        if (CMS_dataInit(cms, outBio)) {
            char buf[4096];
            int readBytes = 0;
            while ((readBytes = BIO_read(outBio, buf, sizeof(buf))) > 0) {
                xmlPlist.append(buf, readBytes);
            }
        }
        BIO_free(outBio);
        CMS_ContentInfo_free(cms);
    }

    // Fallback: search for <?xml ... </plist>
    if (xmlPlist.empty()) {
        size_t start = profileData.find("<?xml");
        size_t end = profileData.rfind("</plist>");
        if (start != std::string::npos && end != std::string::npos && end > start) {
            xmlPlist = profileData.substr(start, (end + 8) - start);
        }
    }

    if (xmlPlist.empty()) {
        m_strLastError = "Failed to extract XML content from provisioning profile.";
        return false;
    }

    // Extract <key>Entitlements</key><dict>...</dict>
    size_t entKey = xmlPlist.find("<key>Entitlements</key>");
    if (entKey != std::string::npos) {
        size_t dictStart = xmlPlist.find("<dict>", entKey);
        size_t dictEnd = xmlPlist.find("</dict>", dictStart);
        if (dictStart != std::string::npos && dictEnd != std::string::npos) {
            std::string innerDict = xmlPlist.substr(dictStart, (dictEnd + 7) - dictStart);
            m_strEntitlementsData = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                                    "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
                                    "<plist version=\"1.0\">\n" +
                                    innerDict + "\n</plist>";
        }
    }

    if (m_strEntitlementsData.empty()) {
        // Fallback default minimal entitlements
        m_strEntitlementsData = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                                "<plist version=\"1.0\"><dict></dict></plist>";
    }

    return true;
}

bool ZSignAsset::GenerateCMS(const std::string &codeDirectoryHash, std::string &cmsOutput) {
    if (!m_pKey || !m_pCert) {
        m_strLastError = "Cannot generate CMS: Private key or leaf certificate is missing.";
        return false;
    }

    BIO *bioData = BIO_new_mem_buf(codeDirectoryHash.data(), (int)codeDirectoryHash.size());
    if (!bioData) {
        m_strLastError = "Failed to allocate memory BIO for CodeDirectory hash.";
        return false;
    }

    STACK_OF(X509) *pCAChain = reinterpret_cast<STACK_OF(X509) *>(m_pCAChain);
    CMS_ContentInfo *cms = CMS_sign(NULL, NULL, pCAChain, bioData, CMS_PARTIAL | CMS_BINARY | CMS_NOSIGS);
    if (!cms) {
        BIO_free(bioData);
        m_strLastError = "CMS_sign initialization failed.";
        return false;
    }

    CMS_SignerInfo *si = CMS_add1_signer(cms, m_pCert, m_pKey, EVP_sha256(), CMS_NOATTR | CMS_NOSMIMECAP);
    if (!si) {
        CMS_ContentInfo_free(cms);
        BIO_free(bioData);
        m_strLastError = "Failed to attach CMS signer information.";
        return false;
    }

    if (CMS_final(cms, bioData, NULL, CMS_NOCERTS | CMS_BINARY) != 1) {
        CMS_ContentInfo_free(cms);
        BIO_free(bioData);
        m_strLastError = "CMS_final signature finalization failed.";
        return false;
    }

    int derLen = i2d_CMS_ContentInfo(cms, NULL);
    if (derLen <= 0) {
        CMS_ContentInfo_free(cms);
        BIO_free(bioData);
        m_strLastError = "DER serialization calculation failed.";
        return false;
    }

    cmsOutput.resize(derLen);
    unsigned char *pDer = reinterpret_cast<unsigned char *>(&cmsOutput[0]);
    i2d_CMS_ContentInfo(cms, &pDer);

    CMS_ContentInfo_free(cms);
    BIO_free(bioData);
    return true;
}

bool ZSignAsset::GenerateDEREntitlements(const std::string &xmlEntitlements, std::string &derOutput) {
    // Apple AMFI requires slot 7 (0xfade7172) to contain the DER-encoded entitlements.
    // An ASN.1 OCTET STRING header wraps the raw or encoded entitlement payload.
    // ASN.1 Tag 0x04 = OCTET STRING
    size_t len = xmlEntitlements.size();
    derOutput.clear();
    derOutput.push_back(0x04); // OCTET STRING tag
    if (len < 128) {
        derOutput.push_back((char)len);
    } else if (len <= 0xFF) {
        derOutput.push_back((char)0x81);
        derOutput.push_back((char)len);
    } else if (len <= 0xFFFF) {
        derOutput.push_back((char)0x82);
        derOutput.push_back((char)((len >> 8) & 0xFF));
        derOutput.push_back((char)(len & 0xFF));
    } else {
        derOutput.push_back((char)0x84);
        derOutput.push_back((char)((len >> 24) & 0xFF));
        derOutput.push_back((char)((len >> 16) & 0xFF));
        derOutput.push_back((char)((len >> 8) & 0xFF));
        derOutput.push_back((char)(len & 0xFF));
    }
    derOutput.append(xmlEntitlements);
    return true;
}

bool ZSignAsset::Sha1(const std::string &input, std::string &output) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char *>(input.data()), input.size(), hash);
    output.assign(reinterpret_cast<char *>(hash), SHA_DIGEST_LENGTH);
    return true;
}

bool ZSignAsset::Sha256(const std::string &input, std::string &output) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char *>(input.data()), input.size(), hash);
    output.assign(reinterpret_cast<char *>(hash), SHA256_DIGEST_LENGTH);
    return true;
}
