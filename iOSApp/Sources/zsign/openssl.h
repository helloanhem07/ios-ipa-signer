//
//  openssl.h
//  iOSApp
//
//  Cryptographic engine managing PKCS#12, X.509, CMS signatures, and DER entitlements.
//

#ifndef ZSIGN_OPENSSL_H
#define ZSIGN_OPENSSL_H

#include "common.h"
#include <string>
#include <vector>

// Forward declarations for OpenSSL structures to avoid leaking OpenSSL types into headers
typedef struct evp_pkey_st EVP_PKEY;
typedef struct x509_st X509;
typedef struct stack_st_X509 STACK_OF_X509;

class ZSignAsset {
public:
    ZSignAsset();
    ~ZSignAsset();

    bool Init(const std::string &strP12File,
              const std::string &strP12Password,
              const std::string &strProvisionFile,
              const std::string &strEntitlements);

    bool GenerateCMS(const std::string &codeDirectoryHash, std::string &cmsOutput);

    const std::string &GetEntitlements() const { return m_strEntitlementsData; }
    const std::string &GetDEREntitlements() const { return m_derEntitlementsData; }
    const std::string &GetTeamID() const { return m_strTeamID; }
    const std::string &GetLastError() const { return m_strLastError; }

    static void InitializeProviders();
    static bool GenerateDEREntitlements(const std::string &xmlEntitlements, std::string &derOutput);
    static bool Sha1(const std::string &input, std::string &output);
    static bool Sha256(const std::string &input, std::string &output);

private:
    bool LoadProvisioningProfile(const std::string &strProvisionFile);
    void Free();

    EVP_PKEY *m_pKey;
    X509 *m_pCert;
    void *m_pCAChain; // STACK_OF(X509)*
    std::string m_strEntitlementsData;
    std::string m_derEntitlementsData;
    std::string m_strTeamID;
    std::string m_strLastError;
};

#endif // ZSIGN_OPENSSL_H
