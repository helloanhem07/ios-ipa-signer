//
//  zsign.h
//  iOSApp
//
//  High-level C++ zsign engine interface adapted for in-process iOS execution.
//

#ifndef ZSIGN_H
#define ZSIGN_H

#include "common.h"
#include "openssl.h"
#include "macho.h"
#include "bundle.h"
#include <string>

class ZSignEngine {
public:
    ZSignEngine();
    ~ZSignEngine();

    static const char *GetVersion() {
        return "2.1.0-ios-embedded";
    }

    bool Sign(const std::string &strAppFolder,
              const std::string &strP12Path,
              const std::string &strP12Password,
              const std::string &strProvisioningPath,
              const std::string &strBundleId,
              const std::string &strDisplayName,
              const std::string &strEntitlementsPath,
              ZAppBundle::ProgressCallback progressCallback);

    const std::string &GetLastError() const { return m_strLastError; }

private:
    std::string m_strLastError;
};

#endif // ZSIGN_H
