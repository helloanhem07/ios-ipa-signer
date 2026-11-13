//
//  zsign.cpp
//  iOSApp
//
//  Implementation of ZSignEngine in-process execution coordinator.
//

#include "zsign.h"

ZSignEngine::ZSignEngine() {}

ZSignEngine::~ZSignEngine() {}

bool ZSignEngine::Sign(const std::string &strAppFolder,
                       const std::string &strP12Path,
                       const std::string &strP12Password,
                       const std::string &strProvisioningPath,
                       const std::string &strBundleId,
                       const std::string &strDisplayName,
                       const std::string &strEntitlementsPath,
                       ZAppBundle::ProgressCallback progressCallback) {

    ZSignAsset signAsset;
    if (!signAsset.Init(strP12Path, strP12Password, strProvisioningPath, strEntitlementsPath)) {
        m_strLastError = signAsset.GetLastError();
        return false;
    }

    // Inject provisioning profile into bundle root as embedded.mobileprovision
    std::string profileDest = strAppFolder + "/embedded.mobileprovision";
    std::string profileData;
    if (ReadFile(strProvisioningPath.c_str(), profileData)) {
        WriteFile(profileDest.c_str(), profileData);
    } else {
        m_strLastError = "Could not read provisioning profile to embed.";
        return false;
    }

    ZAppBundle appBundle;
    if (progressCallback) {
        appBundle.SetProgressCallback(progressCallback);
    }

    if (!appBundle.SignFolder(&signAsset,
                              strAppFolder,
                              strBundleId,
                              strDisplayName,
                              "",    // No dylib injection by default
                              true,  // Force
                              false, // Weak inject
                              false  // Enable cache
                              )) {
        m_strLastError = appBundle.GetLastError();
        return false;
    }

    return true;
}
