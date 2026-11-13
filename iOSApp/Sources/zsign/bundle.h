//
//  bundle.h
//  iOSApp
//
//  Application bundle traversal, CodeResources generator, and recursive signing coordinator.
//

#ifndef ZSIGN_BUNDLE_H
#define ZSIGN_BUNDLE_H

#include "common.h"
#include "openssl.h"
#include "macho.h"
#include <string>
#include <vector>
#include <map>
#include <functional>

class ZAppBundle {
public:
    ZAppBundle();
    ~ZAppBundle();

    typedef std::function<void(float progress, const std::string &status)> ProgressCallback;

    void SetProgressCallback(ProgressCallback callback);

    bool SignFolder(ZSignAsset *pSignAsset,
                    const std::string &strFolder,
                    const std::string &strBundleID,
                    const std::string &strDisplayName,
                    const std::string &strDyLibFile,
                    bool bForce,
                    bool bWeakInject,
                    bool bEnableCache);

    const std::string &GetLastError() const { return m_strLastError; }

private:
    bool SignNode(const std::string &strPath, ZSignAsset *pSignAsset, bool bForce);
    bool GenerateCodeResources(const std::string &strAppDir, std::string &outCodeResources);
    bool ModifyInfoPlist(const std::string &strAppDir, const std::string &strBundleID, const std::string &strDisplayName, std::string &outInfoPlistData);
    bool GetExecutables(const std::string &strFolder, std::vector<std::string> &executables);
    std::string FindMainExecutable(const std::string &strAppDir, const std::string &infoPlistData);

    ProgressCallback m_progressCallback;
    std::string m_strLastError;
};

#endif // ZSIGN_BUNDLE_H
