//
//  bundle.cpp
//  iOSApp
//
//  App bundle re-signing logic and CodeResources generator adapted for iOS in-process execution.
//

#include "bundle.h"
#include <sys/stat.h>
#include <dirent.h>
#include <algorithm>
#include <fstream>
#include <sstream>

// Base64 helper for CodeResources plist
static std::string Base64Encode(const std::string &input) {
    static const char *s_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int val = 0, valb = -6;
    for (unsigned char c : input) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(s_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) out.push_back(s_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

static void TraverseDir(const std::string &dirPath, std::vector<std::string> &files, const std::string &relPrefix = "") {
    DIR *dir = opendir(dirPath.c_str());
    if (!dir) return;

    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
        std::string name = entry->d_name;
        if (name == "." || name == ".." || name == ".DS_Store") continue;
        if (name == "_CodeSignature") continue; // Never hash existing signatures

        std::string fullPath = dirPath + "/" + name;
        std::string relPath = relPrefix.empty() ? name : (relPrefix + "/" + name);

        struct stat st;
        if (stat(fullPath.c_str(), &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                TraverseDir(fullPath, files, relPath);
            } else if (S_ISREG(st.st_mode)) {
                files.push_back(relPath);
            }
        }
    }
    closedir(dir);
}

ZAppBundle::ZAppBundle() {}

ZAppBundle::~ZAppBundle() {}

void ZAppBundle::SetProgressCallback(ProgressCallback callback) {
    m_progressCallback = callback;
}

bool ZAppBundle::SignFolder(ZSignAsset *pSignAsset,
                            const std::string &strFolder,
                            const std::string &strBundleID,
                            const std::string &strDisplayName,
                            const std::string &strDyLibFile,
                            bool bForce,
                            bool bWeakInject,
                            bool bEnableCache) {
    if (!pSignAsset) {
        m_strLastError = "ZSignAsset is null.";
        return false;
    }

    if (m_progressCallback) m_progressCallback(0.1f, "Inspecting bundle structure...");

    // 1. Modify Info.plist
    std::string infoPlistData;
    if (!ModifyInfoPlist(strFolder, strBundleID, strDisplayName, infoPlistData)) {
        return false;
    }

    // 2. Discover and Sign Nested Frameworks and Dylibs (Reverse Post-Order Traversal)
    std::string frameworksDir = strFolder + "/Frameworks";
    DIR *fwDir = opendir(frameworksDir.c_str());
    if (fwDir) {
        std::vector<std::string> dylibs;
        std::vector<std::string> frameworks;
        struct dirent *ent;
        while ((ent = readdir(fwDir)) != nullptr) {
            std::string name = ent->d_name;
            if (name == "." || name == "..") continue;
            std::string fullPath = frameworksDir + "/" + name;
            if (name.find(".framework") != std::string::npos) {
                frameworks.push_back(fullPath);
            } else if (name.find(".dylib") != std::string::npos) {
                dylibs.push_back(fullPath);
            }
        }
        closedir(fwDir);

        // Sign nested dylibs
        for (size_t i = 0; i < dylibs.size(); i++) {
            if (m_progressCallback) {
                float p = 0.2f + (0.2f * (float)i / (float)std::max(size_t(1), dylibs.size()));
                m_progressCallback(p, "Signing dylib: " + dylibs[i].substr(dylibs[i].rfind('/') + 1));
            }
            if (!SignNode(dylibs[i], pSignAsset, bForce)) {
                return false;
            }
        }

        // Sign nested frameworks
        for (size_t i = 0; i < frameworks.size(); i++) {
            if (m_progressCallback) {
                float p = 0.4f + (0.2f * (float)i / (float)std::max(size_t(1), frameworks.size()));
                m_progressCallback(p, "Signing framework: " + frameworks[i].substr(frameworks[i].rfind('/') + 1));
            }
            std::string fwCodeRes;
            GenerateCodeResources(frameworks[i], fwCodeRes);

            // Locate framework binary
            std::string fwName = frameworks[i].substr(frameworks[i].rfind('/') + 1);
            if (fwName.find(".framework") != std::string::npos) {
                fwName = fwName.substr(0, fwName.find(".framework"));
            }
            std::string fwBinary = frameworks[i] + "/" + fwName;
            struct stat st;
            if (stat(fwBinary.c_str(), &st) == 0 && S_ISREG(st.st_mode)) {
                std::string fwInfoPlist;
                ReadFile((frameworks[i] + "/Info.plist").c_str(), fwInfoPlist);
                ZMachO machO;
                if (machO.Init(fwBinary)) {
                    if (!machO.Sign(pSignAsset, bForce, "", fwInfoPlist, fwCodeRes)) {
                        m_strLastError = machO.GetLastError();
                        return false;
                    }
                }
            }
        }
    }

    // 3. Generate Root CodeResources Plist
    if (m_progressCallback) m_progressCallback(0.7f, "Generating bundle CodeResources manifest...");
    std::string rootCodeResources;
    if (!GenerateCodeResources(strFolder, rootCodeResources)) {
        return false;
    }

    // 4. Locate Main Executable
    std::string mainExePath = FindMainExecutable(strFolder, infoPlistData);
    if (mainExePath.empty()) {
        m_strLastError = "Could not identify main executable in bundle: " + strFolder;
        return false;
    }

    if (m_progressCallback) m_progressCallback(0.85f, "Signing main Mach-O executable...");

    // 5. Inject dylib into main executable if requested
    ZMachO mainMachO;
    if (!mainMachO.Init(mainExePath)) {
        m_strLastError = mainMachO.GetLastError();
        return false;
    }

    if (!strDyLibFile.empty()) {
        mainMachO.InjectDyLib(strDyLibFile, bWeakInject);
    }

    // 6. Sign Main Executable with Root Entitlements & CodeResources
    if (!mainMachO.Sign(pSignAsset, bForce, strBundleID, infoPlistData, rootCodeResources)) {
        m_strLastError = mainMachO.GetLastError();
        return false;
    }

    if (m_progressCallback) m_progressCallback(1.0f, "Bundle signed successfully.");
    return true;
}

bool ZAppBundle::SignNode(const std::string &strPath, ZSignAsset *pSignAsset, bool bForce) {
    ZMachO machO;
    if (!machO.Init(strPath)) {
        m_strLastError = machO.GetLastError();
        return false;
    }
    if (!machO.Sign(pSignAsset, bForce, "", "", "")) {
        m_strLastError = machO.GetLastError();
        return false;
    }
    return true;
}

bool ZAppBundle::ModifyInfoPlist(const std::string &strAppDir,
                                 const std::string &strBundleID,
                                 const std::string &strDisplayName,
                                 std::string &outInfoPlistData) {
    std::string infoPlistPath = strAppDir + "/Info.plist";
    if (!ReadFile(infoPlistPath.c_str(), outInfoPlistData)) {
        m_strLastError = "Cannot read Info.plist from: " + infoPlistPath;
        return false;
    }

    bool modified = false;

    // Override Bundle ID if requested
    if (!strBundleID.empty()) {
        size_t idPos = outInfoPlistData.find("<key>CFBundleIdentifier</key>");
        if (idPos != std::string::npos) {
            size_t strStart = outInfoPlistData.find("<string>", idPos);
            size_t strEnd = outInfoPlistData.find("</string>", strStart);
            if (strStart != std::string::npos && strEnd != std::string::npos) {
                outInfoPlistData.replace(strStart + 8, strEnd - (strStart + 8), strBundleID);
                modified = true;
            }
        }
    }

    // Override Display Name if requested
    if (!strDisplayName.empty()) {
        size_t namePos = outInfoPlistData.find("<key>CFBundleDisplayName</key>");
        if (namePos != std::string::npos) {
            size_t strStart = outInfoPlistData.find("<string>", namePos);
            size_t strEnd = outInfoPlistData.find("</string>", strStart);
            if (strStart != std::string::npos && strEnd != std::string::npos) {
                outInfoPlistData.replace(strStart + 8, strEnd - (strStart + 8), strDisplayName);
                modified = true;
            }
        }
    }

    if (modified) {
        WriteFile(infoPlistPath.c_str(), outInfoPlistData);
    }

    return true;
}

std::string ZAppBundle::FindMainExecutable(const std::string &strAppDir, const std::string &infoPlistData) {
    // 1. Search CFBundleExecutable in Info.plist
    size_t exePos = infoPlistData.find("<key>CFBundleExecutable</key>");
    if (exePos != std::string::npos) {
        size_t strStart = infoPlistData.find("<string>", exePos);
        size_t strEnd = infoPlistData.find("</string>", strStart);
        if (strStart != std::string::npos && strEnd != std::string::npos) {
            std::string exeName = infoPlistData.substr(strStart + 8, strEnd - (strStart + 8));
            std::string fullPath = strAppDir + "/" + exeName;
            struct stat st;
            if (stat(fullPath.c_str(), &st) == 0 && S_ISREG(st.st_mode)) {
                return fullPath;
            }
        }
    }

    // 2. Fallback to folder name without .app
    std::string folderName = strAppDir.substr(strAppDir.rfind('/') + 1);
    if (folderName.find(".app") != std::string::npos) {
        folderName = folderName.substr(0, folderName.find(".app"));
    }
    std::string fallbackPath = strAppDir + "/" + folderName;
    struct stat st;
    if (stat(fallbackPath.c_str(), &st) == 0 && S_ISREG(st.st_mode)) {
        return fallbackPath;
    }

    return "";
}

bool ZAppBundle::GenerateCodeResources(const std::string &strAppDir, std::string &outCodeResources) {
    std::vector<std::string> relativeFiles;
    TraverseDir(strAppDir, relativeFiles);

    std::ostringstream ss;
    ss << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    ss << "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n";
    ss << "<plist version=\"1.0\">\n";
    ss << "<dict>\n";

    // <key>files</key>
    ss << "\t<key>files</key>\n\t<dict>\n";
    for (const auto &relFile : relativeFiles) {
        std::string fullPath = strAppDir + "/" + relFile;
        std::string fileContent;
        if (ReadFile(fullPath.c_str(), fileContent)) {
            std::string sha1Hash;
            ZSignAsset::Sha1(fileContent, sha1Hash);
            ss << "\t\t<key>" << relFile << "</key>\n";
            ss << "\t\t<data>" << Base64Encode(sha1Hash) << "</data>\n";
        }
    }
    ss << "\t</dict>\n";

    // <key>files2</key>
    ss << "\t<key>files2</key>\n\t<dict>\n";
    for (const auto &relFile : relativeFiles) {
        std::string fullPath = strAppDir + "/" + relFile;
        std::string fileContent;
        if (ReadFile(fullPath.c_str(), fileContent)) {
            std::string sha1Hash, sha256Hash;
            ZSignAsset::Sha1(fileContent, sha1Hash);
            ZSignAsset::Sha256(fileContent, sha256Hash);
            ss << "\t\t<key>" << relFile << "</key>\n";
            ss << "\t\t<dict>\n";
            ss << "\t\t\t<key>hash</key>\n";
            ss << "\t\t\t<data>" << Base64Encode(sha1Hash) << "</data>\n";
            ss << "\t\t\t<key>hash2</key>\n";
            ss << "\t\t\t<data>" << Base64Encode(sha256Hash) << "</data>\n";
            ss << "\t\t</dict>\n";
        }
    }
    ss << "\t</dict>\n";

    // <key>rules</key>
    ss << "\t<key>rules</key>\n\t<dict>\n";
    ss << "\t\t<key>.*</key>\n\t\t<true/>\n";
    ss << "\t\t<key>^Info\\.plist$</key>\n\t\t<dict><key>omit</key><true/><key>weight</key><real>10</real></dict>\n";
    ss << "\t</dict>\n";

    // <key>rules2</key>
    ss << "\t<key>rules2</key>\n\t<dict>\n";
    ss << "\t\t<key>.*</key>\n\t\t<true/>\n";
    ss << "\t\t<key>^Info\\.plist$</key>\n\t\t<dict><key>omit</key><true/><key>weight</key><real>20</real></dict>\n";
    ss << "\t</dict>\n";

    ss << "</dict>\n</plist>\n";

    outCodeResources = ss.str();

    // Ensure _CodeSignature directory exists
    std::string codeSignDir = strAppDir + "/_CodeSignature";
    mkdir(codeSignDir.c_str(), 0755);
    std::string codeResourcesFile = codeSignDir + "/CodeResources";
    WriteFile(codeResourcesFile.c_str(), outCodeResources);

    return true;
}
