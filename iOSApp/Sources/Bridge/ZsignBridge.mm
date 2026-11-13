//
//  ZsignBridge.mm
//  iOSApp
//
//  Objective-C++ implementation bridging Swift to C++ zsign engine with in-process zip/unzip.
//

#import "ZsignBridge.h"
#import <UIKit/UIKit.h>

// Standard C++ and POSIX headers
#include <string>
#include <vector>
#include <memory>
#include <exception>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <zlib.h>

// zsign C++ Core headers
#include "zsign.h"
#include "bundle.h"
#include "openssl.h"
#include "macho.h"
#include "common.h"

// Forward declarations of internal archive helpers
static BOOL InProcessUnpackIPA(NSString *ipaPath, NSString *destinationDir, ZsignProgressBlock progress);
static BOOL InProcessRepackIPA(NSString *sourceDir, NSString *outputIpaPath, NSInteger compressionLevel, ZsignProgressBlock progress);
static NSString *FindAppBundleInside(NSString *payloadDir);

@implementation ZsignResult
+ (instancetype)failureWithError:(NSString *)errorMessage {
    ZsignResult *res = [[ZsignResult alloc] init];
    res.success = NO;
    res.errorMessage = errorMessage;
    return res;
}

+ (instancetype)successWithOutputIpa:(NSString *)outputPath
                            bundleId:(nullable NSString *)bundleId
                          appVersion:(nullable NSString *)version
                             appName:(nullable NSString *)name {
    ZsignResult *res = [[ZsignResult alloc] init];
    res.success = YES;
    res.outputIpaPath = outputPath;
    res.bundleId = bundleId;
    res.appVersion = version;
    res.appName = name;
    return res;
}
@end

@implementation ZsignBridge

+ (NSString *)zsignVersion {
    return [NSString stringWithUTF8String:ZSignEngine::GetVersion()];
}

+ (ZsignResult *)signAppBundleWithIpaPath:(NSString *)ipaPath
                                 p12Path:(NSString *)p12Path
                             p12Password:(NSString *)p12Password
                        provisioningPath:(NSString *)provisioningPath
                                bundleId:(nullable NSString *)bundleId
                             displayName:(nullable NSString *)displayName
                        entitlementsPath:(nullable NSString *)entitlementsPath
                             compression:(NSInteger)compression
                                progress:(nullable ZsignProgressBlock)progressBlock {
    @autoreleasepool {
        NSFileManager *fm = [NSFileManager defaultManager];

        // 1. Parameter Validation
        if (![fm fileExistsAtPath:ipaPath]) {
            return [ZsignResult failureWithError:[NSString stringWithFormat:@"Target IPA file does not exist at: %@", ipaPath]];
        }
        if (![fm fileExistsAtPath:p12Path]) {
            return [ZsignResult failureWithError:[NSString stringWithFormat:@"Signing certificate does not exist at: %@", p12Path]];
        }
        if (![fm fileExistsAtPath:provisioningPath]) {
            return [ZsignResult failureWithError:[NSString stringWithFormat:@"Provisioning profile does not exist at: %@", provisioningPath]];
        }
        if (entitlementsPath && ![fm fileExistsAtPath:entitlementsPath]) {
            return [ZsignResult failureWithError:[NSString stringWithFormat:@"Specified entitlements file not found: %@", entitlementsPath]];
        }

        NSInteger compLevel = (compression >= 1 && compression <= 9) ? compression : 6;

        // 2. Provision Isolated Temporary Workspace
        NSString *sessionUUID = [[NSUUID UUID] UUIDString];
        NSString *workspaceDir = [NSTemporaryDirectory() stringByAppendingPathComponent:[NSString stringWithFormat:@"Signing_%@", sessionUUID]];
        NSString *unpackedDir = [workspaceDir stringByAppendingPathComponent:@"extracted"];
        NSString *outputDir = [workspaceDir stringByAppendingPathComponent:@"output"];
        NSString *outputIpaPath = [outputDir stringByAppendingPathComponent:[NSString stringWithFormat:@"signed_%@.ipa", sessionUUID]];

        NSError *fsError = nil;
        if (![fm createDirectoryAtPath:unpackedDir withIntermediateDirectories:YES attributes:nil error:&fsError] ||
            ![fm createDirectoryAtPath:outputDir withIntermediateDirectories:YES attributes:nil error:&fsError]) {
            return [ZsignResult failureWithError:[NSString stringWithFormat:@"Failed to create workspace scratchpad: %@", fsError.localizedDescription]];
        }

        auto safeProgress = ^(float p, NSString *msg) {
            if (progressBlock) {
                progressBlock(p, msg);
            }
        };

        safeProgress(0.05f, @"Initializing isolated signing workspace...");

        // 3. Unpack IPA In-Process preserving POSIX permissions
        safeProgress(0.12f, @"Unpacking IPA package...");
        if (!InProcessUnpackIPA(ipaPath, unpackedDir, progressBlock)) {
            [fm removeItemAtPath:workspaceDir error:nil];
            return [ZsignResult failureWithError:@"Failed to unpack IPA archive. The package may be corrupted."];
        }

        // 4. Locate Payload/*.app
        NSString *payloadPath = [unpackedDir stringByAppendingPathComponent:@"Payload"];
        NSString *appBundlePath = FindAppBundleInside(payloadPath);
        if (!appBundlePath) {
            [fm removeItemAtPath:workspaceDir error:nil];
            return [ZsignResult failureWithError:@"Invalid IPA structure: No .app bundle found inside Payload directory."];
        }

        // Read original metadata from Info.plist
        NSString *infoPlistPath = [appBundlePath stringByAppendingPathComponent:@"Info.plist"];
        NSMutableDictionary *infoDict = [NSMutableDictionary dictionaryWithContentsOfFile:infoPlistPath];
        if (!infoDict) {
            [fm removeItemAtPath:workspaceDir error:nil];
            return [ZsignResult failureWithError:@"Failed to read Payload/<App>.app/Info.plist."];
        }

        NSString *originalBundleId = infoDict[@"CFBundleIdentifier"] ?: @"";
        NSString *finalBundleId = (bundleId && bundleId.length > 0) ? bundleId : originalBundleId;
        NSString *originalAppName = infoDict[@"CFBundleDisplayName"] ?: (infoDict[@"CFBundleName"] ?: @"App");
        NSString *finalAppName = (displayName && displayName.length > 0) ? displayName : originalAppName;
        NSString *finalVersion = infoDict[@"CFBundleShortVersionString"] ?: (infoDict[@"CFBundleVersion"] ?: @"1.0");

        // 5. Update Info.plist with Overrides
        BOOL infoModified = NO;
        if (bundleId && bundleId.length > 0 && ![bundleId isEqualToString:originalBundleId]) {
            infoDict[@"CFBundleIdentifier"] = bundleId;
            infoModified = YES;
        }
        if (displayName && displayName.length > 0 && ![displayName isEqualToString:originalAppName]) {
            infoDict[@"CFBundleDisplayName"] = displayName;
            infoDict[@"CFBundleName"] = displayName;
            infoModified = YES;
        }
        if (infoModified) {
            [infoDict writeToFile:infoPlistPath atomically:YES];
        }

        // 6. Execute C++ zsign Core Engine
        safeProgress(0.35f, @"Loading cryptographic identity and provisioning assets...");
        try {
            std::string strBundlePath = [appBundlePath UTF8String];
            std::string strP12File = [p12Path UTF8String];
            std::string strP12Password = [p12Password UTF8String];
            std::string strProvisionFile = [provisioningPath UTF8String];
            std::string strEntitlements = entitlementsPath ? [entitlementsPath UTF8String] : "";
            std::string strBundleIdCpp = [finalBundleId UTF8String];
            std::string strDisplayNameCpp = [finalAppName UTF8String];

            ZSignEngine engine;
            bool signSuccess = engine.Sign(strBundlePath,
                                           strP12File,
                                           strP12Password,
                                           strProvisionFile,
                                           strBundleIdCpp,
                                           strDisplayNameCpp,
                                           strEntitlements,
                                           [progressBlock](float p, const std::string &msg) {
                                               if (progressBlock) {
                                                   float scaled = 0.40f + (p * 0.40f); // Scale 0.40 -> 0.80
                                                   progressBlock(scaled, [NSString stringWithUTF8String:msg.c_str()]);
                                               }
                                           });

            if (!signSuccess) {
                std::string lastErr = engine.GetLastError();
                NSString *nsErr = lastErr.empty() ? @"Unknown signing failure in ZSignEngine." : [NSString stringWithUTF8String:lastErr.c_str()];
                [fm removeItemAtPath:workspaceDir error:nil];
                return [ZsignResult failureWithError:[NSString stringWithFormat:@"Signing engine failed: %@", nsErr]];
            }

        } catch (const std::exception &ex) {
            [fm removeItemAtPath:workspaceDir error:nil];
            return [ZsignResult failureWithError:[NSString stringWithFormat:@"C++ Exception during signing: %s", ex.what()]];
        } catch (...) {
            [fm removeItemAtPath:workspaceDir error:nil];
            return [ZsignResult failureWithError:@"Unhandled native exception during Mach-O signing."];
        }

        // 7. Repack IPA In-Process preserving POSIX 0755 attributes
        safeProgress(0.85f, @"Repacking signed IPA package (preserving POSIX permissions)...");
        if (!InProcessRepackIPA(unpackedDir, outputIpaPath, compLevel, progressBlock)) {
            [fm removeItemAtPath:workspaceDir error:nil];
            return [ZsignResult failureWithError:@"Failed to repack signed IPA package."];
        }

        // 8. Reclaim Scratchpad Disk Space
        [fm removeItemAtPath:unpackedDir error:nil];

        safeProgress(1.0f, @"Signing completed successfully.");

        return [ZsignResult successWithOutputIpa:outputIpaPath
                                       bundleId:finalBundleId
                                     appVersion:finalVersion
                                        appName:finalAppName];
    }
}

@end

// MARK: - Internal Helper Implementations

static NSString *FindAppBundleInside(NSString *payloadDir) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *contents = [fm contentsOfDirectoryAtPath:payloadDir error:nil];
    for (NSString *item in contents) {
        if ([item hasSuffix:@".app"]) {
            return [payloadDir stringByAppendingPathComponent:item];
        }
    }
    return nil;
}

// In-Process Zip Extraction with POSIX 0755 Enforcement
static BOOL InProcessUnpackIPA(NSString *ipaPath, NSString *destinationDir, ZsignProgressBlock progress) {
    FILE *fp = fopen([ipaPath UTF8String], "rb");
    if (!fp) return NO;

    NSFileManager *fm = [NSFileManager defaultManager];
    [fm createDirectoryAtPath:destinationDir withIntermediateDirectories:YES attributes:nil error:nil];

    fseek(fp, 0, SEEK_END);
    long fileSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    std::vector<uint8_t> buffer(fileSize);
    size_t readBytes = fread(buffer.data(), 1, fileSize, fp);
    fclose(fp);

    if (readBytes != (size_t)fileSize) return NO;

    // Iterate Local File Headers: 0x04034b50 (PK\x03\x04)
    size_t offset = 0;
    while (offset + 30 <= buffer.size()) {
        uint32_t sig = *(uint32_t *)&buffer[offset];
        if (sig != 0x04034b50) {
            // Not a local header (reached central directory or padding)
            break;
        }

        uint16_t compMethod = *(uint16_t *)&buffer[offset + 8];
        uint32_t compSize = *(uint32_t *)&buffer[offset + 18];
        uint32_t uncompSize = *(uint32_t *)&buffer[offset + 22];
        uint16_t nameLen = *(uint16_t *)&buffer[offset + 26];
        uint16_t extraLen = *(uint16_t *)&buffer[offset + 28];

        size_t nameStart = offset + 30;
        size_t dataStart = nameStart + nameLen + extraLen;

        if (nameStart + nameLen > buffer.size() || dataStart + compSize > buffer.size()) {
            break;
        }

        std::string fileName((char *)&buffer[nameStart], nameLen);
        std::string outPath = [destinationDir UTF8String] + std::string("/") + fileName;

        if (fileName.back() == '/') {
            // Directory entry
            [fm createDirectoryAtPath:[NSString stringWithUTF8String:outPath.c_str()]
          withIntermediateDirectories:YES attributes:nil error:nil];
            chmod(outPath.c_str(), 0755);
        } else {
            // Ensure parent directory exists
            std::string parentDir = outPath.substr(0, outPath.rfind('/'));
            [fm createDirectoryAtPath:[NSString stringWithUTF8String:parentDir.c_str()]
          withIntermediateDirectories:YES attributes:nil error:nil];

            std::vector<uint8_t> decompressedData;
            if (compMethod == 0) {
                // Stored
                decompressedData.assign(&buffer[dataStart], &buffer[dataStart + compSize]);
            } else if (compMethod == 8) {
                // Deflated
                decompressedData.resize(uncompSize);
                z_stream strm = {0};
                strm.avail_in = compSize;
                strm.next_in = &buffer[dataStart];
                strm.avail_out = uncompSize;
                strm.next_out = decompressedData.data();

                if (inflateInit2(&strm, -MAX_WBITS) == Z_OK) {
                    inflate(&strm, Z_FINISH);
                    inflateEnd(&strm);
                }
            }

            FILE *outFile = fopen(outPath.c_str(), "wb");
            if (outFile) {
                fwrite(decompressedData.data(), 1, decompressedData.size(), outFile);
                fclose(outFile);
            }

            // Determine if executable Mach-O or library to apply POSIX 0755
            bool isExecutable = NO;
            if (decompressedData.size() >= 4) {
                uint32_t magic = *(uint32_t *)decompressedData.data();
                if (magic == 0xfeedfacf || magic == 0xfeedface || magic == 0xcafebabe || magic == 0xbebafeca) {
                    isExecutable = YES;
                }
            }
            if (fileName.find(".dylib") != std::string::npos) {
                isExecutable = YES;
            }

            if (isExecutable) {
                chmod(outPath.c_str(), S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH); // 0755
            } else {
                chmod(outPath.c_str(), S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH); // 0644
            }
        }

        offset = dataStart + compSize;
    }

    return YES;
}

// In-Process Zip Repacking with POSIX 0755 (0x81ED0000) External File Attributes
static void CollectFilesToZip(const std::string &baseDir, const std::string &relDir, std::vector<std::pair<std::string, bool>> &fileList) {
    std::string fullDir = relDir.empty() ? baseDir : (baseDir + "/" + relDir);
    DIR *dir = opendir(fullDir.c_str());
    if (!dir) return;

    struct dirent *ent;
    while ((ent = readdir(dir)) != nullptr) {
        std::string name = ent->d_name;
        if (name == "." || name == "..") continue;

        std::string relPath = relDir.empty() ? name : (relDir + "/" + name);
        std::string fullPath = baseDir + "/" + relPath;

        struct stat st;
        if (stat(fullPath.c_str(), &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                fileList.push_back({relPath + "/", true});
                CollectFilesToZip(baseDir, relPath, fileList);
            } else if (S_ISREG(st.st_mode)) {
                fileList.push_back({relPath, false});
            }
        }
    }
    closedir(dir);
}

static uint32_t GetZipExternalAttributes(const std::string &path, bool isDir) {
    if (isDir) {
        return (0040755 << 16); // 0x41ED0000
    }
    struct stat st;
    if (stat(path.c_str(), &st) == 0) {
        if ((st.st_mode & S_IXUSR) || (st.st_mode & S_IXGRP) || (st.st_mode & S_IXOTH)) {
            return (0100755 << 16); // 0x81ED0000 (Executable)
        }
    }
    return (0100644 << 16); // 0x81A40000 (Regular)
}

static BOOL InProcessRepackIPA(NSString *sourceDir, NSString *outputIpaPath, NSInteger compressionLevel, ZsignProgressBlock progress) {
    std::string baseDir = [sourceDir UTF8String];
    std::vector<std::pair<std::string, bool>> fileList;
    CollectFilesToZip(baseDir, "", fileList);

    FILE *outZip = fopen([outputIpaPath UTF8String], "wb");
    if (!outZip) return NO;

    struct ZipEntry {
        std::string name;
        uint32_t crc;
        uint32_t compSize;
        uint32_t uncompSize;
        uint32_t localHeaderOffset;
        uint32_t externalAttr;
        uint16_t compMethod;
    };

    std::vector<ZipEntry> centralDirEntries;

    for (size_t i = 0; i < fileList.size(); i++) {
        const auto &item = fileList[i];
        std::string relName = item.first;
        bool isDir = item.second;
        std::string fullPath = baseDir + "/" + (isDir ? relName.substr(0, relName.size() - 1) : relName);

        ZipEntry entry = {0};
        entry.name = relName;
        entry.localHeaderOffset = (uint32_t)ftell(outZip);
        entry.externalAttr = GetZipExternalAttributes(fullPath, isDir);

        std::string fileContent;
        if (!isDir) {
            ReadFile(fullPath.c_str(), fileContent);
        }

        entry.uncompSize = (uint32_t)fileContent.size();
        entry.crc = (uint32_t)crc32(0L, (const Bytef *)fileContent.data(), (uInt)fileContent.size());

        std::vector<uint8_t> compressedData;
        if (isDir || fileContent.empty()) {
            entry.compMethod = 0; // Stored
            entry.compSize = 0;
        } else {
            entry.compMethod = 8; // Deflated
            z_stream strm = {0};
            deflateInit2(&strm, (int)compressionLevel, Z_DEFLATED, -MAX_WBITS, 8, Z_DEFAULT_STRATEGY);
            compressedData.resize(fileContent.size() + 1024);
            strm.avail_in = (uInt)fileContent.size();
            strm.next_in = (Bytef *)fileContent.data();
            strm.avail_out = (uInt)compressedData.size();
            strm.next_out = compressedData.data();
            deflate(&strm, Z_FINISH);
            compressedData.resize(strm.total_out);
            deflateEnd(&strm);

            entry.compSize = (uint32_t)compressedData.size();
        }

        // Write Local File Header (30 bytes)
        uint32_t sig = 0x04034b50;
        uint16_t ver = 20;
        uint16_t flags = 0;
        uint16_t time = 0, date = 0x54cd;
        uint16_t nameLen = (uint16_t)relName.size();
        uint16_t extraLen = 0;

        fwrite(&sig, 4, 1, outZip);
        fwrite(&ver, 2, 1, outZip);
        fwrite(&flags, 2, 1, outZip);
        fwrite(&entry.compMethod, 2, 1, outZip);
        fwrite(&time, 2, 1, outZip);
        fwrite(&date, 2, 1, outZip);
        fwrite(&entry.crc, 4, 1, outZip);
        fwrite(&entry.compSize, 4, 1, outZip);
        fwrite(&entry.uncompSize, 4, 1, outZip);
        fwrite(&nameLen, 2, 1, outZip);
        fwrite(&extraLen, 2, 1, outZip);
        fwrite(relName.data(), 1, nameLen, outZip);

        if (entry.compSize > 0) {
            fwrite(compressedData.data(), 1, entry.compSize, outZip);
        }

        centralDirEntries.push_back(entry);
    }

    // Write Central Directory Headers
    uint32_t cdOffset = (uint32_t)ftell(outZip);
    for (const auto &entry : centralDirEntries) {
        uint32_t cdSig = 0x02014b50;
        uint16_t verMadeBy = 0x031e; // UNIX (3), zip 3.0 (30)
        uint16_t verNeed = 20;
        uint16_t flags = 0;
        uint16_t time = 0, date = 0x54cd;
        uint16_t nameLen = (uint16_t)entry.name.size();
        uint16_t extraLen = 0, commentLen = 0, diskNum = 0, intAttr = 0;

        fwrite(&cdSig, 4, 1, outZip);
        fwrite(&verMadeBy, 2, 1, outZip);
        fwrite(&verNeed, 2, 1, outZip);
        fwrite(&flags, 2, 1, outZip);
        fwrite(&entry.compMethod, 2, 1, outZip);
        fwrite(&time, 2, 1, outZip);
        fwrite(&date, 2, 1, outZip);
        fwrite(&entry.crc, 4, 1, outZip);
        fwrite(&entry.compSize, 4, 1, outZip);
        fwrite(&entry.uncompSize, 4, 1, outZip);
        fwrite(&nameLen, 2, 1, outZip);
        fwrite(&extraLen, 2, 1, outZip);
        fwrite(&commentLen, 2, 1, outZip);
        fwrite(&diskNum, 2, 1, outZip);
        fwrite(&intAttr, 2, 1, outZip);
        fwrite(&entry.externalAttr, 4, 1, outZip);
        fwrite(&entry.localHeaderOffset, 4, 1, outZip);
        fwrite(entry.name.data(), 1, nameLen, outZip);
    }
    uint32_t cdSize = (uint32_t)ftell(outZip) - cdOffset;

    // Write End of Central Directory Record (22 bytes)
    uint32_t eocdSig = 0x06054b50;
    uint16_t disk1 = 0, disk2 = 0;
    uint16_t totalEntries = (uint16_t)centralDirEntries.size();
    uint16_t commentLen = 0;

    fwrite(&eocdSig, 4, 1, outZip);
    fwrite(&disk1, 2, 1, outZip);
    fwrite(&disk2, 2, 1, outZip);
    fwrite(&totalEntries, 2, 1, outZip);
    fwrite(&totalEntries, 2, 1, outZip);
    fwrite(&cdSize, 4, 1, outZip);
    fwrite(&cdOffset, 4, 1, outZip);
    fwrite(&commentLen, 2, 1, outZip);

    fclose(outZip);
    return YES;
}
