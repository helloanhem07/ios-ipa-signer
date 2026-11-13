//
//  macho.h
//  iOSApp
//
//  Mach-O 32/64/Universal binary parser, CodeDirectory generator, and SuperBlob assembler.
//

#ifndef ZSIGN_MACHO_H
#define ZSIGN_MACHO_H

#include "common.h"
#include "openssl.h"
#include <string>
#include <vector>

// Mach-O Magic Numbers
#define MH_MAGIC            0xfeedface
#define MH_CIGAM            0xcefaedfe
#define MH_MAGIC_64         0xfeedfacf
#define MH_CIGAM_64         0xcffaedfe
#define FAT_MAGIC           0xcafebabe
#define FAT_CIGAM           0xbebafeca

// Mach-O Load Commands
#define LC_REQ_DYLD         0x80000000
#define LC_LOAD_DYLIB       0x0c
#define LC_LOAD_WEAK_DYLIB  (0x18 | LC_REQ_DYLD)
#define LC_CODE_SIGNATURE   0x1d
#define LC_SEGMENT          0x01
#define LC_SEGMENT_64       0x19

// Apple Code Signing Magic Constants
#define CSMAGIC_REQUIREMENTS               0xfade0c01
#define CSMAGIC_CODEDIRECTORY              0xfade0c02
#define CSMAGIC_EMBEDDED_SIGNATURE         0xfade0cc0
#define CSMAGIC_DETACHED_SIGNATURE         0xfade0cc1
#define CSMAGIC_BLOBWRAPPER                0xfade0b01
#define CSMAGIC_EMBEDDED_ENTITLEMENTS      0xfade7171
#define CSMAGIC_EMBEDDED_DER_ENTITLEMENTS  0xfade7172

// Apple Slot Indexes
#define CSSLOT_CODEDIRECTORY               0
#define CSSLOT_INFOSLOT                    1
#define CSSLOT_REQUIREMENTS                2
#define CSSLOT_RESOURCEDIR                 3
#define CSSLOT_APPLICATION                 4
#define CSSLOT_ENTITLEMENTS                5
#define CSSLOT_DER_ENTITLEMENTS            7
#define CSSLOT_ALTERNATE_CODEDIRECTORIES   0x1000
#define CSSLOT_SIGNATURESLOT               0x10000

#pragma pack(push, 1)
typedef struct __CS_BlobIndex {
    uint32_t type;
    uint32_t offset;
} CS_BlobIndex;

typedef struct __CS_SuperBlob {
    uint32_t magic;
    uint32_t length;
    uint32_t count;
    CS_BlobIndex index[1];
} CS_SuperBlob;

typedef struct __CS_CodeDirectory {
    uint32_t magic;
    uint32_t length;
    uint32_t version;
    uint32_t flags;
    uint32_t hashOffset;
    uint32_t identOffset;
    uint32_t nSpecialSlots;
    uint32_t nCodeSlots;
    uint32_t codeLimit;
    uint8_t hashSize;
    uint8_t hashType;
    uint8_t platform;
    uint8_t pageSize;
    uint32_t spare2;
    uint32_t scatterOffset;
    uint32_t teamOffset;
    uint32_t spare3;
    uint64_t codeLimit64;
    uint64_t execSegBase;
    uint64_t execSegLimit;
    uint64_t execSegFlags;
} CS_CodeDirectory;
#pragma pack(pop)

class ZMachO {
public:
    ZMachO();
    ~ZMachO();

    bool Init(const std::string &strFilePath);
    void Free();

    bool Sign(ZSignAsset *pSignAsset,
              bool bForce,
              const std::string &strBundleId,
              const std::string &strInfoPlistData,
              const std::string &strCodeResourcesData);

    bool InjectDyLib(const std::string &strDyLibPath, bool bWeakInject);

    const std::string &GetLastError() const { return m_strLastError; }

private:
    bool SignArch(uint8_t *pBase,
                  size_t uSize,
                  size_t uFileOffset,
                  ZSignAsset *pSignAsset,
                  const std::string &strBundleId,
                  const std::string &strInfoPlistData,
                  const std::string &strCodeResourcesData);

    bool ReallocCodeSignSpace(uint8_t *pBase, size_t &uSize, size_t uRequiredSize);

    std::string m_strFilePath;
    uint8_t *m_pMapping;
    size_t m_uFileSize;
    int m_fd;
    std::string m_strLastError;
};

#endif // ZSIGN_MACHO_H
