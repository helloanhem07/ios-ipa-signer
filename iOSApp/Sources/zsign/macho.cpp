//
//  macho.cpp
//  iOSApp
//
//  Mach-O code-signing and SuperBlob assembly adapted for in-process iOS execution.
//

#include "macho.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <algorithm>

#pragma pack(push, 1)
struct fat_header {
    uint32_t magic;
    uint32_t nfat_arch;
};

struct fat_arch {
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t offset;
    uint32_t size;
    uint32_t align;
};

struct mach_header {
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
};

struct mach_header_64 {
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
};

struct load_command {
    uint32_t cmd;
    uint32_t cmdsize;
};

struct linkedit_data_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t dataoff;
    uint32_t datasize;
};

struct dylib {
    uint32_t name_offset;
    uint32_t timestamp;
    uint32_t current_version;
    uint32_t compatibility_version;
};

struct dylib_command {
    uint32_t cmd;
    uint32_t cmdsize;
    struct dylib dylib;
};

struct CS_Blob {
    uint32_t magic;
    uint32_t length;
};
#pragma pack(pop)

ZMachO::ZMachO() : m_pMapping(nullptr), m_uFileSize(0), m_fd(-1) {}

ZMachO::~ZMachO() {
    Free();
}

void ZMachO::Free() {
    if (m_pMapping) {
        free(m_pMapping);
        m_pMapping = nullptr;
    }
    if (m_fd >= 0) {
        close(m_fd);
        m_fd = -1;
    }
    m_uFileSize = 0;
}

bool ZMachO::Init(const std::string &strFilePath) {
    Free();
    m_strFilePath = strFilePath;

    FILE *fp = fopen(strFilePath.c_str(), "rb");
    if (!fp) {
        m_strLastError = "Cannot open Mach-O binary: " + strFilePath;
        return false;
    }

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (size <= 0) {
        fclose(fp);
        m_strLastError = "Mach-O binary is empty.";
        return false;
    }

    m_uFileSize = (size_t)size;
    m_pMapping = (uint8_t *)malloc(m_uFileSize + 4096 * 16); // extra headroom for signature growth
    if (!m_pMapping) {
        fclose(fp);
        m_strLastError = "Out of memory allocating Mach-O buffer.";
        return false;
    }

    size_t bytesRead = fread(m_pMapping, 1, m_uFileSize, fp);
    fclose(fp);

    if (bytesRead != m_uFileSize) {
        m_strLastError = "Failed to read complete Mach-O binary.";
        Free();
        return false;
    }

    return true;
}

bool ZMachO::Sign(ZSignAsset *pSignAsset,
                  bool bForce,
                  const std::string &strBundleId,
                  const std::string &strInfoPlistData,
                  const std::string &strCodeResourcesData) {
    if (!m_pMapping || m_uFileSize < sizeof(mach_header)) {
        m_strLastError = "Mach-O mapping invalid or file too small.";
        return false;
    }

    uint32_t magic = *(uint32_t *)m_pMapping;

    if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        fat_header *pFatHeader = (fat_header *)m_pMapping;
        uint32_t nfat_arch = (magic == FAT_MAGIC) ? ByteSwap32(pFatHeader->nfat_arch) : pFatHeader->nfat_arch;
        fat_arch *pArchs = (fat_arch *)(m_pMapping + sizeof(fat_header));

        for (uint32_t i = 0; i < nfat_arch; i++) {
            uint32_t offset = (magic == FAT_MAGIC) ? ByteSwap32(pArchs[i].offset) : pArchs[i].offset;
            uint32_t size = (magic == FAT_MAGIC) ? ByteSwap32(pArchs[i].size) : pArchs[i].size;

            if (offset + size > m_uFileSize) {
                m_strLastError = "FAT architecture slice bounds exceeded file size.";
                return false;
            }

            if (!SignArch(m_pMapping + offset, size, offset, pSignAsset, strBundleId, strInfoPlistData, strCodeResourcesData)) {
                return false;
            }
        }
    } else if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64 || magic == MH_MAGIC || magic == MH_CIGAM) {
        if (!SignArch(m_pMapping, m_uFileSize, 0, pSignAsset, strBundleId, strInfoPlistData, strCodeResourcesData)) {
            return false;
        }
    } else {
        m_strLastError = "Not a recognized Mach-O binary (unsupported magic).";
        return false;
    }

    // Write modified binary back to disk
    FILE *fp = fopen(m_strFilePath.c_str(), "wb");
    if (!fp) {
        m_strLastError = "Cannot write signed Mach-O to: " + m_strFilePath;
        return false;
    }

    size_t written = fwrite(m_pMapping, 1, m_uFileSize, fp);
    fclose(fp);

    if (written != m_uFileSize) {
        m_strLastError = "Failed to write complete signed Mach-O binary.";
        return false;
    }

    return true;
}

bool ZMachO::SignArch(uint8_t *pBase,
                      size_t uSize,
                      size_t uFileOffset,
                      ZSignAsset *pSignAsset,
                      const std::string &strBundleId,
                      const std::string &strInfoPlistData,
                      const std::string &strCodeResourcesData) {
    uint32_t magic = *(uint32_t *)pBase;
    bool is64 = (magic == MH_MAGIC_64 || magic == MH_CIGAM_64);
    uint32_t ncmds = 0;
    uint8_t *pCommands = nullptr;

    if (is64) {
        mach_header_64 *mh = (mach_header_64 *)pBase;
        ncmds = mh->ncmds;
        pCommands = pBase + sizeof(mach_header_64);
    } else {
        mach_header *mh = (mach_header *)pBase;
        ncmds = mh->ncmds;
        pCommands = pBase + sizeof(mach_header);
    }

    linkedit_data_command *pCodeSignCmd = nullptr;
    uint8_t *pCurCmd = pCommands;

    for (uint32_t i = 0; i < ncmds; i++) {
        load_command *lc = (load_command *)pCurCmd;
        if (lc->cmd == LC_CODE_SIGNATURE) {
            pCodeSignCmd = (linkedit_data_command *)lc;
            break;
        }
        pCurCmd += lc->cmdsize;
    }

    uint32_t codeLimit = 0;
    if (pCodeSignCmd) {
        codeLimit = pCodeSignCmd->dataoff;
    } else {
        codeLimit = (uint32_t)uSize;
    }

    // 1. Prepare Sub-Blobs
    // Requirements Blob
    std::string requirementsData;
    {
        uint32_t magicReq = ByteSwap32(CSMAGIC_REQUIREMENTS);
        uint32_t lengthReq = ByteSwap32(12);
        uint32_t countReq = 0;
        requirementsData.append((char *)&magicReq, 4);
        requirementsData.append((char *)&lengthReq, 4);
        requirementsData.append((char *)&countReq, 4);
    }

    // XML Entitlements Blob
    std::string entitlementsData;
    const std::string &rawXmlEnt = pSignAsset->GetEntitlements();
    {
        uint32_t magicEnt = ByteSwap32(CSMAGIC_EMBEDDED_ENTITLEMENTS);
        uint32_t lengthEnt = ByteSwap32((uint32_t)(rawXmlEnt.size() + 8));
        entitlementsData.append((char *)&magicEnt, 4);
        entitlementsData.append((char *)&lengthEnt, 4);
        entitlementsData.append(rawXmlEnt);
    }

    // DER Entitlements Blob (iOS 15+)
    std::string derEntitlementsData;
    const std::string &rawDerEnt = pSignAsset->GetDEREntitlements();
    {
        uint32_t magicDer = ByteSwap32(CSMAGIC_EMBEDDED_DER_ENTITLEMENTS);
        uint32_t lengthDer = ByteSwap32((uint32_t)(rawDerEnt.size() + 8));
        derEntitlementsData.append((char *)&magicDer, 4);
        derEntitlementsData.append((char *)&lengthDer, 4);
        derEntitlementsData.append(rawDerEnt);
    }

    // 2. Prepare CodeDirectory
    uint8_t pageSizeBits = 12; // 4096 bytes
    uint32_t pageSize = 1 << pageSizeBits;
    uint32_t nCodeSlots = (codeLimit + pageSize - 1) / pageSize;
    uint32_t nSpecialSlots = 7; // Slots -1 to -7

    std::string identifier = strBundleId.empty() ? "com.signing.app" : strBundleId;
    uint32_t identOffset = sizeof(CS_CodeDirectory);
    uint32_t hashOffset = identOffset + (uint32_t)identifier.size() + 1;
    // Align hashOffset to 4 bytes
    while (hashOffset % 4 != 0) hashOffset++;

    uint32_t cdTotalLength = hashOffset + (nCodeSlots * 32);

    CS_CodeDirectory cd = {0};
    cd.magic = ByteSwap32(CSMAGIC_CODEDIRECTORY);
    cd.length = ByteSwap32(cdTotalLength);
    cd.version = ByteSwap32(0x20400);
    cd.flags = 0;
    cd.hashOffset = ByteSwap32(hashOffset);
    cd.identOffset = ByteSwap32(identOffset);
    cd.nSpecialSlots = ByteSwap32(nSpecialSlots);
    cd.nCodeSlots = ByteSwap32(nCodeSlots);
    cd.codeLimit = ByteSwap32(codeLimit);
    cd.hashSize = 32; // SHA-256
    cd.hashType = 2;  // CS_HASHTYPE_SHA256
    cd.pageSize = pageSizeBits;

    std::string cdBuffer;
    cdBuffer.append((char *)&cd, sizeof(cd));
    cdBuffer.append(identifier.c_str(), identifier.size() + 1);
    while (cdBuffer.size() < hashOffset) cdBuffer.push_back('\0');

    // Special Slots Hashing
    std::vector<std::string> specialHashes(nSpecialSlots, std::string(32, '\0'));

    // Slot -1: Info.plist
    if (!strInfoPlistData.empty()) {
        ZSignAsset::Sha256(strInfoPlistData, specialHashes[0]);
    }
    // Slot -2: Requirements
    ZSignAsset::Sha256(requirementsData, specialHashes[1]);
    // Slot -3: CodeResources
    if (!strCodeResourcesData.empty()) {
        ZSignAsset::Sha256(strCodeResourcesData, specialHashes[2]);
    }
    // Slot -5: XML Entitlements
    ZSignAsset::Sha256(rawXmlEnt, specialHashes[4]);
    // Slot -7: DER Entitlements (iOS 15+)
    ZSignAsset::Sha256(rawDerEnt, specialHashes[6]);

    // Append special slots in reverse order (-7 down to -1)
    std::string specialSlotsData;
    for (int s = nSpecialSlots - 1; s >= 0; s--) {
        specialSlotsData.append(specialHashes[s]);
    }

    // Replace pre-hash section with special slots
    // CodeDirectory hashes array starts with negative indices before hashOffset
    // We adjust cdBuffer so that (hashOffset - 32 * nSpecialSlots) holds special slots
    size_t specialOffset = hashOffset - (32 * nSpecialSlots);
    if (cdBuffer.size() > specialOffset) {
        cdBuffer.resize(specialOffset);
    }
    cdBuffer.append(specialSlotsData);

    // Compute Page Hashes
    for (uint32_t p = 0; p < nCodeSlots; p++) {
        uint32_t pageStart = p * pageSize;
        uint32_t pageLen = std::min(pageSize, codeLimit - pageStart);
        std::string pageHash;
        ZSignAsset::Sha256(std::string((char *)(pBase + pageStart), pageLen), pageHash);
        cdBuffer.append(pageHash);
    }

    // 3. Compute CodeDirectory Hash and Generate CMS Signature
    std::string cdHash;
    ZSignAsset::Sha256(cdBuffer, cdHash);

    std::string cmsBlob;
    if (!pSignAsset->GenerateCMS(cdHash, cmsBlob)) {
        m_strLastError = "Failed to generate CMS signature: " + pSignAsset->GetLastError();
        return false;
    }

    // Wrap CMS in CSMAGIC_BLOBWRAPPER
    std::string cmsWrapper;
    {
        uint32_t magicCms = ByteSwap32(CSMAGIC_BLOBWRAPPER);
        uint32_t lengthCms = ByteSwap32((uint32_t)(cmsBlob.size() + 8));
        cmsWrapper.append((char *)&magicCms, 4);
        cmsWrapper.append((char *)&lengthCms, 4);
        cmsWrapper.append(cmsBlob);
    }

    // 4. Assemble CS_SuperBlob
    uint32_t blobCount = 5; // CD, Requirements, XML Entitlements, DER Entitlements, CMS Signature
    uint32_t headerLen = 12 + (blobCount * sizeof(CS_BlobIndex));

    uint32_t offsetCD = headerLen;
    uint32_t offsetReq = offsetCD + (uint32_t)cdBuffer.size();
    uint32_t offsetEnt = offsetReq + (uint32_t)requirementsData.size();
    uint32_t offsetDer = offsetEnt + (uint32_t)entitlementsData.size();
    uint32_t offsetCms = offsetDer + (uint32_t)derEntitlementsData.size();
    uint32_t totalSuperBlobLen = offsetCms + (uint32_t)cmsWrapper.size();

    CS_SuperBlob superBlobHeader = {0};
    superBlobHeader.magic = ByteSwap32(CSMAGIC_EMBEDDED_SIGNATURE);
    superBlobHeader.length = ByteSwap32(totalSuperBlobLen);
    superBlobHeader.count = ByteSwap32(blobCount);

    std::vector<CS_BlobIndex> indices(blobCount);
    indices[0].type = ByteSwap32(CSSLOT_CODEDIRECTORY);
    indices[0].offset = ByteSwap32(offsetCD);

    indices[1].type = ByteSwap32(CSSLOT_REQUIREMENTS);
    indices[1].offset = ByteSwap32(offsetReq);

    indices[2].type = ByteSwap32(CSSLOT_ENTITLEMENTS);
    indices[2].offset = ByteSwap32(offsetEnt);

    indices[3].type = ByteSwap32(CSSLOT_DER_ENTITLEMENTS);
    indices[3].offset = ByteSwap32(offsetDer);

    indices[4].type = ByteSwap32(CSSLOT_SIGNATURESLOT);
    indices[4].offset = ByteSwap32(offsetCms);

    std::string superBlobData;
    superBlobData.append((char *)&superBlobHeader, 12);
    superBlobData.append((char *)indices.data(), blobCount * sizeof(CS_BlobIndex));
    superBlobData.append(cdBuffer);
    superBlobData.append(requirementsData);
    superBlobData.append(entitlementsData);
    superBlobData.append(derEntitlementsData);
    superBlobData.append(cmsWrapper);

    // 5. Write SuperBlob into Binary & Update LC_CODE_SIGNATURE
    if (!pCodeSignCmd) {
        m_strLastError = "Mach-O binary does not have an LC_CODE_SIGNATURE command slot.";
        return false;
    }

    uint32_t signatureOffset = pCodeSignCmd->dataoff;
    // Align signature offset to 16 bytes
    if (signatureOffset % 16 != 0) {
        signatureOffset += (16 - (signatureOffset % 16));
        pCodeSignCmd->dataoff = signatureOffset;
    }

    pCodeSignCmd->datasize = (uint32_t)superBlobData.size();

    // Ensure capacity
    if (signatureOffset + superBlobData.size() > m_uFileSize) {
        m_uFileSize = signatureOffset + superBlobData.size();
    }

    memcpy(pBase + signatureOffset, superBlobData.data(), superBlobData.size());

    return true;
}

bool ZMachO::InjectDyLib(const std::string &strDyLibPath, bool bWeakInject) {
    if (!m_pMapping || m_uFileSize < sizeof(mach_header)) {
        return false;
    }

    uint32_t magic = *(uint32_t *)m_pMapping;
    bool is64 = (magic == MH_MAGIC_64 || magic == MH_CIGAM_64);

    uint32_t *pNCmds = is64 ? &((mach_header_64 *)m_pMapping)->ncmds : &((mach_header *)m_pMapping)->ncmds;
    uint32_t *pSizeOfCmds = is64 ? &((mach_header_64 *)m_pMapping)->sizeofcmds : &((mach_header *)m_pMapping)->sizeofcmds;

    uint32_t pathLen = (uint32_t)strDyLibPath.size() + 1;
    uint32_t cmdSize = sizeof(dylib_command) + pathLen;
    // Align to 8 bytes for 64-bit
    while (cmdSize % 8 != 0) cmdSize++;

    uint8_t *pCmdStart = is64 ? (m_pMapping + sizeof(mach_header_64)) : (m_pMapping + sizeof(mach_header));
    uint8_t *pNewCmdLoc = pCmdStart + *pSizeOfCmds;

    dylib_command dc = {0};
    dc.cmd = bWeakInject ? LC_LOAD_WEAK_DYLIB : LC_LOAD_DYLIB;
    dc.cmdsize = cmdSize;
    dc.dylib.name_offset = sizeof(dylib_command);
    dc.dylib.timestamp = 2;
    dc.dylib.current_version = 0x010000;
    dc.dylib.compatibility_version = 0x010000;

    memcpy(pNewCmdLoc, &dc, sizeof(dylib_command));
    memcpy(pNewCmdLoc + sizeof(dylib_command), strDyLibPath.c_str(), pathLen);

    (*pNCmds)++;
    (*pSizeOfCmds) += cmdSize;

    return true;
}
