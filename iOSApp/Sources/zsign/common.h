//
//  common.h
//  iOSApp
//
//  Adapted for embedded iOS in-process execution: thread-safe logging, byte swapping, and error handling.
//

#ifndef ZSIGN_COMMON_H
#define ZSIGN_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <stdexcept>
#include <mutex>

// Standard Byte Swapping Macros
#if defined(__APPLE__)
#include <libkern/OSByteOrder.h>
#define ByteSwap16(x) OSSwapInt16(x)
#define ByteSwap32(x) OSSwapInt32(x)
#define ByteSwap64(x) OSSwapInt64(x)
#elif defined(_MSC_VER)
#define ByteSwap16(x) _byteswap_ushort(x)
#define ByteSwap32(x) _byteswap_ulong(x)
#define ByteSwap64(x) _byteswap_uint64(x)
#else
#define ByteSwap16(x) __builtin_bswap16(x)
#define ByteSwap32(x) __builtin_bswap32(x)
#define ByteSwap64(x) __builtin_bswap64(x)
#endif

// Exception type replacing CLI exit() / abort() calls
class ZSignException : public std::runtime_error {
public:
    explicit ZSignException(const std::string &message) : std::runtime_error(message) {}
};

// Thread-safe redirectable logging engine
class ZLog {
public:
    enum Level { Info = 0, Warn = 1, Error = 2, Success = 3 };
    typedef std::function<void(Level level, const std::string &msg)> LogCallback;

    static void SetCallback(LogCallback cb) {
        std::lock_guard<std::mutex> lock(GetMutex());
        GetCallback() = cb;
    }

    static void Print(const char *format, ...) {
        va_list args;
        va_start(args, format);
        LogInternal(Info, format, args);
        va_end(args);
    }

    static void Warn(const char *format, ...) {
        va_list args;
        va_start(args, format);
        LogInternal(Warn, format, args);
        va_end(args);
    }

    static void Error(const char *format, ...) {
        va_list args;
        va_start(args, format);
        LogInternal(Error, format, args);
        va_end(args);
    }

    static void Success(const char *format, ...) {
        va_list args;
        va_start(args, format);
        LogInternal(Success, format, args);
        va_end(args);
    }

private:
    static std::mutex &GetMutex() {
        static std::mutex s_mutex;
        return s_mutex;
    }

    static LogCallback &GetCallback() {
        static LogCallback s_cb = nullptr;
        return s_cb;
    }

    static void LogInternal(Level level, const char *format, va_list args) {
        char buffer[2048];
        vsnprintf(buffer, sizeof(buffer), format, args);
        std::string msg(buffer);

        std::lock_guard<std::mutex> lock(GetMutex());
        if (GetCallback()) {
            GetCallback()(level, msg);
        }
    }
};

// Safe File and Memory Helpers
inline bool ReadFile(const char *path, std::string &outData) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return false;
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (size < 0) {
        fclose(fp);
        return false;
    }
    outData.resize(size);
    size_t readBytes = fread(&outData[0], 1, size, fp);
    fclose(fp);
    return readBytes == (size_t)size;
}

inline bool WriteFile(const char *path, const std::string &data) {
    FILE *fp = fopen(path, "wb");
    if (!fp) return false;
    size_t written = fwrite(data.data(), 1, data.size(), fp);
    fclose(fp);
    return written == data.size();
}

#endif // ZSIGN_COMMON_H
