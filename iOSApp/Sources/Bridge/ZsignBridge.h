//
//  ZsignBridge.h
//  iOSApp
//
//  Objective-C Interface conforming to sub_orch_m2/SCOPE.md.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Progress callback reporting completion fraction (0.0 to 1.0) and human-readable status.
typedef void (^ZsignProgressBlock)(float progress, NSString *statusMessage);

/// Structured execution result returned to Swift.
@interface ZsignResult : NSObject

@property (nonatomic, assign) BOOL success;
@property (nonatomic, copy, nullable) NSString *outputIpaPath;
@property (nonatomic, copy, nullable) NSString *bundleId;
@property (nonatomic, copy, nullable) NSString *appVersion;
@property (nonatomic, copy, nullable) NSString *appName;
@property (nonatomic, copy, nullable) NSString *errorMessage;

+ (instancetype)failureWithError:(NSString *)errorMessage;
+ (instancetype)successWithOutputIpa:(NSString *)outputPath
                            bundleId:(nullable NSString *)bundleId
                          appVersion:(nullable NSString *)version
                             appName:(nullable NSString *)name;
@end

/// Objective-C++ Facade wrapping the C++ zsign engine.
@interface ZsignBridge : NSObject

/**
 Signs an iOS application archive (.ipa) using an embedded PKCS#12 certificate and provisioning profile.
 
 @param ipaPath Path to the unsigned .ipa file on disk.
 @param p12Path Path to the .p12 signing certificate.
 @param p12Password Password to decrypt the .p12 container.
 @param provisioningPath Path to the .mobileprovision file.
 @param bundleId Optional bundle identifier override (e.g. "com.example.override").
 @param displayName Optional home screen application title override.
 @param entitlementsPath Optional custom XML entitlements file path.
 @param compression Compression level for repacking (1 fastest, 9 maximum compression).
 @param progressBlock Callback block for step-by-step progress and status messages.
 @return ZsignResult indicating success/failure and metadata of the signed package.
 */
+ (ZsignResult *)signAppBundleWithIpaPath:(NSString *)ipaPath
                                 p12Path:(NSString *)p12Path
                             p12Password:(NSString *)p12Password
                        provisioningPath:(NSString *)provisioningPath
                                bundleId:(nullable NSString *)bundleId
                             displayName:(nullable NSString *)displayName
                        entitlementsPath:(nullable NSString *)entitlementsPath
                             compression:(NSInteger)compression
                                progress:(nullable ZsignProgressBlock)progressBlock;

/// Returns the embedded zsign engine semantic version string.
+ (NSString *)zsignVersion;

@end

NS_ASSUME_NONNULL_END
