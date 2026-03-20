// HavocAuthInject.m
// Dylib inject token + payment_secret vào Keychain của XXTExplorer
// Build: clang -arch arm64 -isysroot $(xcrun --sdk iphoneos --show-sdk-path)
//              -framework Foundation -framework Security
//              -dynamiclib -install_name @executable_path/Frameworks/HavocAuthInject.dylib
//              -o HavocAuthInject.dylib HavocAuthInject.m

#import <Foundation/Foundation.h>
#import <Security/Security.h>

// ===== HARDCODED CREDENTIALS =====
// Thay các giá trị này nếu token hết hạn
static NSString *const kHavocToken   = @"0c2fba0dc33ccfe8875b13b71dd93956657d5342195065e81a0c0f8400254d9d";
static NSString *const kHavocSecret  = @"fb0e28d0d50e4753330993f6f7ad2175c92f996711589c99c3fa0558f9ecd093";

// UserDefaults flag để chỉ chạy 1 lần
static NSString *const kInjectedFlagKey = @"HavocAuthInjected_v1";

// ===== Helper: lưu 1 item vào Keychain =====
static OSStatus saveKeychainItem(NSString *service, NSString *value) {
    NSData *data = [value dataUsingEncoding:NSUTF8StringEncoding];

    // Xoá item cũ nếu có
    NSDictionary *deleteQuery = @{
        (__bridge id)kSecClass:       (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: service,
        (__bridge id)kSecAttrAccount: service,
    };
    SecItemDelete((__bridge CFDictionaryRef)deleteQuery);

    // Thêm item mới
    NSDictionary *addQuery = @{
        (__bridge id)kSecClass:            (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService:      service,
        (__bridge id)kSecAttrAccount:      service,
        (__bridge id)kSecValueData:        data,
        (__bridge id)kSecAttrAccessible:   (__bridge id)kSecAttrAccessibleAfterFirstUnlock,
        (__bridge id)kSecAttrSynchronizable: @NO,
    };
    return SecItemAdd((__bridge CFDictionaryRef)addQuery, NULL);
}

// ===== Constructor: chạy khi dylib load =====
__attribute__((constructor))
static void HavocAuthInjectInit(void) {
    @autoreleasepool {
        // Chỉ inject 1 lần
        NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
        if ([defaults boolForKey:kInjectedFlagKey]) {
            return;
        }

        // Keychain format: KeychainHelper.[<identifier>].token / .secret
        // Thử tất cả các identifier có thể
        NSArray<NSString *> *identifiers = @[
            @"OwnGoalStudio/XXTouchElite",  // Havoc repo path (trước khi patch)
            @"OwnGoalStudio/XXTouchFaked",  // Havoc repo path (sau khi patch)
            @"ch.xxtou.XXTExplorer",        // Bundle ID
        ];

        for (NSString *ident in identifiers) {
            NSString *tokenKey  = [NSString stringWithFormat:@"KeychainHelper.[%@].token",  ident];
            NSString *secretKey = [NSString stringWithFormat:@"KeychainHelper.[%@].secret", ident];

            OSStatus tStatus = saveKeychainItem(tokenKey,  kHavocToken);
            OSStatus sStatus = saveKeychainItem(secretKey, kHavocSecret);

            NSLog(@"[HavocInject] Saved for '%@': token=%d secret=%d", ident, (int)tStatus, (int)sStatus);
        }

        // Đánh dấu đã inject
        [defaults setBool:YES forKey:kInjectedFlagKey];
        [defaults synchronize];

        NSLog(@"[HavocInject] Keychain injection complete.");
    }
}
