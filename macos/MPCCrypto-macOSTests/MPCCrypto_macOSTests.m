//
//  MPCCrypto_macOSTests.m
//  MPCCrypto-macOSTests
//
//  Created by Lior Cohen on 25/11/2018.
//  Copyright © 2018 Unbound Tech. All rights reserved.
//

#import <XCTest/XCTest.h>

#if __cplusplus
extern "C" {
#endif
    extern int MPCCrypto_test(void);
#if __cplusplus
}   // Extern C
#endif


@interface MPCCrypto_macOSTests : XCTestCase

@end

@implementation MPCCrypto_macOSTests

- (void)setUp {
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
}

- (void)testMPCCrypto {
    // This is an example of a functional test case.
    // Use XCTAssert and related functions to verify your tests produce the correct results.
    MPCCrypto_test();
}


@end
