//
//  ViewController.m
//  JustPush
//
//  Created by pandora on 4/13/16.
//  Copyright © 2016 pandora. All rights reserved.
//

#import "ViewController.h"
#import "ioSock.h"

#define Push_Developer  "gateway.sandbox.push.apple.com"
#define Push_Production  "gateway.push.apple.com"

@interface ViewController ()
{
    NSString *_cerFile;
    NSString *_tokenStr;
    
    otSocket socket;
    OSStatus _connectResult;
    OSStatus _closeResult;
    
    SSLContextRef context;
    SecKeychainRef keychain;
    SecCertificateRef certificate;
    SecIdentityRef identity;
}

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];

    self.payload.stringValue = @"{\"aps\":{\"alert\":\"This is some fancy message.\",\"badge\":1,\"sound\": \"default\"}}";
    _connectResult = -50;
    _closeResult = -50;
    
    self.deviceToken.stringValue = @"3411bea9 38dfe039 7a1b0891 48c0d8e3 ef44a68b 482e9e00 3521c87d c372e0b3";
    
    self.cerPath.stringValue = @"/Users/pandora/Desktop/all hiclub/mini_weibo_ota/aps_development.cer";
    
    [self modeSwitch:self.devSelect];
}

- (void)setRepresentedObject:(id)representedObject {
    [super setRepresentedObject:representedObject];

    // Update the view, if already loaded.
}

// connect - step 1
- (void)setPeerServer
{
    // Establish connection to server.
    PeerSpec peer;
    
    //测试开发环境
    if (self.devSelect == self.pushMode.selectedCell) {
        _connectResult = MakeServerConnection(Push_Developer, 2195, 1, &socket, &peer);
        NSLog(@"MakeServerConnection(): %d", _connectResult);
    }
    
    //生产正式环境
    if (self.productSelect == self.pushMode.selectedCell) {
        _connectResult = MakeServerConnection(Push_Production, 2195, 1, &socket, &peer);
        NSLog(@"MakeServerConnection(): %d", _connectResult);
    }
}

// connect - step 2
- (void)configSSLContext
{
    // Create new SSL context.
    _connectResult = SSLNewContext(false, &context);
    
    // Set callback functions for SSL context.
    _connectResult = SSLSetIOFuncs(context, SocketRead, SocketWrite);
    
    // Set SSL context connection.
    _connectResult = SSLSetConnection(context, socket);
}

// connect - step 4
- (void)setPeerDomain
{
    //测试环境
    if (self.devSelect == self.pushMode.selectedCell) {
        // Set server domain name.
        _connectResult = SSLSetPeerDomainName(context, Push_Developer, 30);
    }
    
    //生产正式环境
    if (self.productSelect == self.pushMode.selectedCell) {
        _connectResult = SSLSetPeerDomainName(context,Push_Production, 22);
    }
    
    // Open keychain.
    _connectResult = SecKeychainCopyDefault(&keychain);
}

// conect - step 4
- (void)configSSLCer
{
    // Create certificate.
    if (self.devSelect == self.pushMode.selectedCell) {
        _cerFile = self.cerPath.stringValue;
    }
    
    //生产正式环境
    if (self.productSelect == self.pushMode.selectedCell) {
        _cerFile = self.cerPath.stringValue;
    }
    
    NSData *certificateData = [NSData dataWithContentsOfFile:_cerFile];
    
    certificate = SecCertificateCreateWithData(kCFAllocatorDefault, (__bridge CFDataRef)certificateData);
    if (certificate == NULL){
        [self showMessage:@"读取证书失败!"];
    }
    
    // Create identity.
    _connectResult = SecIdentityCreateWithCertificate(keychain, certificate, &identity);
    
    // Set client certificate.
    CFArrayRef certificates = CFArrayCreate(NULL, (const void **)&identity, 1, NULL);
    _connectResult = SSLSetCertificate(context, certificates);
    CFRelease(certificates);
}

- (IBAction)connect:(id)sender
{
    NSLog(@"begin connect ...");
    
    _cerFile = _cerPath.stringValue;
    if(_cerFile == nil || [_cerFile isEqualToString:@""]) {
        [self showMessage:@"APNS证书.cer文件路径未指定"];
        return;
    }
    
    [self setPeerServer];
    
    [self configSSLContext];
    
    [self setPeerDomain];
    
    [self configSSLCer];
    
    // SSL handshake.
    do {
        _connectResult = SSLHandshake(context);
        NSLog(@"SSLHandshake(): %d", _connectResult);
    } while(_connectResult == errSSLWouldBlock);
    
    NSLog(@"end connect ...");
}

#pragma mark - Push Action

- (IBAction)push:(id)sender
{
    NSLog(@"begin push ...");
    
    if(_connectResult == -50) {
        [self showMessage:@"未连接服务器"];
        return;
    }
    
    _tokenStr = [self buildToken:self.deviceToken];
    
    if(_tokenStr == nil) {
        [self showMessage:@"token 不能为空"];
        return;
    }

    // Convert string into device token data.
    NSMutableData *deviceToken = [NSMutableData data];
    unsigned value;
    NSScanner *scanner = [NSScanner scannerWithString:_tokenStr];
    while(![scanner isAtEnd]) {
        [scanner scanHexInt:&value];
        value = htonl(value);
        [deviceToken appendBytes:&value length:sizeof(value)];
    }
    
    // 1. Create C input variables.
    char *deviceTokenBinary = (char *)[deviceToken bytes];
    char *payloadBinary = (char *)[self.payload.stringValue UTF8String];
    size_t payloadLength = strlen(payloadBinary);
    
    // 2. Define some variables.
    uint8_t command = 0;
    char message[8000]; //限定值
    char *pointer = message;
    uint16_t networkTokenLength = htons(32);
    uint16_t networkPayloadLength = htons(payloadLength);
    
    // 3. Compose message.
    memcpy(pointer, &command, sizeof(uint8_t));
    pointer += sizeof(uint8_t);
    memcpy(pointer, &networkTokenLength, sizeof(uint16_t));
    pointer += sizeof(uint16_t);
    memcpy(pointer, deviceTokenBinary, 32);
    pointer += 32;
    memcpy(pointer, &networkPayloadLength, sizeof(uint16_t));
    pointer += sizeof(uint16_t);
    memcpy(pointer, payloadBinary, payloadLength);
    pointer += payloadLength;
    
    // 4. Send message over SSL.
    size_t processed = 0;
    OSStatus result = SSLWrite(context, &message, (pointer - message), &processed);
    
    if (result == noErr){
        [self showMessage:@"发送成功"];
    }else{
        [self showMessage:@"发送失败"];
    }
    
    NSLog(@"end push ...");
}

#pragma mark - Custom Methods

- (void)disconnect {
    if (_closeResult != 0) return;
    _closeResult = SSLClose(context); // Terminate current SSL session
    if (identity != NULL) CFRelease(identity); // Release identity.
    if (certificate != NULL) CFRelease(certificate); // Release certificate.
    if (keychain != NULL) CFRelease(keychain); // Release keychain.
    close((int)socket); // Close connection to server.
    _closeResult = SSLDisposeContext(context); // Delete SSL context.
}

-(void)resetConnect{
    _connectResult = -50;
    [self disconnect];
}

- (IBAction)modeSwitch:(id)sender {
    [self resetConnect];
    _tokenStr = [self buildToken:self.deviceToken];
}

-(NSString*)buildToken:(NSTextField*)text{
    // Validate input.
    NSMutableString* tempString;
    
    if(![text.stringValue rangeOfString:@" "].length)
    {
        //put in spaces in device token
        tempString =  [NSMutableString stringWithString:text.stringValue];
        int offset = 0;
        for(int i = 0; i < tempString.length; i++)
        {
            if(i%8 == 0 && i != 0 && i+offset < tempString.length-1)
            {
                //NSLog(@"i = %d + offset[%d] = %d", i, offset, i+offset);
                [tempString insertString:@" " atIndex:i+offset];
                offset++;
            }
        }
        NSLog(@"格式化token: '%@'", tempString);
        text.stringValue = tempString;
    }
    return text.stringValue;
}

-(void)showMessage:(NSString*)message{
    NSAlert *alert = [[NSAlert alloc] init];
    [alert setMessageText:message];
    [alert beginSheetModalForWindow:self.view.window completionHandler:^(NSModalResponse returnCode) {
        
    }];
}

@end
