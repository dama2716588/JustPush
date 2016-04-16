//
//  ViewController.m
//  JustPush
//
//  Created by pandora on 4/13/16.
//  Copyright © 2016 pandora. All rights reserved.
//

#import "ViewController.h"

#include <sys/socket.h>
#include <netdb.h>

#define Push_Developer  "gateway.sandbox.push.apple.com"
#define Push_Production  "gateway.push.apple.com"
#define NWSSL_HANDSHAKE_TRY_COUNT 1 << 26

OSStatus NWSSLRead(SSLConnectionRef connection, void *data, size_t *length);
OSStatus NWSSLWrite(SSLConnectionRef connection, const void *data, size_t *length);

@interface ViewController ()
{
    NSString *_cerFile;
    NSString *_tokenStr;
    
    OSStatus _connectResult;
    OSStatus _closeResult;
    
    SSLContextRef _context;
    SecKeychainRef keychain;
    SecCertificateRef certificate;
    SecIdentityRef identity;
    
    int _socket;
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

#pragma mark - Connect Action

- (BOOL)handshakeSSL
{
    OSStatus status = errSSLWouldBlock;
    for (NSUInteger i = 0; i < NWSSL_HANDSHAKE_TRY_COUNT && status == errSSLWouldBlock; i++) {
        NSLog(@"try handshake %ld",i);
        status = SSLHandshake(_context);
    }
    
    switch (status) {
        case errSecSuccess: return YES;
    }
    
    return NO;
}

- (IBAction)connect:(id)sender
{
    NSLog(@"begin connect ...");
    
    _cerFile = _cerPath.stringValue;
    if(_cerFile == nil || [_cerFile isEqualToString:@""]) {
        [self showMessage:@"APNS证书.cer文件路径未指定"];
        return;
    }
    
    NSString *host = nil;
    NSInteger port = 0;
    
    if (self.devSelect == self.pushMode.selectedCell) {
        host = @Push_Developer;
        port = 2195;

    }
    
    if (self.productSelect == self.pushMode.selectedCell) {
        host = @Push_Production;
        port = 2195;
    }
    
    [self connectSocket:host port:port];
    
    [self connectSSL];
    
    [self configSSLCer];
    
    if ([self handshakeSSL]) {
        NSLog(@"connect success ...");
    } else {
        NSLog(@"connect failed ...");
    }
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
    OSStatus result = SSLWrite(_context, &message, (pointer - message), &processed);
    
    if (result == noErr){
        [self showMessage:@"发送成功"];
    }else{
        [self showMessage:@"发送失败"];
    }
    
    NSLog(@"end push ...");
}

// connect - step 1
- (BOOL)connectSocket:(NSString *)hostName port:(NSInteger)portNum
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(struct sockaddr_in));
    struct hostent *entr = gethostbyname(hostName.UTF8String);
    if (!entr) {
        return NO;
    }
    
    struct in_addr host;
    memcpy(&host, entr->h_addr, sizeof(struct in_addr));
    addr.sin_addr = host;
    addr.sin_port = htons((u_short)portNum);
    addr.sin_family = AF_INET;
    int conn = connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
    if (conn < 0) {
        return NO;
    }

    int cntl = fcntl(sock, F_SETFL, O_NONBLOCK);
    if (cntl < 0) {
        return NO;
    }

    int set = 1, sopt = setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, (void *)&set, sizeof(int));
    if (sopt < 0) {
        return NO;
    }
    _socket = sock;
    
    return YES;
}

// connect - step 2
- (BOOL)connectSSL
{
    // Create new SSL context.
    SSLContextRef contextRef = SSLCreateContext(NULL, kSSLClientSide, kSSLStreamType);
    if (!contextRef) return NO;
    
    // Set callback functions for SSL context.
    OSStatus setio = SSLSetIOFuncs(contextRef, NWSSLRead, NWSSLWrite);
    if (setio != errSecSuccess) return NO;
    
    // Set SSL context connection.
    OSStatus setconn = SSLSetConnection(contextRef, (SSLConnectionRef)(NSInteger)_socket);
    if (setconn != errSecSuccess) return NO;
    
    // Set domain
    if (self.devSelect == self.pushMode.selectedCell) {
        OSStatus setpeer = SSLSetPeerDomainName(contextRef, Push_Developer, 30);
        if (setpeer != errSecSuccess) return NO;
    }
    
    if (self.productSelect == self.pushMode.selectedCell) {
        OSStatus setpeer = SSLSetPeerDomainName(contextRef,Push_Production, 22);
        if (setpeer != errSecSuccess) return NO;
    }
    
    _context = contextRef;
    
    return YES;
}

// conect - step 3
- (void)configSSLCer
{
    // Create certificate.
    NSData *certificateData = [NSData dataWithContentsOfFile:self.cerPath.stringValue];
    certificate = SecCertificateCreateWithData(kCFAllocatorDefault, (__bridge CFDataRef)certificateData);
    
    // Create identity.
    _connectResult = SecIdentityCreateWithCertificate(keychain, certificate, &identity);
    
    // Set client certificate.
    CFArrayRef certificates = CFArrayCreate(NULL, (const void **)&identity, 1, NULL);
    _connectResult = SSLSetCertificate(_context, certificates);
    CFRelease(certificates);
}

#pragma mark - Custom Methods

- (void)disconnect {
    if (_closeResult != 0) return;
    _closeResult = SSLClose(_context); // Terminate current SSL session
    if (identity != NULL) CFRelease(identity); // Release identity.
    if (certificate != NULL) CFRelease(certificate); // Release certificate.
    if (keychain != NULL) CFRelease(keychain); // Release keychain.
    close((int)_socket); // Close connection to server.
    if (certificate != NULL) CFRelease(_context); // Delete SSL context.
    NSLog(@"disconnet success");
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

OSStatus NWSSLRead(SSLConnectionRef connection, void *data, size_t *length) {
    size_t leng = *length;
    *length = 0;
    size_t read = 0;
    ssize_t rcvd = 0;
    for(; read < leng; read += rcvd) {
        rcvd = recv((int)connection, (char *)data + read, leng - read, 0);
        if (rcvd <= 0) break;
    }
    *length = read;
    if (rcvd > 0 || !leng) {
        return errSecSuccess;
    }
    if (!rcvd) {
        return errSSLClosedGraceful;
    }
    switch (errno) {
        case EAGAIN: return errSSLWouldBlock;
        case ECONNRESET: return errSSLClosedAbort;
    }
    return errSecIO;
}

OSStatus NWSSLWrite(SSLConnectionRef connection, const void *data, size_t *length) {
    size_t leng = *length;
    *length = 0;
    size_t sent = 0;
    ssize_t wrtn = 0;
    for (; sent < leng; sent += wrtn) {
        wrtn = write((int)connection, (char *)data + sent, leng - sent);
        if (wrtn <= 0) break;
    }
    *length = sent;
    if (wrtn > 0 || !leng) {
        return errSecSuccess;
    }
    switch (errno) {
        case EAGAIN: return errSSLWouldBlock;
        case EPIPE: return errSSLClosedAbort;
    }
    return errSecIO;
}
