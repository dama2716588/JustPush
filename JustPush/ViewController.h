//
//  ViewController.h
//  JustPush
//
//  Created by pandora on 4/13/16.
//  Copyright © 2016 pandora. All rights reserved.
//

#import <Cocoa/Cocoa.h>

@interface ViewController : NSViewController

// playload
@property (weak) IBOutlet NSTextField *payload;

// Environment
@property (weak) IBOutlet NSMatrix *pushMode;
@property (weak) IBOutlet NSButtonCell *devSelect;
@property (weak) IBOutlet NSButtonCell *productSelect;

// device token
@property (weak) IBOutlet NSTextField *deviceToken;

// cer file
@property (weak) IBOutlet NSTextField *cerPath;

// action
- (IBAction)connect:(id)sender;
- (IBAction)push:(id)sender;
- (IBAction)modeSwitch:(id)sender;

@end

