//
//  SafesCollection.h
//  StrongBox
//
//  Created by Mark on 22/11/2014.
//  Copyright (c) 2014 Mark McGuill. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "SafeMetaData.h"

@interface SafesCollection : NSObject

-(id)init;
-(NSUInteger)count;
-(SafeMetaData*)get:(NSUInteger)index;
-(void)removeSafesAt:(NSIndexSet*)index;
-(void)removeAt:(NSUInteger)index;
-(void)save;
- (void)add:(SafeMetaData *)newSafe;

-(NSString*) sanitizeSafeNickName:(NSString*) string;
-(BOOL)isValidNickName:(NSString*) nickName;

@end
