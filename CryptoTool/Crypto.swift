//
//  Crypto.swift
//  Crypto
//
//  Created by YinHao on 2016/11/17.
//  Copyright © 2016年 Suzhou Qier Network Technology Co., Ltd. All rights reserved.
//

import Foundation
import importCrypto
public func SHA_256(string:String,count:UInt32)->[UInt8]{
    var md:[UInt8] = Array(repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
    CC_SHA256(string,count,&md)
    return md
}
