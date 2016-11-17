//
//  Crypto.swift
//  Crypto
//
//  Created by YinHao on 2016/11/17.
//  Copyright © 2016年 Suzhou Qier Network Technology Co., Ltd. All rights reserved.
//

import Foundation
import Crypto
public func SHA_256(string:String,count:UInt32? = nil)->[UInt8]{
    var md:[UInt8] = Array(repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
    CC_SHA256(string,count ?? UInt32(string.utf8.count),&md)
    return md
}
public func SHA_384(string:String,count:UInt32? = nil)->[UInt8]{
    var md:[UInt8] = Array(repeating: 0, count: Int(CC_SHA384_DIGEST_LENGTH))
    CC_SHA384(string, count ?? UInt32(string.utf8.count), &md)
    return md
}
public func SHA_512(string:String,count:UInt32? = nil)->[UInt8]{
    var md:[UInt8] = Array(repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
    CC_SHA512(string, count ?? UInt32(string.utf8.count), &md)
    return md
}
public func SHA_224(string:String,count:UInt32? = nil)->[UInt8]{
    var md:[UInt8] = Array(repeating: 0, count: Int(CC_SHA224_DIGEST_LENGTH))
    CC_SHA224(string, count ?? UInt32(string.utf8.count), &md)
    return md
}
public func convertCodeToString(code:[UInt8])->String{
    return code.reduce("", {$0 + String(format: "%02x", $1)})
}
