//
//  Crypto.swift
//  Crypto
//
//  Created by YinHao on 2016/11/17.
//  Copyright © 2016年 Suzhou Qier Network Technology Co., Ltd. All rights reserved.
//

import Foundation
import Crypto.mh
import Crypto.Cryptor
import Crypto.Random
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
public func GenRandom(len:UInt)->UnsafeRawPointer
public class Crypto{
    public enum Algorithm:CCAlgorithm{
        case AES128 = kCCAlgorithmAES128
        case AES = kCCAlgorithmAES
        case DES = kCCAlgorithmDES
        case 3DES = kCCAlgorithm3DES
        case CAST = kCCAlgorithmCAST
        case RC4 = kCCAlgorithmRC4
        case RC2 = kCCAlgorithmRC2
        case Blowfish = kCCAlgorithmBlowfish
    }
    public enum Option:CCOptions{
        case PKCS7Padding = kCCOptionPKCS7Padding
        case ECBMode = kCCOptionECBMode
    }
    var _al:Algorithm
    var _op:Option
    public var iv:[UInt8] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    public init(algorithm:Algorithm,option:Option) {
        _al = algorithm
        _op = Option
    }
    public func decrypto(data:Data,key:Data,keySize:CryptoKeySize)->Data{
        var i:UnsafeMutableRawBufferPointer = UnsafeMutableRawBufferPointer(data)
        data.copyBytes(to: i)
        
        CCCrypt(kCCDecrypt, _al.rawValue, _op.rawValue, key, key.count, iv, i, i.count, <#T##dataOut: UnsafeMutableRawPointer!##UnsafeMutableRawPointer!#>, <#T##dataOutAvailable: Int##Int#>, <#T##dataOutMoved: UnsafeMutablePointer<Int>!##UnsafeMutablePointer<Int>!#>)
    }
    public func encrypto(data:Data)->Data{
        
    }
}
public enum CryptoKeySize:Int{
    case AES128          = 16
    case AES192          = 24
    case AES256          = 32
    case DES             = 8
    case 3DES            = 24
    case MinCAST         = 5
    case MaxCAST         = 16
    case MinRC4          = 1
    case MaxRC4          = 512
    case MinRC2          = 1
    case MaxRC2          = 128
    case MinBlowfish     = 8
    case MaxBlowfish     = 56
}
