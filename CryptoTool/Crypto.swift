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
public class Crypto{
    var _al:Algorithm
    var _op:Options
    public init(algorithm:Algorithm,option:Options) {
        _al = algorithm
        _op = option
    }
    public func encrypto(data:Data,key:Data,keySize:Int)throws ->Data{
        let space = UnsafeMutablePointer<UInt8>.allocate(capacity: keySize)
        var keyData = key
        if key.count < keySize{
            let data = Data(count: keySize - key.count)
            keyData.append(data)
        }
        keyData.copyBytes(to: space, count: keySize)
        
        let dataSpace = UnsafeMutablePointer<UInt8>.allocate(capacity: data.count)
        data.copyBytes(to: dataSpace, count: data.count)
        
        var out = UnsafeMutableRawPointer.allocate(bytes: data.count * 2, alignedTo: 1)
        var l:Int = 0
        let ex = (self._al == Algorithm.AES ? 16 : 8)
        let a = CCCrypt(CCOperation(kCCEncrypt), _al.rawValue, _op.rawValue, UnsafeRawPointer(space), keySize, nil, dataSpace, data.count, out, data.count + ex , &l)
        if a == Int32(kCCSuccess){
            let r = Data.init(bytes: out, count: l)
            space.deallocate(capacity: keySize)
            dataSpace.deallocate(capacity: data.count)
            out.deallocate(bytes: data.count * 2, alignedTo: 1)
            return r
        }else if a == Int32(kCCBufferTooSmall){
            out.deallocate(bytes: data.count * 2, alignedTo: 1)
             let tempsize = l
            out = UnsafeMutableRawPointer.allocate(bytes: tempsize, alignedTo: 1)
            let result = CCCrypt(CCOperation(kCCEncrypt), _al.rawValue, _op.rawValue, UnsafeRawPointer(space), keySize, nil, dataSpace, data.count, out, tempsize, &l)
            if result != Int32(kCCBufferTooSmall){
                throw NSError(domain: "fail", code: Int(result), userInfo: nil)
            }
            let r = Data.init(bytes: out, count: l)
            space.deallocate(capacity: keySize)
            dataSpace.deallocate(capacity: data.count)
            out.deallocate(bytes: tempsize, alignedTo: 1)
            return r
        }else{
            throw NSError(domain: "fail", code: Int(a), userInfo: nil)
        }
    }
    public func decrypto(data:Data,key:Data,keySize:Int)throws ->Data{
        let space = UnsafeMutablePointer<UInt8>.allocate(capacity: keySize)
        var keyData = key
        if key.count < keySize{
            let data = Data(count: keySize - key.count)
            keyData.append(data)
        }
        keyData.copyBytes(to: space, count: keySize)
        let dataSpace = UnsafeMutablePointer<UInt8>.allocate(capacity: data.count)
        data.copyBytes(to: dataSpace, count: data.count)
        
        let out = UnsafeMutableRawPointer.allocate(bytes: data.count * 2, alignedTo: 1)
        var l:Int = 0
        let a = CCCrypt(CCOperation(kCCDecrypt), _al.rawValue, _op.rawValue, UnsafeRawPointer(space), keySize, nil, dataSpace, data.count, out, data.count, &l)
        if a == Int32(kCCSuccess){
            let r = Data.init(bytes: out, count: l)
            space.deallocate(capacity: keySize)
            dataSpace.deallocate(capacity: data.count)
            out.deallocate(bytes: data.count * 2, alignedTo: 1)
            return r
        }else if a == Int32(kCCBufferTooSmall){
            throw NSError(domain: "too small", code: Int(a), userInfo: nil)
        }else{
            throw NSError(domain: "fail", code: Int(a), userInfo: nil)
        }
    }
}
public enum Algorithm:CCAlgorithm{
    case AES            = 0
    case DES
    case DES3
    case CAST
    case RC4
    case RC2
    case Blowfish
}
public enum Options:CCOptions{
    case PKCS7Padding   = 1
    case ECBMode        = 2
}
public enum AESKeySize:Int{
    case AES128         = 16
    case AES192         = 24
    case AES256         = 32
}
