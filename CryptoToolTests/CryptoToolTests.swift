//
//  CryptoToolTests.swift
//  CryptoToolTests
//
//  Created by yin hao on 2016/11/20.
//  Copyright © 2016年 Suzhou Qier Network Technology Co., Ltd. All rights reserved.
//

import XCTest
import Crypto
@testable import CryptoTool
class CryptoToolTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testExample() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.
        let a = Crypto(algorithm: .Blowfish, option: .PKCS7Padding)
        let data = "abcd设计的风格升级换代规范化建设德国飞机上功夫世界高峰时段护肤感受到缓解高峰结束的功夫世界都会发光技术大会高峰即使对方即使对方过手机电话费个世纪的法国收到回复上功夫收到回复过圣诞节风格结合的法国设计的方式决定恢复给大家回复数据库的方式看见的方式对法国设计的数据库的高峰时段发生的发生肯定开始的方式地方时代发生时发生时间地方是感动很烦上岛咖啡时代发生煎豆腐似的发生的法国思考对方说的法国收到回复过是大家回复扫黄打非国家都收到回复速度放水淀粉快速的减肥的黄金分割上的黄金分割上的黄金分割设计的法国高u 俄有关u 也放过素雅风格独有风格u 因为过分 iu 唯一官方五月规范物业法国物业个废物 i 个服务业规范业股份五月风格为月光俄股份五月副 i 我哥也放过吴业股份五月规范额为月光赋予我eyefulweyug 风物业股份物业股份 iu哥与规范物业辜负我一个富裕个以 u以为文艺复古i 为月光分i 物业股份物一个发i u 我也放过吴诶法国".data(using: .utf8)
        let k = "123123123".data(using: .utf8)
        do {
            let d = try a.encrypto(data: data!, key: k!, keySize: 32)
            print (d.count)
            print(String.init(data: d, encoding: .utf8) ?? "@error@")
            let rr = try a.decrypto(data: d, key: k!, keySize: 32)
            print(String.init(data: rr, encoding: .utf8) ?? "@error@")
        }catch{
            XCTAssert(false, "\(error)")
        }
        
    }
    
    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }
    
}
