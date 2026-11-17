import XCTest
@testable import BlackoutCore
import Scrypt

/// scrypt against RFC 7914 §12 (and Python's hashlib.scrypt for the group-key parameters).
final class ScryptTests: XCTestCase {
    func testRfcVectors() {
        XCTAssertEqual(Hex.encode(Scrypt.derive(password: Data(), salt: Data(), n: 16, r: 1, p: 1, length: 64)),
                       "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906")
        XCTAssertEqual(Hex.encode(Scrypt.derive(password: Data("password".utf8), salt: Data("NaCl".utf8), n: 1024, r: 8, p: 16, length: 64)),
                       "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640")
    }

    func testGroupKeyParametersTiming() {
        let start = Date()
        _ = Scrypt.derive(password: Data("blackout-test-1".utf8), salt: Data("darkproof-group-v2".utf8), n: 32768, r: 8, p: 1, length: 32)
        print("scrypt N=32768 r=8 p=1: \(Int(Date().timeIntervalSince(start) * 1000)) ms")
    }
}
