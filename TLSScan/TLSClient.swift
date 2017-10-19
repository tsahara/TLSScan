//
//  TLSClient.swift
//  TLSScan
//
//  Created by Tomoyuki Sahara on 2017/09/20.
//  Copyright © 2017 Tomoyuki Sahara. All rights reserved.
//

import Foundation

extension FixedWidthInteger {
    var bytes: [UInt8] {
        let byteWidth = Self.bitWidth / 8
        var result = [UInt8](repeating: 0, count: byteWidth)
        for i in 0..<byteWidth {
            result[i] = UInt8(truncatingIfNeeded: self >> ((byteWidth - (i + 1)) * 8))
        }
        return result
    }

    var bytes3: [UInt8] {
        let b = bytes
        return [ b[1], b[2], b[3] ]
    }
}

class TLSClient: NSObject, StreamDelegate {
    let host: String

    var inputStream: InputStream?
    var outputStream: OutputStream?

    var readBuffer: [UInt8] = []
    var writebuffer: [UInt8] = []

    var cipherIndex = 0

    static let cipherSuite = [
        (0x00, 0x00, "TLS_NULL_WITH_NULL_NULL"),
        (0xC0, 0x2F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
        (0xC0, 0xAA, "TLS_PSK_DHE_WITH_AES_128_CCM_8"),
        (0xC0, 0xAB, "TLS_PSK_DHE_WITH_AES_256_CCM_8"),
        (0xC0, 0xAC, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM"),
        (0xC0, 0xAD, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM"),
        (0xC0, 0xAE, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8"),
        (0xC0, 0xAF, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8"),
        (0xCC, 0xA8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
        (0xCC, 0xA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"),
        (0xCC, 0xAA, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
        (0xCC, 0xAB, "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256"),
        (0xCC, 0xAC, "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256"),
        (0xCC, 0xAD, "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256"),
        (0xCC, 0xAE, "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256"),
        (0xD0, 0x01, "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256"),
        (0xD0, 0x02, "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384"),
        (0xD0, 0x03, "TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256"),
        (0xD0, 0x05, "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256"),
    ]

    init(host: String) {
        self.host = host
    }

    func scan() {
        self.connect()
    }

    func next() {
        if self.cipherIndex < TLSClient.cipherSuite.count - 1 {
            self.cipherIndex += 1
            self.connect()
        }
    }

    func connect() {
        var readStream: Unmanaged<CFReadStream>?
        var writeStream: Unmanaged<CFWriteStream>?

        print(host)

        CFStreamCreatePairWithSocketToHost(nil, self.host as CFString, 443, &readStream, &writeStream)
        self.inputStream  = readStream!.takeRetainedValue()
        self.outputStream = writeStream!.takeRetainedValue()

        self.inputStream!.delegate = self
        self.inputStream!.schedule(in: RunLoop.current, forMode: .defaultRunLoopMode)
        self.inputStream!.open()

        if let out = self.outputStream {
            out.delegate = self
            out.schedule(in: RunLoop.current, forMode: .defaultRunLoopMode)
            out.open()
        }
    }

    func stream(_ aStream: Stream, handle eventCode: Stream.Event) {
        switch eventCode {
        case Stream.Event.openCompleted:
//            print("open")
            self.writebuffer += make_client_hello()
        case Stream.Event.hasSpaceAvailable:
//            print("writable")
            if self.writebuffer.count > 0 {
                let n = (aStream as! OutputStream).write(self.writebuffer, maxLength: self.writebuffer.count)
                self.writebuffer.removeFirst(n)
                print("written: \(n)")
            }
        case Stream.Event.hasBytesAvailable:
//            print("readable")
            var buf = [UInt8](repeating: 0, count: 2048)
            let n = self.inputStream!.read(&buf, maxLength: buf.count)
            if n > 0 {
                switch buf[0] {
                case 21:
                    let (_, _, name) = TLSClient.cipherSuite[self.cipherIndex]
                    print("TLS Alert -> \(name) rejected")
                case 22:
                    print("TLS Handshake -> accepted")
                default:
                    print("unexpected msg type \(buf[0])")
                }
                self.close()
            }
        default:
            print("eventCode = \(eventCode)")
        }
    }

    func close() {
        self.inputStream?.remove(from: RunLoop.current, forMode: .defaultRunLoopMode)
        self.inputStream?.close()
        self.outputStream?.remove(from: RunLoop.current, forMode: .defaultRunLoopMode)
        self.outputStream?.close()
        self.next()
    }

    func make_client_hello() -> [UInt8] {
        return make_tls_plaintext(type: 22 /* handshake */, fragment: make_tls_handshake(msg_type: 1 /* client_hello */, body: make_tls_client_hello()))
    }

    func make_tls_plaintext(type: Int, fragment: [UInt8]) -> [UInt8] {
        return [UInt8(type)] + [3, 3] + UInt16(fragment.count).bytes + fragment
    }

    func make_tls_handshake(msg_type: UInt8, body: [UInt8]) -> [UInt8] {
        return [msg_type] + UInt32(body.count).bytes3 + body
    }

    func make_tls_client_hello() -> [UInt8] {
        let (a, b, _) = TLSClient.cipherSuite[self.cipherIndex]
        let cipherBytes: [UInt8] = [UInt8(a), UInt8(b)]
        var bytes: [UInt8] = []
        bytes += [ 3, 3 /* client_version */]
        bytes += [UInt8](repeating: 0, count: 32)
        bytes += [0 /* SessionID */]
        bytes += [ 0, UInt8(cipherBytes.count) ] + cipherBytes
        bytes += [ 1, 0 /* compression_methods */]
        return bytes
    }
}

