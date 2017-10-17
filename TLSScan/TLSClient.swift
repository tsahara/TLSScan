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
        return [ b[0] + b[1] + b[2] ]
    }
}

class TLSClient: NSObject, StreamDelegate {
    let host: String

    var inputStream: InputStream?
    var outputStream: OutputStream?

    init(host: String) {
        self.host = host
    }

    func connect() {
        var readStream: Unmanaged<CFReadStream>?
        var writeStream: Unmanaged<CFWriteStream>?

        print(host)

        CFStreamCreatePairWithSocketToHost(nil, self.host as CFString, 443, &readStream, &writeStream)
        self.inputStream  = readStream!.takeRetainedValue()
        self.outputStream = writeStream!.takeRetainedValue()

        if let out = self.outputStream {
            out.delegate = self
            out.schedule(in: RunLoop.current, forMode: .defaultRunLoopMode)
            out.open()
        }
    }

    func stream(_ aStream: Stream, handle eventCode: Stream.Event) {
        switch eventCode {
        case Stream.Event.openCompleted:
            print("open")
        case Stream.Event.hasSpaceAvailable:
            print("writable")
        default:
            print("eventCode = \(eventCode)")
        }
    }

    func make_client_hello() -> [UInt8] {
        return make_tls_plaintext(type: 22 /* handshake */, fragment: make_tls_handshake(msg_type: 1 /* client_hello */, body: []))
    }

    func make_tls_plaintext(type: Int, fragment: [UInt8]) -> [UInt8] {
        return [UInt8(type)] + [3, 1] + UInt16(fragment.count).bytes + fragment
    }

    func make_tls_handshake(msg_type: UInt8, body: [UInt8]) -> [UInt8] {
        return [msg_type] + UInt32(body.count).bytes3 + body
    }

    func make_tls_client_hello() -> [UInt8] {
        return [3, 1 /* client_version */] + [UInt8](repeating: 0, count: 32) + [0 /* SessionID */] + [ 0, 2, 0, 5 ] + [ 1, 0 /* compression_methods */]
    }
}

