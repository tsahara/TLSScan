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

    func make_tls_plaintext(type: Int, payload: [UInt8]) -> [UInt8] {
        return [3, 1] + UInt16(payload.count).bytes + payload
    }

    func make_client_hello() -> [UInt8] {
        return make_tls_plaintext(type: 22, payload: [])
    }
}

