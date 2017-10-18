//
//  ViewController.swift
//  TLSScan
//
//  Created by Tomoyuki Sahara on 2017/09/19.
//  Copyright © 2017 Tomoyuki Sahara. All rights reserved.
//

import Cocoa

class ViewController: NSViewController {
    @IBOutlet weak var hostname: NSTextField!

    var client: TLSClient?

    override func viewDidLoad() {
        super.viewDidLoad()
        hostname!.stringValue = "google.com"

        // Do any additional setup after loading the view.
    }

    @IBAction func scan(_ sender: NSButton) {
        self.client = TLSClient(host: self.hostname.stringValue)
        self.client!.scan()
    }

    override var representedObject: Any? {
        didSet {
        // Update the view, if already loaded.
        }
    }


}
