#!/usr/bin/env ruby

# https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv

File.open("tls-parameters-4.csv").each { |line|
  if line =~ /^"(0x\h\h),(0x\h\h)",(TLS_\w+)/
    puts "(#{$1}, #{$2}, \"#{$3}\"),"
  end
}
