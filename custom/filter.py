class Filter:
    filStr = ""

    def filter(self, protocolPOB, protocol, portPOB, port, srcAddrPOB, srcAddr, dstAddrPOB, dstAddr) -> str:
        self.filStr = ""
        if protocol != "":
            self.filStr += "("
            if protocolPOB == "ONLY":
                if "ipv6" in protocol:
                    protocol = protocol.replace("ipv6", "ip6")
                if "icmpv6" in protocol:
                    protocol = protocol.replace("icmpv6", "icmp6")

                self.filStr += str(protocol).replace(",", " or ")
            else:
                self.filStr += "not (" + str(protocol).replace(",", " or ")
                self.filStr += ")"
            self.filStr += ")"
        if port != "":
            if self.filStr != "":
                self.filStr += " and ("
            else:
                self.filStr += "("
            if portPOB == "ONLY":
                self.filStr += str(port).replace(",", " or ")
            else:
                self.filStr += "not (" + str(port).replace(",", " or ")
                self.filStr += ")"
            self.filStr += ")"
        if srcAddr != "":
            if srcAddrPOB == "ONLY" and self.filStr == "":
                self.filStr += "(src host " + str(srcAddr).replace(",", " or src host ")
            elif srcAddrPOB == "ONLY":
                self.filStr += "and (src host " + str(srcAddr).replace(",", " or src host ")
            elif self.filStr == "":
                self.filStr += "(not (src host " + str(srcAddr).replace(",", " or src host ")
                self.filStr += ")"
            else:
                self.filStr += "and (not (src host " + str(srcAddr).replace(",", " or src host ")
                self.filStr += ")"
            self.filStr += ")"
        if dstAddr != "":
            if dstAddrPOB == "ONLY" and self.filStr == "":
                self.filStr += "(dst host " + str(dstAddr).replace(",", " or dst host ")
            elif dstAddrPOB == "ONLY":
                self.filStr += "and (dst host " + str(dstAddr).replace(",", " or dst host ")
            elif self.filStr == "":
                self.filStr += "(not (dst host " + str(dstAddr).replace(",", " or dst host ")
                self.filStr += ")"
            else:
                self.filStr += "and (not (dst host " + str(dstAddr).replace(",", " or dst host ")
                self.filStr += ")"
            self.filStr += ")"
        if "mdns" in protocol or "mdns," in protocol:
            self.filStr = str(self.filStr).replace("mdns,", "")
            self.filStr = str(self.filStr).replace("mdns", "")
            if protocolPOB == "ONLY":
                self.filStr += " (ip dst 224.0.0.251 or ip6 dst ff02::fb) and udp port 5353"
            else:
                self.filStr += " not ((ip dst 224.0.0.251 and udp port 5353) or (ip6 dst ff02::fb and udp port 5353)) "
        if "dns" in protocol or "dns," in protocol:
            self.filStr = str(self.filStr).replace("dns,", "")
            self.filStr = str(self.filStr).replace("dns", "")
            if protocolPOB == "ONLY":
                self.filStr += " and udp port 53"
            else:
                self.filStr += " and not udp port 53"
        if "tls" in protocol or "tls," in protocol:
            self.filStr = self.filStr.replace("tls,", "")
            self.filStr = self.filStr.replace("tls", "")
            if protocolPOB == "ONLY":
                self.filStr += " and (tcp port 443 or tcp port 8443)"
            else:
                self.filStr += " and not (tcp port 443 or tcp port 8443)"
        if "igmp" in protocol or "igmp," in protocol:
            self.filStr = self.filStr.replace("igmp,", "")
            self.filStr = self.filStr.replace("igmp", "")
            if protocolPOB == "ONLY":
                self.filStr += " and ip proto 2 "
            else:
                self.filStr += " and not ip proto 2 "
        if "  " in self.filStr:
            self.filStr = self.filStr.replace("  ", " ")
        if "() and" in self.filStr:
            self.filStr = self.filStr.replace("() and", " ")
        if "()" in self.filStr:
            self.filStr = self.filStr.replace("()", " ")
        return self.filStr