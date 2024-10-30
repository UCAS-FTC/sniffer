class Filter:
    filStr = ""

    def filter(self, protocolPOB, protocol, portPOB, port, srcAddrPOB, srcAddr, dstAddrPOB, dstAddr) -> str:
        self.filStr = ""
        if protocol != "":
            self.filStr += "("
            if protocolPOB == "ONLY":
                self.filStr += str(protocol).replace(",", " or ")
            else:
                self.filStr += "not (" + str(protocol).replace(",", " and ")
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
                self.filStr += "not (" + str(port).replace(",", " and ")
                self.filStr += ")"
            self.filStr += ")"
        if srcAddr != "":
            if srcAddrPOB == "ONLY" and self.filStr == "":
                self.filStr += "(src host " + str(srcAddr).replace(",", " or src host ")
            elif srcAddrPOB == "ONLY":
                self.filStr += "and (src host " + str(srcAddr).replace(",", " or src host ")
            elif self.filStr == "":
                self.filStr += "(not (src host " + str(srcAddr).replace(",", " and src host ")
                self.filStr += ")"
            else:
                self.filStr += "and (not (src host " + str(srcAddr).replace(",", " and src host ")
                self.filStr += ")"
            self.filStr += ")"
        if dstAddr != "":
            if dstAddrPOB == "ONLY" and self.filStr == "":
                self.filStr += "(dst host " + str(dstAddr).replace(",", " or dst host ")
            elif dstAddrPOB == "ONLY":
                self.filStr += "and (dst host " + str(dstAddr).replace(",", " or dst host ")
            elif self.filStr == "":
                self.filStr += "(not (dst host " + str(dstAddr).replace(",", " and dst host ")
                self.filStr += ")"
            else:
                self.filStr += "and (not (dst host " + str(dstAddr).replace(",", " and dst host ")
                self.filStr += ")"
            self.filStr += ")"
        print(self.filStr)
        return self.filStr
