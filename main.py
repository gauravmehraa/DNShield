import pydivert
import dnslib
import binascii

def main():
    with pydivert.WinDivert("udp.DstPort == 53") as window: # 53 = DNS port
        print("DNS interceptor started...")
        for packet in window:
            try:
                p = binascii.unhexlify(packet.payload.hex())
                record = dnslib.DNSRecord.parse(p)
                record = str(dnslib.DNSRecord.parse(packet.payload)).split()
                
                query = {}
                record = [field.replace(";","").replace(":","").replace(",","").rstrip(".") for field in record]

                query["opcode"] = record[record.index("opcode")+1]
                query["status"] = record[record.index("status")+1]
                query["id"] = record[record.index("id")+1]
                query["domain"] = record[(record.index("SECTION")+1)]
                query["class"] = record[(record.index("SECTION")+2)]
                query["type"] = record[(record.index("SECTION")+3)]
                
                for k, v in query.items():
                    print(f"{k}: {v}")
                    
                print("-" * 100)
            except Exception as e:
                print("Error processing DNS query:", str(e))
            finally:
                window.send(packet, recalculate_checksum=True)

if __name__ == "__main__":
    main()
