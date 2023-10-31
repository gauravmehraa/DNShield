import pydivert
import dnslib
import binascii

def main():
    with pydivert.WinDivert("udp.DstPort == 53 or udp.SrcPort == 53") as w: # 53 = DNS port
        print("DNS interceptor started...")
        for packet in w:
            try:
                p = binascii.unhexlify(packet.payload.hex())
                record = dnslib.DNSRecord.parse(p)
                print(record)


                '''
                record = str(dnslib.DNSRecord.parse(packet.payload)).split()
                query = {}
                record = record[2:]
                while ";;" in record:
                    record.remove(";;")
                
                record = [field.replace(";","").replace(":","").replace(",","").rstrip(".") for field in record]
                record[16] = record[16] + " " + record[17]
                del record[17]

                for i in range(0, len(record)-1, 2):
                    query[record[i]] = record[i+1]
                
                for k, v in query.items():
                    print(f"{k}: {v}")'''
                    

                print("-" * 50)
            except Exception as e:
                print("Error processing DNS query:", str(e))
            finally:
                w.send(packet, recalculate_checksum=True)

if __name__ == "__main__":
    main()
