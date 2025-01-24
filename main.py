import pydivert
import dnslib
import datetime
import time
from collections import defaultdict
import math
import json
import csv
import os
import sys

class Flow:
    def __init__(self, flow_id, timestamp, src_ip, src_port, dst_ip, dst_port, protocol):
        self.flow_id = flow_id
        self.start_time = timestamp
        self.end_time = timestamp
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol
        self.packets = []
        self.sending_packets = []
        self.packet_lengths = []
        self.packet_timestamps = []
        self.dns_features = {}
    
    def add_packet(self, packet, direction, timestamp):
        self.packets.append(packet)
        self.packet_lengths.append(len(packet.payload))
        self.packet_timestamps.append(timestamp)
        self.end_time = timestamp
        if direction == 'sending':
            self.sending_packets.append(packet)
    
    def compute_features(self):
        if not self.sending_packets:
            return None
        dns_record = self.dns_features.get('dns_record', None)
        if not dns_record or not dns_record.questions:
            return None
        is_response = getattr(dns_record.header, 'qr', 0) == 1
        qname = str(dns_record.questions[0].get_qname()).rstrip('.')
        parts = qname.split('.')
        answers = getattr(dns_record, 'answers', [])
        questions = getattr(dns_record, 'questions', [])
        auth = getattr(dns_record, 'auth', [])
        ar = getattr(dns_record, 'ar', [])
        
        features = {
            'flow_id': self.flow_id,
            'timestamp': datetime.datetime.fromtimestamp(self.start_time).strftime('%Y-%m-%d %H:%M:%S.%f'),
            'src_ip': self.src_ip,
            'src_port': self.src_port,
            'dst_ip': self.dst_ip,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'duration': self.end_time - self.start_time,
            'packets_numbers': len(self.packets),
            'receiving_packets_numbers': len([p for p in self.packets if p.dst_port != 53]),
            'sending_packets_numbers': len(self.sending_packets),
            'handshake_duration': 'not a tcp connection',
            'delta_start': 'not a tcp connection',
            'total_bytes': sum(len(p.payload) for p in self.packets),
            'receiving_bytes': sum(len(p.payload) for p in self.packets if p.dst_port != 53),
            'sending_bytes': sum(len(p.payload) for p in self.sending_packets),
            'packets_rate': len(self.packets) / (self.end_time - self.start_time) if (self.end_time - self.start_time) > 0 else 0.0,
            'receiving_packets_rate': len([p for p in self.packets if p.dst_port != 53]) / (self.end_time - self.start_time) if (self.end_time - self.start_time) > 0 else 0.0,
            'sending_packets_rate': len(self.sending_packets) / (self.end_time - self.start_time) if (self.end_time - self.start_time) > 0 else 0.0,
            'packets_len_rate': sum(self.packet_lengths) / (self.end_time - self.start_time) if (self.end_time - self.start_time) > 0 else 0.0,
            'receiving_packets_len_rate': sum(len(p.payload) for p in self.packets if p.dst_port != 53) / (self.end_time - self.start_time) if (self.end_time - self.start_time) > 0 else 0.0,
            'sending_packets_len_rate': sum(len(p.payload) for p in self.sending_packets) / (self.end_time - self.start_time) if (self.end_time - self.start_time) > 0 else 0.0,
            'mean_packets_len': sum(self.packet_lengths) / len(self.packet_lengths) if self.packet_lengths else 0.0,
            'mode_packets_len': mode(self.packet_lengths),
            'coefficient_of_variation_packets_len': (std_dev(self.packet_lengths) / (sum(self.packet_lengths) / len(self.packet_lengths))) if self.packet_lengths else 0.0,
            'dns_domain_name': qname,
            'dns_top_level_domain': parts[-1] if len(parts) >=1 else '',
            'dns_second_level_domain': parts[-2] if len(parts) >=2 else '',
            'dns_domain_name_length': len(qname),
            'dns_subdomain_name_length': '',
            'uni_gram_domain_name': json.dumps(list(qname)),
            'bi_gram_domain_name': json.dumps([qname[i:i+2] for i in range(len(qname)-1)]),
            'tri_gram_domain_name': json.dumps([qname[i:i+3] for i in range(len(qname)-2)]),
            'numerical_percentage': sum(c.isdigit() for c in qname) / len(qname) if len(qname) > 0 else 0.0,
            'character_distribution': json.dumps({c: qname.count(c) for c in set(qname)}),
            'character_entropy': calculate_entropy(qname),
            'vowels_consonant_ratio': calculate_vowels_consonants_ratio(qname),
            'conv_freq_vowels_consonants': calculate_vowels_consonants_freq(qname),
            'distinct_ttl_values': len(set([answer.ttl for answer in answers])) if is_response else 0,
            'ttl_values_mean': sum([answer.ttl for answer in answers]) / len(answers) if is_response and answers else 0.0,
            'ttl_values_mode': mode([answer.ttl for answer in answers]) if is_response and answers else 0.0,
            'ttl_values_coefficient_of_variation': (std_dev([answer.ttl for answer in answers]) / (sum([answer.ttl for answer in answers]) / len(answers))) if is_response and answers else 0.0,
            'distinct_A_records': sum(1 for answer in answers if answer.rtype == dnslib.QTYPE.A) if is_response else 0,
            'distinct_NS_records': sum(1 for answer in answers if answer.rtype == dnslib.QTYPE.NS) if is_response else 0,
            'average_authority_resource_records': len(auth) / len(answers) if is_response and answers else 0.0,
            'average_additional_resource_records': len(ar) / len(answers) if is_response and answers else 0.0,
            'average_answer_resource_records': len(answers) / len(questions) if questions else 0.0,
            'query_resource_record_type': json.dumps([dnslib.QTYPE.get(q.qtype) for q in questions]) if questions else json.dumps([]),
            'ans_resource_record_type': json.dumps([dnslib.QTYPE.get(a.rtype) for a in answers]) if is_response and answers else json.dumps([]),
            'query_resource_record_class': json.dumps([dnslib.CLASS.get(q.qclass) for q in questions]) if questions else json.dumps([]),
            'ans_resource_record_class': json.dumps([dnslib.CLASS.get(a.rclass) for a in answers]) if is_response and answers else json.dumps([]),
            'label': 'Benign'
        }
        return features

def mode(lst):
    if not lst:
        return 0.0
    frequency = defaultdict(int)
    for item in lst:
        frequency[item] += 1
    max_freq = max(frequency.values())
    modes = [k for k, v in frequency.items() if v == max_freq]
    return modes[0] if modes else 0.0

def median(lst):
    sorted_lst = sorted(lst)
    n = len(sorted_lst)
    if n == 0:
        return 0.0
    if n % 2 == 1:
        return float(sorted_lst[n // 2])
    else:
        return (sorted_lst[n // 2 -1] + sorted_lst[n // 2]) / 2.0

def variance(lst):
    if len(lst) < 2:
        return 0.0
    mean = sum(lst) / len(lst)
    return sum((x - mean) **2 for x in lst) / (len(lst) -1)

def std_dev(lst):
    return math.sqrt(variance(lst))

def skewness(lst):
    if len(lst) < 3:
        return 0.0
    mean = sum(lst) / len(lst)
    var = variance(lst)
    std_dev_val = math.sqrt(var)
    if std_dev_val == 0:
        return 0.0
    skew = sum((x - mean) **3 for x in lst) / ((len(lst) -1) * std_dev_val **3)
    return skew

def calculate_entropy(domain):
    if not domain:
        return 0.0
    char_dist = defaultdict(int)
    for c in domain:
        char_dist[c] += 1
    entropy = 0
    for count in char_dist.values():
        p = count / len(domain)
        entropy -= p * math.log2(p) if p > 0 else 0
    return entropy

def calculate_vowels_consonants_ratio(domain):
    vowels = set('aeiouAEIOU')
    consonants = set('bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ')
    vowel_count = sum(1 for c in domain if c in vowels)
    consonant_count = sum(1 for c in domain if c in consonants)
    return vowel_count / consonant_count if consonant_count > 0 else 0.0

def calculate_vowels_consonants_freq(domain):
    vowels = set('aeiouAEIOU')
    consonants = set('bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ')
    vowel_count = sum(1 for c in domain if c in vowels)
    consonant_count = sum(1 for c in domain if c in consonants)
    total = vowel_count + consonant_count
    return vowel_count / total if total > 0 else 0.0

def get_flow_key(packet):
    return f"{packet.src_addr}_{packet.src_port}_{packet.dst_addr}_{packet.dst_port}_{packet.protocol}"

def cleanup_flows(active_flows, current_time, FLOW_TIMEOUT, csv_writer):
    expired = [key for key, flow in active_flows.items() if current_time - flow.end_time > FLOW_TIMEOUT]
    for key in expired:
        flow = active_flows[key]
        features = flow.compute_features()
        if features:
            csv_writer.writerow(features)
        del active_flows[key]

def extract_dns_features(dns_record):
    return {'dns_record': dns_record}

def main():
    active_flows = {}
    FLOW_TIMEOUT = 60
    csv_file = 'dns_queries.csv'
    fieldnames = [
        'flow_id', 'timestamp', 'src_ip', 'src_port', 'dst_ip', 'dst_port',
        'protocol', 'duration', 'packets_numbers', 'receiving_packets_numbers',
        'sending_packets_numbers', 'handshake_duration', 'delta_start',
        'total_bytes', 'receiving_bytes', 'sending_bytes',
        'packets_rate', 'receiving_packets_rate', 'sending_packets_rate',
        'packets_len_rate', 'receiving_packets_len_rate', 'sending_packets_len_rate',
        'mean_packets_len', 'mode_packets_len', 'coefficient_of_variation_packets_len',
        'dns_domain_name', 'dns_top_level_domain', 'dns_second_level_domain',
        'dns_domain_name_length', 'dns_subdomain_name_length',
        'uni_gram_domain_name', 'bi_gram_domain_name', 'tri_gram_domain_name',
        'numerical_percentage', 'character_distribution', 'character_entropy',
        'vowels_consonant_ratio', 'conv_freq_vowels_consonants',
        'distinct_ttl_values', 'ttl_values_mean',
        'ttl_values_mode', 'ttl_values_coefficient_of_variation',
        'distinct_A_records', 'distinct_NS_records',
        'average_authority_resource_records',
        'average_additional_resource_records',
        'average_answer_resource_records',
        'query_resource_record_type', 'ans_resource_record_type',
        'query_resource_record_class', 'ans_resource_record_class',
        'label'
    ]
    
    try:
        # Ensure CSV file exists with headers
        #write_header = not os.path.isfile(csv_file)
        write_header = True
        with open(csv_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            if write_header: writer.writeheader()
            
            with pydivert.WinDivert("udp.DstPort == 53 or udp.SrcPort == 53") as w:
                print("DNS interceptor started...")
                try:
                    while True:
                        packet = w.recv()
                        current_time = time.time()
                        cleanup_flows(active_flows, current_time, FLOW_TIMEOUT, writer)
                        direction = 'sending' if packet.dst_port == 53 else 'receiving'
                        flow_key = get_flow_key(packet)
                        if flow_key not in active_flows:
                            timestamp_str = datetime.datetime.fromtimestamp(current_time).strftime('%Y-%m-%d_%H:%M:%S.%f')
                            flow_id = f"{timestamp_str}_{packet.src_addr}_{packet.src_port}_{packet.dst_addr}_{packet.dst_port}"
                            active_flows[flow_key] = Flow(flow_id, current_time, packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port, 'DNS')
                        active_flows[flow_key].add_packet(packet, direction, current_time)
                        if direction == 'sending':
                            try:
                                if len(packet.payload) < 12:
                                    continue
                                dns_record = dnslib.DNSRecord.parse(packet.payload)
                                active_flows[flow_key].dns_features = extract_dns_features(dns_record)
                                # model prediction
                            except Exception as e:
                                # Optionally log parsing errors
                                print(f"DNS parsing error: {e}", file=sys.stderr)
                                pass
                        w.send(packet, recalculate_checksum=True)
                except KeyboardInterrupt:
                    print("\nStopping DNS interceptor...")
                    for key, flow in active_flows.items():
                        features = flow.compute_features()
                        if features:
                            writer.writerow(features)
                    print("All active flows have been written to the CSV.")
    except Exception as e:
        print(f"An error occurred: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
