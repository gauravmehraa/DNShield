import tkinter as tk
import threading, queue, time, re, ast, requests
import pandas as pd
import numpy as np
import joblib
import tensorflow.keras.models as keras_models

from datetime import datetime
from tkinter import messagebox, scrolledtext, ttk
from math import log2
from collections import Counter
from PIL import Image, ImageTk
from scapy.all import sniff, DNS, DNSQR, DNSRR, get_if_list

firewall_running = False
firewall_thread = None
message_queue = queue.Queue()
consecutive_threat_count = 0  # Counter for consecutive harmful predictions
api_logs = []

# ---------------------------
# Load model and encoders
# ---------------------------
model = load_model('models/model_batchsize64_sequence5.h5')
le_label = joblib.load('encoders/label_encoder.pkl')
le_tld = joblib.load('encoders/le_dns_top_level_domain.pkl')
le_sld = joblib.load('encoders/le_dns_second_level_domain.pkl')
scaler = joblib.load('encoders/scaler.pkl')

# ---------------------------
# Feature extraction
# ---------------------------
def parse_list_safe(list_entry):
    if isinstance(list_entry, list):
        return list_entry
    elif isinstance(list_entry, str):
        try:
            return ast.literal_eval(list_entry)
        except (ValueError, SyntaxError):
            return []
    else:
        return []

def extract_vowels_consonants(dist):
    vowels = set('aeiou')
    consonants = set('bcdfghjklmnpqrstvwxyz')
    vowel_count = 0
    consonant_count = 0
    if isinstance(dist, str):
        try:
            dist = ast.literal_eval(dist)
        except (ValueError, SyntaxError):
            dist = {}
    if isinstance(dist, dict):
        for ch, cnt in dist.items():
            if ch in vowels:
                vowel_count += cnt
            elif ch in consonants:
                consonant_count += cnt
    return vowel_count, consonant_count

feature_order = [
    'dns_domain_name_length',
    'numerical_percentage',
    'character_entropy',
    'max_continuous_numeric_len',
    'max_continuous_alphabet_len',
    'vowels_consonant_ratio',
    'conv_freq_vowels_consonants',
    'packets_numbers',
    'receiving_packets_numbers',
    'sending_packets_numbers',
    'receiving_bytes',
    'sending_bytes',
    'distinct_ttl_values',
    'ttl_values_min',
    'ttl_values_max',
    'ttl_values_mean',
    'dns_top_level_domain_encoded',
    'dns_second_level_domain_encoded',
    'uni_gram_count',
    'bi_gram_count',
    'tri_gram_count',
    'query_resource_record_type_count',
    'ans_resource_record_type_count',
    'query_resource_record_class_count',
    'ans_resource_record_class_count',
    'vowel_count',
    'consonant_count'
]

# ---------------------------
# Buffer
# ---------------------------
sequence_length = 5
event_buffer = []

def preprocess_event(event):
    try:
        _ = pd.to_datetime(event.get('timestamp'))
    except Exception:
        pass

    placeholder = 'unknown'
    tld = event.get('dns_top_level_domain', placeholder) or placeholder
    sld = event.get('dns_second_level_domain', placeholder) or placeholder
    if tld not in le_tld.classes_:
        tld = 'unknown'
    if sld not in le_sld.classes_:
        sld = 'unknown'
    tld_encoded = int(le_tld.transform([tld])[0])
    sld_encoded = int(le_sld.transform([sld])[0])
    
    uni_gram_list = parse_list_safe(event.get('uni_gram_domain_name', []))
    bi_gram_list = parse_list_safe(event.get('bi_gram_domain_name', []))
    tri_gram_list = parse_list_safe(event.get('tri_gram_domain_name', []))
    uni_gram_count = len(uni_gram_list)
    bi_gram_count = len(bi_gram_list)
    tri_gram_count = len(tri_gram_list)
    
    def count_unique(val):
        lst = parse_list_safe(val)
        return len(set(lst)) if lst else 0
    query_rr_type_count = count_unique(event.get('query_resource_record_type', []))
    ans_rr_type_count = count_unique(event.get('ans_resource_record_type', []))
    query_rr_class_count = count_unique(event.get('query_resource_record_class', []))
    ans_rr_class_count = count_unique(event.get('ans_resource_record_class', []))
    
    vowel_count, consonant_count = extract_vowels_consonants(event.get('character_distribution', {}))
    
    conv_freq = event.get('conv_freq_vowels_consonants', 0.0)
    
    features = {
        'dns_domain_name_length': event.get('dns_domain_name_length', 0),
        'numerical_percentage': event.get('numerical_percentage', 0.0),
        'character_entropy': event.get('character_entropy', 0.0),
        'max_continuous_numeric_len': event.get('max_continuous_numeric_len', 0),
        'max_continuous_alphabet_len': event.get('max_continuous_alphabet_len', 0),
        'packets_numbers': event.get('packets_numbers', 0),
        'receiving_packets_numbers': event.get('receiving_packets_numbers', 0),
        'sending_packets_numbers': event.get('sending_packets_numbers', 0),
        'receiving_bytes': event.get('receiving_bytes', 0),
        'sending_bytes': event.get('sending_bytes', 0),
        'distinct_ttl_values': event.get('distinct_ttl_values', 0),
        'ttl_values_min': event.get('ttl_values_min', -1),
        'ttl_values_max': event.get('ttl_values_max', -1),
        'ttl_values_mean': event.get('ttl_values_mean', -1.0),
        'uni_gram_count': uni_gram_count,
        'bi_gram_count': bi_gram_count,
        'tri_gram_count': tri_gram_count,
        'query_resource_record_type_count': query_rr_type_count,
        'ans_resource_record_type_count': ans_rr_type_count,
        'query_resource_record_class_count': query_rr_class_count,
        'ans_resource_record_class_count': ans_rr_class_count,
        'vowels_consonant_ratio': event.get('vowels_consonant_ratio', 0.0),
        'conv_freq_vowels_consonants': conv_freq,
        'vowel_count': vowel_count,
        'consonant_count': consonant_count,
        'dns_top_level_domain_encoded': tld_encoded,
        'dns_second_level_domain_encoded': sld_encoded
    }
    return features

def predict_dns_event(event):
    features = preprocess_event(event)
    df_event = pd.DataFrame([features], columns=feature_order)
    scaled_features = scaler.transform(df_event)
    event_buffer.append(scaled_features[0])
    while len(event_buffer) < sequence_length:
        event_buffer.insert(0, scaled_features[0])
    if len(event_buffer) > sequence_length:
        event_buffer.pop(0)
    sequence_input = np.array(event_buffer).reshape(1, sequence_length, -1)
    pred_probs = model.predict(sequence_input)
    pred_class = np.argmax(pred_probs, axis=1)[0]
    predicted_label = le_label.inverse_transform([pred_class])[0]
    return predicted_label, pred_probs

def send_api_logs(logs):
    message_queue.put(('api_status', "Uploading logs..."))
    try: response = requests.post("http://localhost:8000/api/log/upload", json=logs)
    except Exception as e: print("API call error:", e)
    message_queue.put(('api_status', ""))

def process_packet(packet):
    global consecutive_threat_count, api_logs
    if packet.haslayer(DNS):
        dns_layer = packet.getlayer(DNS)
        event_type = "Query" if dns_layer.qr == 0 else "Response"
        if packet.haslayer(DNSQR):
            query_name = packet[DNSQR].qname.decode('utf-8').strip('.')
            if not query_name: query_name = "unknown"
        elif packet.haslayer(DNSRR):
            query_name = packet[DNSRR].rrname.decode('utf-8').strip('.')
            if not query_name: query_name = "unknown"
        else: query_name = "unknown"
        
        event = {}
        event['timestamp'] = datetime.fromtimestamp(packet.time).strftime("%Y-%m-%d %H:%M:%S.%f")
        parts = query_name.split('.')
        if len(parts) >= 2:
            event['dns_top_level_domain'] = parts[-1]
            event['dns_second_level_domain'] = parts[-2]
        else:
            event['dns_top_level_domain'] = 'unknown'
            event['dns_second_level_domain'] = 'unknown'
        event['dns_domain_name_length'] = len(query_name)
        digits = sum(c.isdigit() for c in query_name)
        event['numerical_percentage'] = digits / len(query_name) if query_name else 0.0
        freq = {}
        for c in query_name: freq[c] = freq.get(c, 0) + 1
        entropy = -sum((count/len(query_name)) * log2(count/len(query_name)) for count in freq.values()) if query_name else 0.0
        event['character_entropy'] = entropy
        numeric_runs = re.findall(r'\d+', query_name)
        event['max_continuous_numeric_len'] = max((len(run) for run in numeric_runs), default=0)
        alpha_runs = re.findall(r'[a-zA-Z]+', query_name)
        event['max_continuous_alphabet_len'] = max((len(run) for run in alpha_runs), default=0)
        event['packets_numbers'] = 1
        event['receiving_packets_numbers'] = 1 if dns_layer.qr == 1 else 0
        event['sending_packets_numbers'] = 1 if dns_layer.qr == 0 else 0
        event['receiving_bytes'] = len(packet) if dns_layer.qr == 1 else 0
        event['sending_bytes'] = len(packet) if dns_layer.qr == 0 else 0
        if packet.haslayer(DNSRR):
            ttl = packet[DNSRR].ttl
            event['distinct_ttl_values'] = 1
            event['ttl_values_min'] = ttl
            event['ttl_values_max'] = ttl
            event['ttl_values_mean'] = float(ttl)
        else:
            event['distinct_ttl_values'] = 0
            event['ttl_values_min'] = -1
            event['ttl_values_max'] = -1
            event['ttl_values_mean'] = -1.0
        event['query_resource_record_type'] = []
        event['ans_resource_record_type'] = []
        event['query_resource_record_class'] = []
        event['ans_resource_record_class'] = []

        def create_ngrams(s, n):
            return [s[i:i+n] for i in range(len(s)-n+1)]

        event['uni_gram_domain_name'] = create_ngrams(query_name, 1)
        event['bi_gram_domain_name'] = create_ngrams(query_name, 2)
        event['tri_gram_domain_name'] = create_ngrams(query_name, 3)
        event['character_distribution'] = dict(Counter(query_name))
        vowels = set('aeiouAEIOU')
        consonants = set('bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ')
        vowel_count = sum(1 for c in query_name if c in vowels)
        consonant_count = sum(1 for c in query_name if c in consonants)
        event['vowels_consonant_ratio'] = vowel_count / consonant_count if consonant_count > 0 else 0.0

        label, probs = predict_dns_event(event)
        log_label = label.lower()
        log_dict = {
            "timestamp": event['timestamp'].split('.')[0],
            "prediction": log_label,
            "domain": query_name,
            "event_type": event_type,
            "dns_domain_name_length": event.get('dns_domain_name_length', 0),
            "numerical_percentage": event.get('numerical_percentage', 0),
            "character_entropy": event.get('character_entropy', 0),
            "max_numeric_length": event.get('max_continuous_numeric_len', 0),
            "max_alphabet_length": event.get('max_continuous_alphabet_len', 0),
            "vowels_consonant_ratio": event.get('vowels_consonant_ratio', 0),
            "receiving_bytes": event.get('receiving_bytes', 0),
            "sending_bytes": event.get('sending_bytes', 0),
            "ttl_mean": event.get('ttl_values_mean', -1)
        }
        log_dict["message"] = f"[{log_dict['timestamp']}] [{label} {event_type}]: {query_name}"
        message_queue.put(('log', log_dict))
        
        if log_label != "system":
            api_logs.append(log_dict)
            if len(api_logs) >= 5:
                send_api_logs(api_logs)
                api_logs.clear()
        
        if log_label in ['malware', 'phishing', 'spam']: consecutive_threat_count += 1
        else: consecutive_threat_count = 0
        if consecutive_threat_count >= 3:
            message_queue.put(('alert', "Warning: Detected potential harmful activity more than 2/3 times in a row!"))
            consecutive_threat_count = 0

def run_firewall():
    while firewall_running:
        sniff(filter="udp port 53", iface="Ethernet", prn=process_packet, store=0, timeout=1)

# ---------------------------
# UI
# ---------------------------
class FirewallUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("DNShield")
        self.geometry("750x700")
        self.iconbitmap("icons/icon.ico")
        icon = Image.open('icons/icon.png')
        photo = ImageTk.PhotoImage(icon)
        self.wm_iconphoto(False, photo)
        self.configure(bg="#f0f0f0")
        
        self.api_status_label = ttk.Label(self, text="", font=('Segoe UI', 10), foreground="blue")
        self.api_status_label.place(x=10, y=10)
        self.all_logs = []
        
        style = ttk.Style(self)
        style.theme_use('clam')
        style.configure('TButton', font=('Segoe UI', 10, 'bold'), padding=6)
        style.configure('Header.TLabel', font=('Segoe UI', 18, 'bold'), background="#f0f0f0", foreground="#333")
        style.configure('SubHeader.TLabel', font=('Segoe UI', 12), background="#f0f0f0", foreground="#666")
        
        header_frame = ttk.Frame(self, padding=(20, 10))
        header_frame.pack(fill='x')
        header_label = ttk.Label(header_frame, text="DNShield Control Panel", style='Header.TLabel')
        header_label.pack(side='left', anchor='center')
        
        filter_frame = ttk.Frame(self, padding=(20, 5))
        filter_frame.pack(fill='x')
        ttk.Label(filter_frame, text="Filter Logs:", font=('Segoe UI', 10)).pack(side='left')
        self.filter_var = tk.StringVar()
        self.filter_combobox = ttk.Combobox(filter_frame, textvariable=self.filter_var, values=["All", "Benign", "Malware", "Phishing", "Spam"], state="readonly", width=12)
        self.filter_combobox.current(0)
        self.filter_combobox.pack(side='left', padx=10)
        self.filter_combobox.bind("<<ComboboxSelected>>", self.update_log_view)
        
        stats_frame = ttk.Frame(self, padding=(20, 5))
        stats_frame.pack(fill='x')
        self.stats_label = ttk.Label(stats_frame, text="Stats: ", font=('Segoe UI', 10))
        self.stats_label.pack(side='left')
        
        content_frame = ttk.Frame(self, padding=(20, 10))
        content_frame.pack(expand=True, fill='both')
        
        log_frame = ttk.LabelFrame(content_frame, text="DNS Logs", padding=(10, 10))
        log_frame.pack(expand=True, fill='both', pady=(0,10))
        self.log_widget = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, font=('Segoe UI', 10), state='disabled', background="#ffffff")
        self.log_widget.pack(expand=True, fill='both')
        
        self.log_widget.tag_configure("benign", foreground="#008000", font=("Segoe UI", 10))
        self.log_widget.tag_configure("malware", foreground="#FF0000", font=("Segoe UI", 10))
        self.log_widget.tag_configure("phishing", foreground="#FFA500", font=("Segoe UI", 10))
        self.log_widget.tag_configure("spam", foreground="#FFD700", font=("Segoe UI", 10))
        self.log_widget.tag_configure("other", foreground="#000000", font=("Segoe UI", 10))
        
        button_frame = ttk.Frame(content_frame)
        button_frame.pack(pady=10)
        
        start_img = Image.open("icons/start_icon.png")
        start_img = start_img.resize((20, 20))
        self.start_icon = ImageTk.PhotoImage(start_img)
        stop_img = Image.open("icons/stop_icon.png")
        stop_img = stop_img.resize((20, 20))
        self.stop_icon = ImageTk.PhotoImage(stop_img)
        delete_img = Image.open("icons/delete_icon.png")
        delete_img = delete_img.resize((20, 20))
        self.delete_icon = ImageTk.PhotoImage(delete_img)
        self.start_button = ttk.Button(button_frame, text=" Start Firewall", command=self.start_firewall, image=self.start_icon, compound="left")
        self.start_button.pack(side='left', padx=10)
        self.stop_button = ttk.Button(button_frame, text=" Stop Firewall", command=self.stop_firewall, image=self.stop_icon, compound="left", state='disabled')
        self.stop_button.pack(side='left', padx=10)
        self.clear_button = ttk.Button(button_frame, text=" Clear Logs", command=self.clear_logs, image=self.delete_icon, compound="left")
        self.clear_button.pack(side='left', padx=10)
        
        status_frame = ttk.Frame(self, relief='sunken', padding=5)
        status_frame.pack(fill='x', side='bottom')
        self.status_indicator = ttk.Label(status_frame, text="●", font=('Segoe UI', 12, 'bold'))
        self.status_indicator.pack(side='left')
        self.status_var = tk.StringVar()
        self.status_var.set(" Status: Idle")
        self.status_label = ttk.Label(status_frame, textvariable=self.status_var, anchor='w')
        self.status_label.pack(side='left', padx=5)
        self.update_status_indicator("idle")

        self.poll_queue()
    
    def update_status_indicator(self, status):
        color = {"running": "green", "stopped": "red", "alert": "yellow", "idle": "gray"}.get(status, "gray")
        self.status_indicator.configure(foreground=color)
    
    def update_stats(self):
        user_logs = [log for log in self.all_logs if log["prediction"] != "system"]
        total = len(user_logs)
        benign = sum(1 for log in user_logs if log["prediction"] == "benign")
        malware = sum(1 for log in user_logs if log["prediction"] == "malware")
        phishing = sum(1 for log in user_logs if log["prediction"] == "phishing")
        spam = sum(1 for log in user_logs if log["prediction"] == "spam")
        benign_pct = (benign / total * 100) if total else 0
        malware_pct = (malware / total * 100) if total else 0
        phishing_pct = (phishing / total * 100) if total else 0
        spam_pct = (spam / total * 100) if total else 0
        
        text = (f"Total Logs: {total}  |  "
                f"Benign: {benign} ({benign_pct:.1f}%)  |  "
                f"Malware: {malware} ({malware_pct:.1f}%)  |  "
                f"Phishing: {phishing} ({phishing_pct:.1f}%)  |  "
                f"Spam: {spam} ({spam_pct:.1f}%)")
        self.stats_label.config(text=text)
    
    def log(self, log_dict):
        self.all_logs.append(log_dict)
        self.update_stats()
        self.update_log_view()
    
    def update_log_view(self, event=None):
        current_filter = self.filter_var.get().lower()
        self.log_widget.configure(state='normal')
        self.log_widget.delete("1.0", tk.END)
        for entry in self.all_logs:
            if current_filter == "all" or entry["prediction"] == current_filter:
                self.log_widget.insert(tk.END, entry["message"] + "\n", entry["prediction"])
        self.log_widget.configure(state='disabled')
        self.log_widget.see(tk.END)
    
    def clear_logs(self):
        self.all_logs.clear()
        self.log_widget.configure(state='normal')
        self.log_widget.delete("1.0", tk.END)
        self.log_widget.configure(state='disabled')
        self.update_stats()
    
    def poll_queue(self):
        while True:
            try: msg_type, content = message_queue.get_nowait()
            except queue.Empty: break
            if msg_type == 'log': self.log(content)
            elif msg_type == 'alert':
                messagebox.showwarning("Alert", content)
                self.status_var.set(" Status: Alert triggered!")
                self.update_status_indicator("alert")
            elif msg_type == 'api_status': self.api_status_label.config(text=content)
        self.after(100, self.poll_queue)
    
    def start_firewall(self):
        global firewall_running, firewall_thread
        if not firewall_running:
            firewall_running = True
            firewall_thread = threading.Thread(target=run_firewall, daemon=True)
            firewall_thread.start()
            self.start_button.config(state='disabled')
            self.stop_button.config(state='normal')
            self.status_var.set(" Status: Running")
            self.update_status_indicator("running")
            self.log({
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "prediction": "system",
                "message": "Firewall started."
            })
            self.log({
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "prediction": "system",
                "message": ""
            })
    
    def stop_firewall(self):
        global firewall_running, firewall_thread
        if firewall_running:
            firewall_running = False
            if firewall_thread: firewall_thread.join(timeout=2)
            self.start_button.config(state='normal')
            self.stop_button.config(state='disabled')
            self.status_var.set(" Status: Stopped")
            self.update_status_indicator("stopped")
            self.log({
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "prediction": "system",
                "message": "Firewall stopped."
            })
            self.log({
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "prediction": "system",
                "message": ""
            })

if __name__ == '__main__':
    app = FirewallUI()
    app.mainloop()