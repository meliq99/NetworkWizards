import torch
import torch.nn as nn
import numpy as np
from scapy.all import sniff, IP, TCP, UDP
from sklearn.preprocessing import LabelEncoder, StandardScaler

# Load the trained model
class Net(nn.Module):
    def __init__(self):
        super(Net, self).__init__()
        self.fc1 = nn.Linear(13, 128)
        self.bn1 = nn.BatchNorm1d(128)
        self.fc2 = nn.Linear(128, 64)
        self.bn2 = nn.BatchNorm1d(64)
        self.fc3 = nn.Linear(64, 32)
        self.bn3 = nn.BatchNorm1d(32)
        self.fc4 = nn.Linear(32, 1)
        self.sigmoid = nn.Sigmoid()
        
    def forward(self, x):
        x = torch.relu(self.bn1(self.fc1(x)))
        x = torch.relu(self.bn2(self.fc2(x)))
        x = torch.relu(self.bn3(self.fc3(x)))
        x = self.sigmoid(self.fc4(x))
        return x

model = Net()
model.load_state_dict(torch.load('model_final.pth'))
model.eval()

# Pre-trained encoders and scaler
proto_encoder = LabelEncoder()
proto_encoder.classes_ = np.array(['3pc', 'a/n', 'aes-sp3-d', 'any', 'argus', 'aris', 'arp', 'ax.25', 'bbn-rcc',
                                   'bna', 'br-sat-mon', 'cbt', 'cftp', 'chaos', 'compaq-peer', 'cphb', 'cpnx',
                                   'crtp', 'crudp', 'dcn', 'ddp', 'ddx', 'dgp', 'egp', 'eigrp', 'emcon', 'encap',
                                   'etherip', 'fc', 'fire', 'ggp', 'gmtp', 'gre', 'hmp', 'i-nlsp', 'iatp', 'ib',
                                   'icmp', 'idpr', 'idpr-cmtp', 'idrp', 'ifmp', 'igmp', 'igp', 'il', 'ip', 'ipcomp',
                                   'ipcv', 'ipip', 'iplt', 'ipnip', 'ippc', 'ipv6', 'ipv6-frag', 'ipv6-no',
                                   'ipv6-opts', 'ipv6-route', 'ipx-n-ip', 'irtp', 'isis', 'iso-ip', 'iso-tp4',
                                   'kryptolan', 'l2tp', 'larp', 'leaf-1', 'leaf-2', 'merit-inp', 'mfe-nsp', 'mhrp',
                                   'micp', 'mobile', 'mtp', 'mux', 'narp', 'netblt', 'nsfnet-igp', 'nvp', 'ospf',
                                   'pgm', 'pim', 'pipe', 'pnni', 'pri-enc', 'prm', 'ptp', 'pup', 'pvp', 'qnx', 'rdp',
                                   'rsvp', 'rtp', 'rvd', 'sat-expak', 'sat-mon', 'sccopmce', 'scps', 'sctp', 'sdrp',
                                   'secure-vmtp', 'sep', 'skip', 'sm', 'smp', 'snp', 'sprite-rpc', 'sps', 'srp',
                                   'st2', 'stp', 'sun-nd', 'swipe', 'tcf', 'tcp', 'tlsp', 'tp++', 'trunk-1',
                                   'trunk-2', 'ttp', 'udp', 'unas', 'uti', 'vines', 'visa', 'vmtp', 'vrrp',
                                   'wb-expak', 'wb-mon', 'wsn', 'xnet', 'xns-idp', 'xtp', 'zero'])

service_encoder = LabelEncoder()
service_encoder.classes_ = np.array(['-', 'dhcp', 'dns', 'ftp', 'ftp-data', 'http', 'irc', 'pop3', 'radius', 'smtp',
                                     'snmp', 'ssh', 'ssl'])

state_encoder = LabelEncoder()
state_encoder.classes_ = np.array(['CON', 'ECO', 'FIN', 'INT', 'PAR', 'REQ', 'RST', 'URN', 'no'])

# Add the unknown labels to the classes
proto_encoder.classes_ = np.append(proto_encoder.classes_, 'unknown')
service_encoder.classes_ = np.append(service_encoder.classes_, 'unknown')
state_encoder.classes_ = np.append(state_encoder.classes_, 'unknown')

# Protocol mapping
protocol_mapping = {
    1: 'icmp',
    6: 'tcp',
    17: 'udp',
    47: 'gre',
    50: 'esp',
    51: 'ah',
    58: 'icmpv6',
    89: 'ospf'
    # Add more protocol numbers and names as needed
}

# Dictionary mapping common ports to services
port_to_service = {
    20: 'ftp_data',
    21: 'ftp',
    22: 'ssh',
    23: 'telnet',
    25: 'smtp',
    53: 'domain',
    67: 'bootps',
    68: 'bootpc',
    69: 'tftp',
    80: 'http',
    110: 'pop3',
    115: 'sftp',
    123: 'ntp_u',
    143: 'imap4',
    161: 'snmp',
    179: 'bgp',
    194: 'irc',
    443: 'http_443',
    445: 'microsoft-ds',
    993: 'imaps',
    995: 'pop3s',
    1080: 'socks',
    1521: 'sqlnet',
    3306: 'mysql',
    3389: 'ms-wbt-server',
    5432: 'postgresql',
    5900: 'vnc',
    8080: 'http_proxy'
    # Add more mappings as required
}

# Replace with actual scaler parameters used during training
scaler = StandardScaler()
scaler.mean_ = np.array([1.35938869e+00, 1.09606675e+02, 2.02986637e+01, 1.89695907e+01,
                         8.84484384e+03, 1.49289186e+04, 9.54061871e+04, 1.79546997e+02,
                         7.96095665e+01, 1.36751769e+02, 1.24173382e+02, 1.61891971e+00,
                         2.35517648e+00])
scaler.scale_ = np.array([6.48023038e+00, 2.23525372e+01, 1.36887207e+02, 1.10257956e+02,
                          1.74765146e+05, 1.43653808e+05, 1.65400507e+05, 1.02939718e+02,
                          1.10506548e+02, 2.04676776e+02, 2.58316319e+02, 2.30514410e+00,
                          8.67939407e-01])

# Define feature list
features_list = ['dur', 'proto', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'rate', 'sttl', 'dttl',
                 'smean', 'dmean', 'service', 'state']

class PacketFeatureExtractor:
    def __init__(self):
        self.packets = []
        self.start_time = None

    def process_packet(self, pkt):
        if IP not in pkt:
            print("Non-IP packet detected.")
            print(f"Packet summary: {pkt.summary()}")
            print("No attack detected.")
            return

        if not self.start_time:
            self.start_time = pkt.time
        self.packets.append(pkt)
        if len(self.packets) >= 100:  # Process after capturing 100 packets
            self.extract_features()
            self.packets = []  # Reset for next batch

    def extract_features(self):
        features = {}
        features['dur'] = max(pkt.time for pkt in self.packets) - min(pkt.time for pkt in self.packets)
        proto_value = protocol_mapping.get(self.packets[0].proto, 'unknown')
        features['proto'] = proto_encoder.transform([proto_value])[0]

        features['spkts'] = len(self.packets)
        features['dpkts'] = len([pkt for pkt in self.packets if pkt[IP].dst == self.packets[0][IP].src])
        features['sbytes'] = sum(len(pkt) for pkt in self.packets if pkt[IP].src == self.packets[0][IP].src)
        features['dbytes'] = sum(len(pkt) for pkt in self.packets if pkt[IP].dst == self.packets[0][IP].src)
        features['rate'] = features['spkts'] / features['dur'] if features['dur'] > 0 else 0
        features['sttl'] = self.packets[0][IP].ttl
        features['dttl'] = self.packets[-1][IP].ttl
        features['smean'] = features['sbytes'] / features['spkts'] if features['spkts'] > 0 else 0
        features['dmean'] = features['dbytes'] / features['dpkts'] if features['dpkts'] > 0 else 0
        
        # Determine service based on port
        if TCP in self.packets[0]:
            port = self.packets[0][TCP].dport
        elif UDP in self.packets[0]:
            port = self.packets[0][UDP].dport
        else:
            port = None

        service = port_to_service.get(port, '-')
        try:
            features['service'] = service_encoder.transform([service])[0]
        except ValueError:
            features['service'] = service_encoder.transform(['unknown'])[0]

        try:
            features['state'] = state_encoder.transform(['FIN' if 'F' in self.packets[0][TCP].flags else 'SYN' if 'S' in self.packets[0][TCP].flags else 'ACK'])[0] if TCP in self.packets[0] else state_encoder.transform(['-'])[0]
        except ValueError:
            features['state'] = state_encoder.transform(['unknown'])[0]
        
        self.detect_attack(features)
        
    def detect_attack(self, features):
        feature_values = np.array([features[feature] for feature in features_list]).reshape(1, -1)
        feature_values = scaler.transform(feature_values)
        feature_values = torch.tensor(feature_values, dtype=torch.float32)
        
        with torch.no_grad():
            output = model(feature_values)
            prediction = (output > 0.5).float().item()
            if prediction == 1.0:
                print("Attack detected!")
            else:
                print("No attack detected.")
                
            print("Prediction details:")
            print(f"Duration: {features['dur']}")
            print(f"Protocol: {proto_encoder.inverse_transform([features['proto']])[0]}")
            print(f"Source Packets: {features['spkts']}")
            print(f"Destination Packets: {features['dpkts']}")
            print(f"Source Bytes: {features['sbytes']}")
            print(f"Destination Bytes: {features['dbytes']}")
            print(f"Rate: {features['rate']}")
            print(f"Source TTL: {features['sttl']}")
            print(f"Destination TTL: {features['dttl']}")
            print(f"Source Mean Bytes: {features['smean']}")
            print(f"Destination Mean Bytes: {features['dmean']}")
            print(f"Service: {service_encoder.inverse_transform([features['service']])[0]}")
            print(f"State: {state_encoder.inverse_transform([features['state']])[0]}")

# Real-time packet capture
extractor = PacketFeatureExtractor()
sniff(prn=extractor.process_packet, count=0)
       

