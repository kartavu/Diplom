#!/usr/bin/python
from prettytable import PrettyTable
import subprocess
import sys
import signal
import os
import numpy as np
import pickle

cmd = "ryu-manager Diplom/simple_monitor_AK.py"
flows = {}
TIMEOUT = 15 * 60  # 15 минут

class Flow:
    def __init__(self, time_start, datapath, inport, ethsrc, ethdst, outport, packets, bytes, traffic_type=None):
        self.time_start = time_start
        self.datapath = datapath
        self.inport = inport
        self.ethsrc = ethsrc
        self.ethdst = ethdst
        self.outport = outport
        self.traffic_type = traffic_type

        self.forward_packets = packets
        self.forward_bytes = bytes
        self.forward_delta_packets = 0
        self.forward_delta_bytes = 0
        self.forward_inst_pps = 0.00
        self.forward_avg_pps = 0.00
        self.forward_inst_bps = 0.00
        self.forward_avg_bps = 0.00
        self.forward_status = 'ACTIVE'
        self.forward_last_time = time_start

        self.reverse_packets = 0
        self.reverse_bytes = 0
        self.reverse_delta_packets = 0
        self.reverse_delta_bytes = 0
        self.reverse_inst_pps = 0.00
        self.reverse_avg_pps = 0.00
        self.reverse_inst_bps = 0.00
        self.reverse_avg_bps = 0.00
        self.reverse_status = 'INACTIVE'
        self.reverse_last_time = time_start

    def updateforward(self, packets, bytes, curr_time):
        self.forward_delta_packets = packets - self.forward_packets
        self.forward_packets = packets
        if curr_time != self.time_start:
            self.forward_avg_pps = packets / float(curr_time - self.time_start)
        if curr_time != self.forward_last_time:
            self.forward_inst_pps = self.forward_delta_packets / float(curr_time - self.forward_last_time)

        self.forward_delta_bytes = bytes - self.forward_bytes
        self.forward_bytes = bytes
        if curr_time != self.time_start:
            self.forward_avg_bps = bytes / float(curr_time - self.time_start)
        if curr_time != self.forward_last_time:
            self.forward_inst_bps = self.forward_delta_bytes / float(curr_time - self.forward_last_time)
        self.forward_last_time = curr_time

        self.forward_status = 'ACTIVE' if (self.forward_delta_bytes != 0 and self.forward_delta_packets != 0) else 'INACTIVE'

    def updatereverse(self, packets, bytes, curr_time):
        self.reverse_delta_packets = packets - self.reverse_packets
        self.reverse_packets = packets
        if curr_time != self.time_start:
            self.reverse_avg_pps = packets / float(curr_time - self.time_start)
        if curr_time != self.reverse_last_time:
            self.reverse_inst_pps = self.reverse_delta_packets / float(curr_time - self.reverse_last_time)

        self.reverse_delta_bytes = bytes - self.reverse_bytes
        self.reverse_bytes = bytes
        if curr_time != self.time_start:
            self.reverse_avg_bps = bytes / float(curr_time - self.time_start)
        if curr_time != self.reverse_last_time:
            self.reverse_inst_bps = self.reverse_delta_bytes / float(curr_time - self.reverse_last_time)
        self.reverse_last_time = curr_time

        self.reverse_status = 'ACTIVE' if (self.reverse_delta_bytes != 0 and self.reverse_delta_packets != 0) else 'INACTIVE'

def printclassifier(model, save_to_file=None):
    table_console = PrettyTable()
    table_console.field_names = ["Flow ID", "Src MAC", "Dest MAC", "Traffic Type", "Forward Status", "Reverse Status"]

    table_full = PrettyTable()
    table_full.field_names = [
        "Flow ID", "Src MAC", "Dest MAC", "Traffic Type",
        "Fwd Packets", "Fwd Bytes", "Fwd Delta Pkts", "Fwd Delta Bytes",
        "Fwd Inst PPS", "Fwd Avg PPS", "Fwd Inst BPS", "Fwd Avg BPS", "Fwd Status",
        "Rev Packets", "Rev Bytes", "Rev Delta Pkts", "Rev Delta Bytes",
        "Rev Inst PPS", "Rev Avg PPS", "Rev Inst BPS", "Rev Avg BPS", "Rev Status"
    ]

    for key, flow in flows.items():
        features = np.asarray([
            flow.forward_delta_packets, flow.forward_delta_bytes,
            flow.forward_inst_pps, flow.forward_avg_pps,
            flow.forward_inst_bps, flow.forward_avg_bps,
            flow.reverse_delta_packets, flow.reverse_delta_bytes,
            flow.reverse_inst_pps, flow.reverse_avg_pps,
            flow.reverse_inst_bps, flow.reverse_avg_bps
        ]).reshape(1, -1)

        label = model.predict(features.tolist())

        if label == 0:
            label = ['dns']
        elif label == 1:
            label = ['ping']
        elif label == 2:
            label = ['telnet']
        elif label == 3:
            label = ['voice']
        elif label == 4:
            label = ['arp']

        if flow.traffic_type is None or flow.traffic_type != 'ping':
            if flow.forward_status == "ACTIVE" or flow.reverse_status == "ACTIVE":
                flow.traffic_type = label[0]
            elif flow.traffic_type is None:
                flow.traffic_type = label[0]

        table_console.add_row([abs(key), flow.ethsrc, flow.ethdst, flow.traffic_type, flow.forward_status, flow.reverse_status])

        table_full.add_row([
            abs(key), flow.ethsrc, flow.ethdst, flow.traffic_type,
            flow.forward_packets, flow.forward_bytes,
            flow.forward_delta_packets, flow.forward_delta_bytes,
            f"{flow.forward_inst_pps:.2f}", f"{flow.forward_avg_pps:.2f}",
            f"{flow.forward_inst_bps:.2f}", f"{flow.forward_avg_bps:.2f}", flow.forward_status,
            flow.reverse_packets, flow.reverse_bytes,
            flow.reverse_delta_packets, flow.reverse_delta_bytes,
            f"{flow.reverse_inst_pps:.2f}", f"{flow.reverse_avg_pps:.2f}",
            f"{flow.reverse_inst_bps:.2f}", f"{flow.reverse_avg_bps:.2f}", flow.reverse_status
        ])
    print(table_console)

    if save_to_file is not None:
        with open(save_to_file, 'w') as f:
            for key, flow in flows.items():
                f.write(f"Flow ID: {abs(key)}\n")
                f.write(f"Source MAC: {flow.ethsrc}\n")
                f.write(f"Destination MAC: {flow.ethdst}\n")
                f.write(f"Traffic Type: {flow.traffic_type}\n\n")

                f.write("Forward direction:\n")
                f.write(f"  Total Packets: {flow.forward_packets} (Change since last: {flow.forward_delta_packets})\n")
                f.write(f"  Total Bytes: {flow.forward_bytes} (Change since last: {flow.forward_delta_bytes})\n")
                f.write(f"  Instantaneous Packets Per Second: {flow.forward_inst_pps:.2f}\n")
                f.write(f"  Average Packets Per Second: {flow.forward_avg_pps:.2f}\n")
                f.write(f"  Instantaneous Bits Per Second: {flow.forward_inst_bps:.2f}\n")
                f.write(f"  Average Bits Per Second: {flow.forward_avg_bps:.2f}\n")
                f.write(f"  Status: {flow.forward_status}\n\n")

                f.write("Reverse direction:\n")
                f.write(f"  Total Packets: {flow.reverse_packets} (Change since last: {flow.reverse_delta_packets})\n")
                f.write(f"  Total Bytes: {flow.reverse_bytes} (Change since last: {flow.reverse_delta_bytes})\n")
                f.write(f"  Instantaneous Packets Per Second: {flow.reverse_inst_pps:.2f}\n")
                f.write(f"  Average Packets Per Second: {flow.reverse_avg_pps:.2f}\n")
                f.write(f"  Instantaneous Bits Per Second: {flow.reverse_inst_bps:.2f}\n")
                f.write(f"  Average Bits Per Second: {flow.reverse_avg_bps:.2f}\n")
                f.write(f"  Status: {flow.reverse_status}\n")
                f.write("-" * 60 + "\n")

def run_ryu(p, model=None):
    time = 0
    while True:
        out = p.stdout.readline()
        if out == b'' and p.poll() is not None:
            break
        if out != b'' and out.startswith(b'data'):
            fields = out.split(b'\t')[1:]
            fields = [f.decode('utf-8', errors='ignore') for f in fields]

            unique_id = hash(''.join([fields[1], fields[3], fields[4]]))
            if unique_id in flows.keys():
                flows[unique_id].updateforward(int(fields[6]), int(fields[7]), int(fields[0]))
            else:
                rev_unique_id = hash(''.join([fields[1], fields[4], fields[3]]))
                if rev_unique_id in flows.keys():
                    flows[rev_unique_id].updatereverse(int(fields[6]), int(fields[7]), int(fields[0]))
                else:
                    flows[unique_id] = Flow(int(fields[0]), fields[1], fields[2], fields[3], fields[4], fields[5], int(fields[6]),
                                           int(fields[7]))
            if model is not None:
                if time % 10 == 0:
                    printclassifier(model, save_to_file='Diplom/results/output.txt')
        time += 1


def printHelp():
    print("Usage: sudo python traffic_classifier.py supervised")
    print("\tTo start a near real time traffic classification application using supervised ML, run: sudo python traffic_classifier.py supervised")
    return


if __name__ == '__main__':
    if len(sys.argv) != 2 or sys.argv[1] != 'supervised':
        printHelp()
        sys.exit()

    # Загрузка модели логистической регрессии
    model_path = 'Diplom/LogisticRegression'  # путь к файлу с моделью - поправь, если нужно
    try:
        with open(model_path, 'rb') as infile:
            model = pickle.load(infile)
    except Exception as e:
        print(f"Error loading model from {model_path}: {e}")
        sys.exit(1)

    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, preexec_fn=os.setsid)

    try:
        run_ryu(p, model=model)
    except KeyboardInterrupt:
        print("Interrupted by user")
        os.killpg(os.getpgid(p.pid), signal.SIGTERM)
    except Exception as e:
        print(f"Error: {e}")
        os.killpg(os.getpgid(p.pid), signal.SIGTERM)

    sys.exit()
