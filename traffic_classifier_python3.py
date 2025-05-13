from prettytable import PrettyTable 
import subprocess, sys 
import signal 
import os
import numpy as np 
import pickle 

cmd = "ryu-manager Diplom/simple_monitor_AK.py"
flows = {}
TIMEOUT = 15 * 60 

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
        
        if self.forward_delta_bytes == 0 or self.forward_delta_packets == 0:
            self.forward_status = 'INACTIVE'
        else:
            self.forward_status = 'ACTIVE'

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

        if self.reverse_delta_bytes == 0 or self.reverse_delta_packets == 0: 
            self.reverse_status = 'INACTIVE'
        else:
            self.reverse_status = 'ACTIVE'

def printclassifier(model):
    x = PrettyTable()
    x.field_names = ["Flow ID", "Src MAC", "Dest MAC", "Traffic Type", "Forward Status", "Reverse Status"]

    for key, flow in flows.items():
        features = np.asarray([flow.forward_delta_packets, flow.forward_delta_bytes, flow.forward_inst_pps, flow.forward_avg_pps, flow.forward_inst_bps, 
                               flow.forward_avg_bps, flow.reverse_delta_packets, flow.reverse_delta_bytes, flow.reverse_inst_pps, 
                               flow.reverse_avg_pps, flow.reverse_inst_bps, flow.reverse_avg_bps]).reshape(1, -1) 

        label = model.predict(features.tolist())  

        if label == 0: label = ['dns']
        elif label == 1: label = ['ping']
        elif label == 2: label = ['telnet']
        elif label == 3: label = ['voice']
        elif label == 4: label = ['arp']

        if flow.traffic_type is None or flow.traffic_type != 'ping': 
            if flow.forward_status == "ACTIVE" or flow.reverse_status == "ACTIVE":
                flow.traffic_type = label[0]  
            elif flow.traffic_type is None:  
                flow.traffic_type = label[0]

        x.add_row([key, flow.ethsrc, flow.ethdst, flow.traffic_type, flow.forward_status, flow.reverse_status])

    print(x)

def printflows(traffic_type, f):
    for key, flow in flows.items():
        outstring = '\t'.join([
        str(flow.forward_packets),
        str(flow.forward_bytes),
        str(flow.forward_delta_packets),
        str(flow.forward_delta_bytes), 
        str(flow.forward_inst_pps), 
        str(flow.forward_avg_pps),
        str(flow.forward_inst_bps), 
        str(flow.forward_avg_bps), 
        str(flow.reverse_packets),
        str(flow.reverse_bytes),
        str(flow.reverse_delta_packets),
        str(flow.reverse_delta_bytes),
        str(flow.reverse_inst_pps),
        str(flow.reverse_avg_pps),
        str(flow.reverse_inst_bps),
        str(flow.reverse_avg_bps),
        str(traffic_type)])
        f.write(outstring + '\n')

def run_ryu(p, traffic_type=None, f=None, model=None):
    time = 0
    while True:
        out = p.stdout.readline()
        if out == '' and p.poll() is not None:
            break
        if out != '' and out.startswith(b'data'):
            fields = out.split(b'\t')[1:] 
            
            fields = [f.decode(encoding='utf-8', errors='strict') for f in fields] 
            
            unique_id = hash(''.join([fields[1], fields[3], fields[4]])) 
            if unique_id in flows.keys():
                flows[unique_id].updateforward(int(fields[6]), int(fields[7]), int(fields[0])) 
            else:
                rev_unique_id = hash(''.join([fields[1], fields[4], fields[3]]))
                if rev_unique_id in flows.keys():
                    flows[rev_unique_id].updatereverse(int(fields[6]), int(fields[7]), int(fields[0])) 
                else:
                    flows[unique_id] = Flow(int(fields[0]), fields[1], fields[2], fields[3], fields[4], fields[5], int(fields[6]), int(fields[7])) 
            if model is not None:
                if time % 10 == 0:
                    printclassifier(model)
            else:
                printflows(traffic_type, f) 
        time += 1

def printHelp():
    print("Usage: sudo python traffic_classifier.py [subcommand] [options]")
    print("\tTo start a near real time traffic classification application using supervised ML, run: sudo python traffic_classifier.py supervised")
    return

def alarm_handler(signum, frame):
    print("Finished collecting data.")
    raise Exception()

if __name__ == '__main__':
    SUBCOMMANDS = ('supervised')

    if len(sys.argv) < 2:
        print("ERROR: Incorrect # of args")
        print()
        printHelp()
        sys.exit()
    else:
        if len(sys.argv) == 2:
            if sys.argv[1] not in SUBCOMMANDS:
                print("ERROR: Unknown subcommand argument.")
                print("       Currently subaccepted commands are: %s" % str(SUBCOMMANDS).strip('()'))
                print()
                printHelp()
                sys.exit()

    if len(sys.argv) == 1:
        printHelp()
    elif len(sys.argv) >= 2:
        if sys.argv[1] == 'supervised':
            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) 
            try:
                infile = open('/Diplom/models/LogisticRegression', 'rb') 
                model = pickle.load(infile)
                infile.close()
            except FileNotFoundError:
                print("ERROR: LogisticRegression model file not found.")
                sys.exit(1)
            run_ryu(p, model=model)
    sys.exit()
