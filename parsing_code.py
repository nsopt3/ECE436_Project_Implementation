import pyshark
import pandas as pd


#captures .pcapng file, and doesnt save packets after use (since its a large capture)
capture = pyshark.FileCapture('Wireshark_Packet_Capture_23Mar2026.pcapng', keep_packets=False)


#assigns each packets its respective fields with each iteration
data = [];
for packet in capture:
    try:
        src_adrs = packet.ip.src if hasattr(packet, 'ip') else (packet.ipv6.src if hasattr(packet, 'ipv6') else None)
        src_port = packet[packet.transport_layer].srcport if packet.transport_layer else None

        
        dst_adrs = packet.ip.dst if hasattr(packet, 'ip') else (packet.ipv6.dst if hasattr(packet, 'ipv6') else None)
        dst_port = packet[packet.transport_layer].dstport if packet.transport_layer else None


        packet_fields = {
            'Pkt_Time': float(packet.sniff_timestamp),
            'Src_Address': src_adrs,
            'Src_Port': src_port,
            'Dst_Address': dst_adrs,
            'Dst_Port': dst_port,
            'Protocol': packet.highest_layer,
            'Length_(B)': int(packet.length),
        }
        data.append(packet_fields)
    except (AttributeError, KeyError, TypeError):
        continue


print(f'Number of Packets Parsed = {len(data)}')

#append packet info to a Pandas dataframe
pDat = pd.DataFrame(data)

#(Part 3) tried to calc inter arrival time, commented it out because it was giving me errors 
#pDat['Inter_Arrival_Time'] = pDat['Pkt_Time'].diff()


#converts dataframe to a csv file for part 3 (opens in excel)
pDat.to_csv('packet_info.csv', index = False)
