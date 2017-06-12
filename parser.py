import os
import json
import pyshark
import requests



def parser(pcap_file):
    # Opening the captured file path given by the user:

    pcap_file_name = os.path.splitext(pcap_file)[0]
    pcap_file_name_without_extension = os.path.basename(pcap_file_name)
    cap = pyshark.FileCapture(pcap_file)
    i = 1
    for pkt in cap:
        highest_layer = pkt.highest_layer
        src_ip = pkt.ip.src
        dst_ip = pkt.ip.dst
        src_port = pkt.tcp.srcport
        dst_port = pkt.tcp.dstport
        if highest_layer == 'HTTP':
            try:
                website_url = pkt.http.host
                headers = {
                    "Accept-Encoding": "gzip, deflate",
                    "User-Agent": "gzip,  My Python requests library example client or username"
                }
                params = {'apikey': '3b8871665936a18f433ae5eee608148a4ed00ca69b9925cc22ab3ab414efa3c1', 'resource': website_url}
                response = requests.post('https://www.virustotal.com/vtapi/v2/url/report',
                                         params=params, headers=headers)
                json_response = response.json()
                scan_results = ''

                # Checking in the json response from virustotal if a scan resulted in a malware/malicious result,
                # if so, the result is appended to the scan results variable

                for scan in json_response['scans']:
                    scan_result = json_response['scans'][scan]['result']
                    if scan_result != 'clean site' and scan_result != 'unrated site':
                        scan_results += scan + ' - ' + scan_result + ", "
                if scan_results == '':
                    scan_results = 'Clean site'
                scan_results = scan_results.rstrip(' ,')
                temp_dict = {
                    'Scan results': scan_results,
                    'Packet number': i,
                    'Protocol': highest_layer,
                    'Source ip': src_ip,
                    'Destination ip': dst_ip,
                    'Source port': src_port,
                    'Destination port': dst_port,
                    'Url': website_url
                }
            except:
                print "Oops, the HTTP packet was broken!"
        else:
            temp_dict = {
                'Packet number': i,
                'Protocol': highest_layer,
                'Source ip': src_ip,
                'Destination ip': dst_ip,
                'Source port': src_port,
                'Destination port': dst_port
            }

        with open(pcap_file_name_without_extension+'.json', "a") as json_file:
            json_file.write("{}\n".format(json.dumps(temp_dict, indent=5)))

        i += 1

parser('/home/director/tcpdump7.pcap')
