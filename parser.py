import os
import json
import pyshark
import requests
import time


def dump_output_to_json(output, pcap_file):
    pcap_file_name = os.path.splitext(pcap_file)[0]
    with open(pcap_file_name + '.json', "a") as json_file:
        json_file.write("{}\n".format(json.dumps(output, indent=5)))


def get_basic_packet_parameters(pkt):
    try:
        packet_number = pkt.number
        highest_layer = pkt.highest_layer
        src_ip = pkt.ip.src
        dst_ip = pkt.ip.dst
        src_port = pkt.tcp.srcport
        dst_port = pkt.tcp.dstport
        return packet_number, highest_layer, src_ip, dst_ip, src_port, dst_port

    except Exception as e:
        print("Broken Packet", e)
        return 0, 0, 0, 0, 0, 0


def api_request_to_virus_total(website_url, urls_scanned):
    if website_url == '':
        return 0
    if website_url in urls_scanned:
        return urls_scanned[website_url]
    try:
        status_code = 204
        while status_code == 204:
            headers = {
                "Accept-Encoding": "gzip, deflate",
                "User-Agent": "gzip,  My Python requests library example client or username"
            }
            params = {'apikey': '3b8871665936a18f433ae5eee608148a4ed00ca69b9925cc22ab3ab414efa3c1',
                      'resource': website_url}
            response = requests.post("https://www.virustotal.com/vtapi/v2/url/report",
                                     params=params, headers=headers)
            if response.status_code == 204:
                print("API's Limit Reached, waiting a few seconds")
                time.sleep(15)
            else:
                status_code = response.status_code
                urls_scanned[website_url] = response
        return response

    except Exception as e:
        print("Problem with the API request", e.__repr__())
        return 0


def parsing_api_scan_results(response):
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
        print('The site ' + json_response['resource'] + ' is clean ')
    scan_results = scan_results.rstrip(' ,')
    return scan_results


def main(pcap_file):
    # Opening the captured file path given by the user:
    cap = pyshark.FileCapture(pcap_file)
    output = []
    urls_scanned = {}
    for pkt in cap:
        packet_number, highest_layer, src_ip, dst_ip, src_port, dst_port = get_basic_packet_parameters(pkt)
        if highest_layer == 0:
            continue
        packet_data = {
            'Packet number': packet_number,
            'Protocol': highest_layer,
            'Source ip': src_ip,
            'Destination ip': dst_ip,
            'Source port': src_port,
            'Destination port': dst_port
        }
        if highest_layer == 'HTTP':
            try:
                website_url = pkt.http.host
            except Exception as e:
                print("Packet has no url")
                continue
            response = api_request_to_virus_total(website_url, urls_scanned)
            if response == 0:
                continue
            api_scan_results = parsing_api_scan_results(response)
            packet_data['Scan results'] = api_scan_results
            packet_data['Url'] = website_url
        output.append(packet_data)

    dump_output_to_json(output, pcap_file)


if __name__ == '__main__':
    main('MalwareTrafficPcap.pcap')
