import pyshark
import requests
import os
import json
import pandas as pd


# get_basic_packet_parameters tests
def get_basic_packet_parameters(pkt):
    packet_number = pkt.number
    highest_layer = pkt.highest_layer
    src_ip = pkt.ip.src
    dst_ip = pkt.ip.dst
    src_port = pkt.tcp.srcport
    dst_port = pkt.tcp.dstport
    return packet_number, highest_layer, src_ip, dst_ip, src_port, dst_port


def test_get_basic_packet_parameters_with_bad_pcap_file(bad_pacp_file='bad.pcap'):
    bad_pacp_file = pyshark.FileCapture(bad_pacp_file)
    for pkt in bad_pacp_file:
        result = get_basic_packet_parameters(pkt)


def test_get_basic_packet_parameters_with_goodpcap_file(good_pacp_file='good.pcap'):
    good_pacp_file = pyshark.FileCapture(good_pacp_file)
    for pkt in good_pacp_file:
        result = get_basic_packet_parameters(pkt)


# api_request_to_virus_total tests
def api_request_to_virus_total(website_url):
    if website_url == '':
        raise Exception
    headers = {
        "Accept-Encoding": "gzip, deflate",
        "User-Agent": "gzip,  My Python requests library example client or username"
    }
    params = {'apikey': '3b8871665936a18f433ae5eee608148a4ed00ca69b9925cc22ab3ab414efa3c1',
              'resource': website_url}
    response = requests.post("https://www.virustotal.com/vtapi/v2/url/report",
                             params=params, headers=headers)


def test_api_request_to_virus_total_with_no_url(empty_url=''):
    api_request_to_virus_total(empty_url)


def test_api_request_to_virus_total_with_good_url(good_url='google.com'):
    api_request_to_virus_total(good_url)


# parsing_api_scan_results tests
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
    scan_results = scan_results.rstrip(' ,')
    return scan_results


def test_parsing_api_scan_results_with_bad_response_as_parameter(bad_response=1):
    result = parsing_api_scan_results(bad_response)
    assert result


def test_parsing_api_scan_results_with_good_response_as_parameter(good_response=''):
    headers = {
        "Accept-Encoding": "gzip, deflate",
        "User-Agent": "gzip,  My Python requests library example client or username"
    }
    params = {'apikey': '3b8871665936a18f433ae5eee608148a4ed00ca69b9925cc22ab3ab414efa3c1',
              'resource': 'google.com'}
    good_response = requests.post("https://www.virustotal.com/vtapi/v2/url/report",
                                  params=params, headers=headers)
    result = parsing_api_scan_results(good_response)
    assert result


# dump_output_to_json tests
def dump_output_to_json(output, pcap_file):
    pcap_file_name = os.path.splitext(pcap_file)[0]
    with open(pcap_file_name + '.json', "a") as json_file:
        json_file.write("{}\n".format(json.dumps(output, indent=5)))


def test_dump_output_to_json_with_bad_output(bad_output=pd.DataFrame, pcap_file='good.pcap'):
    dump_output_to_json(bad_output, pcap_file)


def test_dump_output_to_json_with_good_output(good_output=[], pcap_file='good.pcap'):
    good_output = [{'Packet number': '1',
                    'Protocol': 'TCP',
                    'Source ip': '10.60.6.154',
                    'Destination ip': '1.2.3.4',
                    'Source port': '20',
                    'Destination port': '123'}]
    dump_output_to_json(good_output, pcap_file)


# main tests, check if the given file has .pcap extension
def main(pcap_file):
    cap = pyshark.FileCapture(pcap_file)


def test_main_with_bad_pcap_file(bad_file='bad.pcapa'):
    pcap_file_extension = os.path.splitext(bad_file)[1]
    assert pcap_file_extension == '.pcap'


def test_main_with_good_pcap_file(good_file='good.pcap'):
    pcap_file_extension = os.path.splitext(good_file)[1]
    assert pcap_file_extension == '.pcap'
