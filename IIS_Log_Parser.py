# Copyright (C) 2015  JeredFromCMLP

# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation; either version 2 of the License, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.

# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

import os
import ast
import sys
import json
import urllib
import hashlib
from pytz import timezone
from datetime import datetime
from elasticsearch import Elasticsearch

pointers = []
# Define your Elasticsearch server IP
es = Elasticsearch(hosts=[{'host': 'YOUR_ELASTICSEARCH_SERVER_IP', 'port': '9200'}])

# Define the path(s) list to your log files (e.g: C:\inetpub\logs\LogFiles\W3SVC1)
paths = ['PATH1', 'PATH2']
uas_exception = ['JAX-WS RI 2.2.6b02  svn-revision#12583']


def read_log(log_file, offset=0):
    try:
        with open(log_file, 'r') as f:
            counter = 0
            pointer = {}
            pointer['file'] = log_file
            if offset != 0:
                # print offset
                f.seek(offset)
                pointer['offset'] = offset
            print 'Indexing %s ...' % log_file,
            with open('uas.dat') as uas_file:
                uas = json.load(uas_file)
            for line in f:
                pointer['offset'] = f.tell()
                datas = {}
                if '#' in line[0]:
                    continue
                else:
                    data = line.split(' ')
                    datas['hash_id'] = hashlib.sha224(line).hexdigest()
                    datas['timestamp'] = datetime.now()
                    datas['eventtime'] = data[0] + " " + data[1]
                    datas['sitename'] = data[2]
                    datas['computername'] = data[3]
                    datas['server_ip'] = data[4]
                    datas['method'] = data[5]
                    datas['URI'] = data[6]
                    datas['query'] = data[7]
                    datas['port'] = data[8]
                    datas['username'] = data[9]
                    datas['client_ip'] = data[10]
                    datas['protocol_version'] = data[11]
                    datas['user_agent'] = data[12]
                    datas['cookie'] = data[13]
                    datas['referer'] = data[14]
                    datas['host'] = data[15]
                    datas['status'] = data[16]
                    datas['substatus'] = data[17]
                    datas['win32_status'] = data[18]
                    datas['tx_bytes'] = int(data[19])
                    datas['rx_bytes'] = int(data[20])
                    datas['time_taken'] = int(data[21])
                    datas['@timestamp'] = datetime.strptime(datetime.strptime(datas['eventtime'], '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone('UTC')).strftime('%Y-%m-%d %H:%M:%S.%f'), '%Y-%m-%d %H:%M:%S.%f')
                    info_client = get_user_agent(data[12], uas, uas_file)
                    if info_client is None:
                        datas['user_agent_name'] = 'Unknown'
                        datas['os_name'] = 'Unknown'
                    else:
                        datas['user_agent_name'] = info_client[0]
                        datas['os_name'] = info_client[1]
                    index_data(datas)
            pointers.append(pointer)
            print "Ok !"
    except Exception as e:
        print 'Error:', e
        print 'Counter:', counter


def index_data(datas):
    es.index(index="iis_logs", doc_type="logs", id=datas['hash_id'], body=datas)


def save_uas(uas, uaf):
    with open('uas.dat', 'w') as uas_file:
        json.dump(uas, uas_file)
    with open('uas.dat') as uas_file:
        uas = json.load(uas_file)
    return uas


def create_new_ua(ua_string, uas, uas_file):
    new_ua = {}
    get_uas = urllib.urlopen('http://www.useragentstring.com/?uas=' + ua_string.replace('+', ' ') + '&getJSON=all')
    new_ua['uas'] = ua_string
    new_ua['User_Agent'] = get_uas.read()
    uas.append(new_ua)
    uan = ast.literal_eval(new_ua['User_Agent'])
    save_uas(uas, uas_file)
    if uan['os_name'] is None:
        uan['os_name'] = "Unknown"
    elif uan['agent_name'] is None:
        uan['agent_name'] = 'Unknown'
    elif uan['agent_version'] is None:
        uan['agent_version'] = ''
    return [uan['agent_name'].replace(' ', '_') + '_' + uan['agent_version'].replace(' ', '_'), uan['os_name'].replace(' ', '_')]


def get_user_agent(ua_string, uas, uas_file):
    ua_string = ua_string.replace('+', ' ')
    try:
        if len(uas) != 0:
            flag = False
            for ua in uas:
                if ua_string in ua['uas']:
                    flag = True
            if flag:
                for ua in uas:
                    if ua_string in ua['uas']:
                        uan = ast.literal_eval(ua['User_Agent'])
                        if uan['os_name'] is None or uan['agent_name'] is None:
                            uan['os_name'] = "Unknown"
                        elif uan['agent_name'] is None:
                            uan['agent_name'] = 'Unknown'
                        elif uan['agent_version'] is None:
                            uan['agent_version'] = ''
                        return [uan['agent_name'].replace(' ', '_') + '_' + uan['agent_version'].replace(' ', '_'), uan['os_name'].replace(' ', '_')]
            elif ua_string in uas_exception:
                return 'Unknown', 'Unknown'
            else:
                new_ua = {}
                get_uas = urllib.urlopen('http://www.useragentstring.com/?uas=' + ua_string + '&getJSON=all')
                new_ua['uas'] = ua_string
                new_ua['User_Agent'] = get_uas.read()
                uas.append(new_ua)
                uan = ast.literal_eval(new_ua['User_Agent'])
                uas = save_uas(uas, uas_file)
                if uan['os_name'] is None:
                    uan['os_name'] = "Unknown"
                elif uan['agent_name'] is None:
                    uan['agent_name'] = 'Unknown'
                elif uan['agent_version'] is None:
                    uan['agent_version'] = ''
                return [uan['agent_name'].replace(' ', '_') + '_' + uan['agent_version'].replace(' ', '_'), uan['os_name'].replace(' ', '_')]
        else:
            print ua_string
            new_ua = {}
            get_uas = urllib.urlopen('http://www.useragentstring.com/?uas=' + ua_string + '&getJSON=all')
            new_ua['uas'] = ua_string
            new_ua['User_Agent'] = get_uas.read()
            uas.append(new_ua)
            uan = ast.literal_eval(new_ua['User_Agent'])
            uas = save_uas(uas, uas_file)
            if uan['os_name'] is None:
                uan['os_name'] = "Unknown"
            elif uan['agent_name'] is None:
                uan['agent_name'] = 'Unknown'
            elif uan['agent_version'] is None:
                uan['agent_version'] = ''
            return [uan['agent_name'].replace(' ', '_') + '_' + uan['agent_version'].replace(' ', '_'), uan['os_name'].replace(' ', '_')]
    except Exception as e:
        print 'Error:', e
        sys.exit()


def main():
    if os.path.isfile('offsets.dat'):
        with open('offsets.dat') as o:
            offsets_list = json.load(o)
        for offset in offsets_list:
            if os.path.isfile(offset['file']):
                read_log(offset['file'], offset['offset'])
                with open('offsets.dat', 'w') as o:
                    json.dump(pointers, o)
    for path in paths:
        for files in os.listdir(path):
            file_flag = False
            if os.path.join(path, files) not in [offset['file'] for offset in offsets_list] and files.endswith('.log'):
                file_flag = True
            if file_flag:
                log_file = os.path.join(path, files)
                read_log(log_file)
                with open('offsets.dat', 'w') as o:
                    json.dump(pointers, o)


if __name__ == '__main__':
    main()
