#!/usr/bin/env python3

import sys,os,getopt
import traceback
import os
import fcntl
import json
import requests
import time
import re
import boto3
import gzip
import datetime

from six import PY2

if PY2:
    get_unicode_string = unicode
else:
    get_unicode_string = str

sys.path.insert(0, './ds-integration')
from DefenseStorm import DefenseStorm

from html.parser import HTMLParser

class integration(object):


    JSON_field_mappings = {
        'aid' : 'device_id',
        'aip' : 'external_ip',
        'ContextProcessId' : 'process_id',
        'ContextThreadId' : 'thread_id',
        'event_platform' : 'os_type',
        'ComputerName' : 'client_hostname',
        'event_simpleName' : 'category',
        'FileName' : 'file_name',
        'FilePath' : 'file_path',
    }

    def get_S3_files(self, sqs_msg):
        if not os.path.isdir('datadir'):
            os.mkdir('datadir')
        if len(os.listdir('datadir')) > 1:
            self.ds.log('ERROR', "datadir/ is not empty.  A previous run might have failed.  Exiting")
            return None

        my_bucket = self.s3.Bucket(sqs_msg['bucket'])
        obj_list = my_bucket.objects.filter(Prefix = sqs_msg['pathPrefix'])
        Found = False
        file_list = []
        for b_obj in obj_list:
            file_list.append(b_obj.key)
            if '_SUCCESS' in b_obj.key:
                Found = True
        if not Found:
            return None
        self.ds.log('INFO', "Downloading files: %s" %(str(file_list)))
        downloaded_files = []
        for filename in file_list:
            if '_SUCCESS' in filename:
                continue
            my_bucket.download_file(filename, 'datadir/' + filename.replace('/','_'))
            downloaded_files.append(filename.replace('/','_'))
        return downloaded_files


    def get_SQS_message(self):
        try:
            response = self.sqs.receive_message(
                QueueUrl=self.sqs_url,
                AttributeNames=[
                    'SentTimestamp'
                ],
                MaxNumberOfMessages=1,
                MessageAttributeNames=[
                    'All'
                ],
                VisibilityTimeout=0,
                WaitTimeSeconds=0
                )
        except Exception as e:
            traceback.print_exc()
            self.ds.log('ERROR', "Exception {0}".format(str(e)))
            return None, None, None

        notification_time = response
        if 'Messages' not in response.keys():
            self.ds.log('INFO', "No more SQS Notifications to handle")
            return None, None, None

        msg_count = len(response['Messages'])
        if msg_count < 1:
            self.ds.log('INFO', "No SQS Notifications to handle")
            return None, None, None
        if msg_count > 1:
            self.ds.log('ERROR', "Should never get more than one message from SQS")
            return None, None, None
        message = response['Messages'][0]
        msg_body = json.loads(message['Body'])
        return message['ReceiptHandle'], message['MessageId'], msg_body

    def handle_local_files(self, local_files):
        for thisfile in local_files:
            self.ds.log('INFO', "Processing file %s" %(thisfile))
            f_name = 'datadir/' + thisfile
            if 'managedassets' in thisfile:
                category = 'managedassets'
            elif 'aid_master' in thisfile:
                category = 'aid_master'
            elif 'notmanaged' in thisfile:
                category = 'notmanaged'
            else:
                category = None
            try:
                with gzip.open(f_name) as f:
                    for line in f:
                        event = json.loads(str(line, 'utf-8'))
                        if category != None:
                            event['category'] = category
                            event['message'] = category + ' event'
                        elif 'ComputerName' in event.keys():

                            event['message'] = event['ComputerName'] + ' - ' + event['event_simpleName']
                        else:
                            event['message'] = event['event_simpleName']
                        if 'ContextTimeStamp' in event.keys():
                            event['receive_time'] = event['timestamp']
                            event['timestamp'] = event['ContextTimeStamp']
                            del event['ContextTimeStamp']
                        self.ds.writeJSONEvent(event, JSON_field_mappings = self.JSON_field_mappings)
            except Exception as e:
                self.ds.log('ERROR', "Error handling file %s: %s" %(f_name, e))
                return False
            os.remove(f_name)
        return True

    def delete_SQS_message(self, sqs_rh):
        self.ds.log('INFO', "Deleting SQS Notification: %s" %(sqs_rh))
        try:
            self.sqs.delete_message(QueueUrl = self.sqs_url, ReceiptHandle = sqs_rh)
        except Exception as e:
            self.ds.log('ERROR', "Failed to delete SQS Notification: %s - %s" %(sqs_rh, e))
            return False
        return True

    def cs_main(self): 

        self.s3_key = self.ds.config_get('crowdstrike', 's3_key')
        self.s3_secret = self.ds.config_get('crowdstrike', 's3_secret')
        self.sqs_url = self.ds.config_get('crowdstrike', 'sqs_url')
        self.s3_idenfifier = self.ds.config_get('crowdstrike', 's3_identifier')
        self.history = self.ds.config_get('crowdstrike', 'history')

        try:
            self.sqs = boto3.client('sqs', region_name='us-west-1', aws_access_key_id=self.s3_key, aws_secret_access_key=self.s3_secret)
            self.s3 = boto3.resource('s3', aws_access_key_id=self.s3_key, aws_secret_access_key=self.s3_secret)
        except Exception as e:
            traceback.print_exc()
            self.ds.log('ERROR', "Exception {0}".format(str(e)))
            return

        sqs_rh, msg_id, sqs_msg = self.get_SQS_message()

        while sqs_rh != None:
            self.ds.log('INFO', "Processing Notification: %s" %(msg_id))
            notification_time = int(sqs_msg['timestamp']) / 1000
            current_epoch = time.time()
            self.ds.log('INFO', "Notification: %s, Timestamp %s" %(msg_id, datetime.datetime.utcfromtimestamp(int(sqs_msg['timestamp']/1000)).isoformat() + 'Z'))
            if (current_epoch - notification_time) > (int(self.history) * 60 * 60):
                self.ds.log('INFO', "Message %s older than %s hours, deleting from SQS." %(msg_id, self.history))
                if not self.delete_SQS_message(sqs_rh):
                    self.ds.log('ERROR', "Deleting SQS Notification - %s" %(sqs_rh))
                    return
            else:
                self.ds.log('INFO', "Downloading files for notification: %s" %(msg_id))
                local_files = self.get_S3_files(sqs_msg)
                if local_files == None:
                    self.ds.log('ERROR', "Error getting local files. Ending Run.")
                    return
                if not self.handle_local_files(local_files):
                    self.ds.log('ERROR', "Error handling downloaded files. Exiting.")
                    return
                if not self.delete_SQS_message(sqs_rh):
                    self.ds.log('ERROR', "Deleting SQS Notification - %s" %(sqs_rh))
                    return
            sqs_rh, msg_id, sqs_msg = self.get_SQS_message()
        

    def run(self):
        try:
            pid_file = self.ds.config_get('crowdstrike', 'pid_file')
            fp = open(pid_file, 'w')
            try:
                fcntl.lockf(fp, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except IOError:
                self.ds.log('ERROR', "An instance of cb defense syslog connector is already running")
                # another instance is running
                sys.exit(0)
            self.cs_main()
        except Exception as e:
            traceback.print_exc()
            self.ds.log('ERROR', "Exception {0}".format(str(e)))
            return
    
    def usage(self):
        print
        print(os.path.basename(__file__))
        print
        print('  No Options: Run a normal cycle')
        print
        print('  -t    Testing mode.  Do all the work but do not send events to GRID via ')
        print('        syslog Local7.  Instead write the events to file \'output.TIMESTAMP\'')
        print('        in the current directory')
        print
        print('  -l    Log to stdout instead of syslog Local6')
        print
    
    def __init__(self, argv):

        self.testing = False
        self.send_syslog = True
        self.ds = None
    
        try:
            opts, args = getopt.getopt(argv,"htnld:",["datedir="])
        except getopt.GetoptError:
            self.usage()
            sys.exit(2)
        for opt, arg in opts:
            if opt == '-h':
                self.usage()
                sys.exit()
            elif opt in ("-t"):
                self.testing = True
            elif opt in ("-l"):
                self.send_syslog = False
    
        try:
            self.ds = DefenseStorm('crowdstrikeFDREventLogs', testing=self.testing, send_syslog = self.send_syslog)
        except Exception as e:
            traceback.print_exc()
            try:
                self.ds.log('ERROR', 'ERROR: ' + str(e))
            except:
                pass


if __name__ == "__main__":
    i = integration(sys.argv[1:]) 
    i.run()
