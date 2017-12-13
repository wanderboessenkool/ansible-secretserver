#!/usr/bin/env python
# Copyright (c) 2017 Wander Boessenkool (HCS Company)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: secretserver
short_description: Grab secrets from Thycotic Secret Server
description: This module can fetch secrets from Thycotic Secret Server using HTTPS
author: Wander Boessenkool (@wanderboessenkool)
options:
  uri:
    required: true
    default: null
    description:
      - The full URL to the base of your Secret Server, e.g.  https://<my-server.domain>/SecretServer/webservices/sswebservice.asmx/"

  username:
    required: true
    default: null
    description:
      - The username you wish to use when connecting to Secret Server

  password:
    required: true
    default: null
    description:
      - The password to use when connecting to your secret server

  organziation:
    required: false
    default: ""
    description:
      - The organization ID to sue when authenticating, typically not set

  domain:
    required: false
    default: ""
    description:
      - The authentication domain to use when connecting to Secret Server

  secretid:
    required: true
    default: null
    description:
      - The ID of the secret you want to retrieve, can be found in the URL when viewing a secret in a web browser.

'''

EXAMPLES = '''
- name: Retrieve the secret 513
  secretserver:
    uri:  https://secret.exampl.com/SecretServer/webservices/sswebservice.asmx/
    username: SoloH
    password: IheartWookies
    domain: mfalcon
    secretid: 513
  register: mysecret
'''

RETURN = '''
secret:
  description: The requested secret
  returned: success
  type: dict
  sample: |
    {
      "Items": {
        "Notes": {
          "FieldDisplayName": "Notes",
          "FieldId": "154",
          "FieldName": "Notes",
          "Id": "71596",
          "IsFile": "false",
          "IsNotes": "true",
          "IsPassword": "false",
          "SecretItem": "",
          "Value": null
        },
        "Username": {
          "FieldDisplayName": "Username",
          "FieldId": "152",
          "FieldName": "Username",
          "Id": "71594",
          "IsFile": "false",
          "IsNotes": "false",
          "IsPassword": "false",
          "SecretItem": "",
          "Value": "hallo"
        },
          "Wachtwoord": {
          "FieldDisplayName": "Wachtwoord",
          "FieldId": "153",
          "FieldName": "Wachtwoord",
          "Id": "71595",
          "IsFile": "false",
          "IsNotes": "false",
          "IsPassword": "true",
          "SecretItem": "",
          "Value": "doei"
        }
      },
      "name": "test"
    }
'''



from ansible.module_utils.basic import *
from lxml import etree
import requests

fields = {
  "uri": {"required": True, "type": "str"},
  "username": {"required": True, "type": "str"},
  "password": {"required": True, "type": "str", "no_log": True},
  "organization": {"required": False, "type": "str", "default": ""},
  "domain": {"required": False, "type": "str", "default": ""},
  "secretid": {"required": True, "type": "str"}
}

namespaces = { "x": "urn:thesecretserver.com" }

def parseXML(document):
  utf8_parser = etree.XMLParser(encoding='utf-8')
  doc = etree.fromstring(document.encode('utf-8'), parser=utf8_parser)
  return doc
  

def getAuthToken(params):
  payload = { "username": params['username'], "password": params['password'],
              "organization": params['organization'], "domain": params['domain'] }
  try:
    r = requests.post(params['uri']+"Authenticate", data=payload, verify=False)
  except Exception,e:
    return False, "Error opening URL"+str(e)
  if not r.ok:
    return False, r.reason
  doc = parseXML(r.text)
  token = doc.xpath('//x:Token', namespaces=namespaces)[0].text
  if token:
    return True, token
  else:
    return False, doc.xpath('//x:Errors/x:string', namespaces=namespaces)[0].text

def getSecret(params, authtoken):
  results = {
    "changed": False,
    "failed": False,
    "secret": {}
  }
  payload = { 'secretid': params['secretid'],
              'token': authtoken }
  try:
    r = requests.post(params['uri']+'GetSecretLegacy', data=payload, verify=False)
  except:
    results['failed'] = True
    return result
  if not r.ok:
    results['failed'] = True
    return results
  doc = parseXML(r.text)
  results['secres'] = {}
  results['secret']['name'] = doc.xpath('//x:Secret/x:Name', namespaces=namespaces)[0].text
  results['secret']['Items'] = {}
  for field in doc.xpath('.//x:SecretItem', namespaces=namespaces):
    itemname = field.xpath('.//x:FieldName', namespaces=namespaces)[0].text
    results['secret']['Items'][itemname] = {}
    for element in field.iter():
      mytag = element.tag.split('}')[-1]
      results['secret']['Items'][itemname][mytag] = element.text
  # results['msg'] = r.text
  return results

def main():
  module = AnsibleModule(argument_spec=fields)
  success, msg = getAuthToken(module.params)
  results = {
    "changed": False,
    "failed": False
  }
  if success:
    results = getSecret(module.params, msg) 
    module.exit_json(**results)
  else:
    results['failed'] = True
    results['message'] = msg
    module.exit_json(**results)

if __name__ == '__main__':
    main()
