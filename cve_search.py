#!/usr/bin/env python

import helper as Helper
import json
import os
import requests
import sys

JSON_URL = 'https://olbat.github.io/nvdcve/'

def get_vendor_advisory_by_cve(cve):
    for reference in cve['cve']['references']['reference_data']:
        if 'Vendor Advisory' in reference['tags']:
            return reference['url']


def get_cve_obj(cve_id):
    cve = get_cve_by_id(cve_id)
    cve_obj = {}
    cve_obj['id'] = {'label': 'CVE-ID', 'text': cve_id}
    cve_obj['summary'] = {
            'label': 'Summary',
            'text': cve['cve']['description']['description_data'][0]['value']}
    cve_obj['cwe'] = {'label': 'CWE-ID',
                      'text': get_cwe_by_cve(cve)}
    #cve_obj['link'] = {'label': 'link',
    #                  'text': get_cve_link_by_cve_id(cve_id)}
    
    severity = get_severity_by_cve(cve)
    formatted_severity = Helper.get_colorbox_for_cvss(severity[0], severity[1])
    
    cve_obj['severity'] = {'label': 'CVSS 3.x Severity',
                           'text': formatted_severity}
    cve_obj['advisory'] = {'label': 'Vendor advisory',
                           'text': get_vendor_advisory_by_cve(cve)}
    return cve_obj

def get_cve_link_by_cve_id(cve_id):
    return "https://nvd.nist.gov/vuln/detail/{}".format(cve_id)

def get_severity_by_cve(cve):
    base_score = cve['impact']['baseMetricV3']['cvssV3']['baseScore']
    base_severity = cve['impact']['baseMetricV3']['cvssV3']['baseSeverity']
    return [base_score, base_severity]

def get_cwe_by_cve(cve):
    for problem in cve['cve']['problemtype']['problemtype_data']:
        return(problem['description'][0]['value'])

def get_cve_by_id(cve_id):
    url = "{}{}.json".format(JSON_URL, 'CVE-2018-0442')
    r = requests.get(url)
    return r.json()

def verify_cve_format(cve_id):
    pass
