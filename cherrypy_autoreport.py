#!/usr/bin/env python

import argparse
import datetime
import json
import os
import requests
import sqlite3
import subprocess
import sys
import uuid
import xml.etree.ElementTree as ET
import cve_search as CVE
import helper as Helper
from mdutils.mdutils import MdUtils


def connect():
    conn = sqlite3.connect(cherrytree)
    conn.row_factory = sqlite3.Row
    return conn.cursor()


def get_node_by_name(name):
    params = (name,)
    r = connect().execute('SELECT * FROM node WHERE name=?', params)
    return node_from_row(r.fetchone())


def get_codebox_in_node(node):
    params = (node['node_id'],)          
    codeboxes = connect().execute(
                '''SELECT n.name, c.offset, c.txt, n.txt FROM codebox c
                   INNER JOIN node n on n.node_id = c.node_id
                   WHERE n.node_id =?''', params)
    codebox_objects = []
    for codebox in codeboxes:
        codebox_obj = {'txt': codebox['txt'],
                       'offset': codebox['offset'],
                       'type': 'codebox'}
        codebox_objects.append(codebox_obj)
    return codebox_objects


def write_static_part(mdFile, path, argument_list=None):
    if argument_list: 
        text = Helper.get_static_block_from_file(path).format(*argument_list)
        mdFile.new_paragraph(text)
    else:
        mdFile.new_paragraph(Helper.get_static_block_from_file(path))
    return mdFile


def write_images_in_node(node):
    params = (node['node_id'],)
    images = connect().execute('''SELECT n.name, offset, png FROM image i
                                  INNER JOIN node n on n.node_id = i.node_id
                                  WHERE n.node_id =?''', params)
    index = 0
    image_objects = []
    for image in images:
        index += 1
        name = '{}-{}.png'.format(image['name'],(index))
        write_image_from_blob(image['png'], name)
        
        image_obj = {'name': name,
                     'offset': image['offset'],
                     'type': 'image'}
        image_objects.append(image_obj)
    return image_objects


def write_image_from_blob(blob, name='{}.png'.format(str(uuid.uuid4()))):
    with open('images/' + name, 'wb') as image:
        image.write(blob)


def node_from_row(row):
    node = {}
    node['name'] = row['name']
    
    #remove xml tags from row[txt']
    node['txt'] = row['txt']
    if row['txt'].startswith('<?xml version="1.0" ?>'):
        node['txt'] = ET.tostring(
                ET.fromstring(row['txt']), method='text').decode('utf-8')

    node['node_id'] = row['node_id']
    return node


def get_node_by_id(node_id):
    params = (node_id,)
    connect().execute('SELECT * FROM node WHERE node_id=?', params)
    result = connect().fetchone()
    return node_from_row(result)


def get_child_nodes(node):
    params = (node['node_id'],)
    result = connect().execute('''SELECT cn.name, cn.txt, cn.node_id FROM node n 
                          INNER JOIN children c ON c.father_id = n.node_id                         
                          INNER JOIN node cn ON cn.node_id = c.node_id
                          WHERE n.node_id =?
                          ORDER BY c.sequence''', params)
    children = []
    for row in result:
        children.append(node_from_row(row))
    return children


#recursively add all child nodes to parent_node
def populate_childs_of_node(parent_node):
    parent_node['children'] = []
    for node in get_child_nodes(parent_node):
        parent_node['children'].append(node)
        populate_childs_of_node(node)
    return parent_node


#recursively look in a node for a child node by 'name'
#return first match
def get_child_node_by_name(parent_node, name):
    for node in parent_node['children']:
        if node['name'] == name:
            return node
        elif len(node['children']):
            found = get_child_node_by_name(node, name)
            if found is not None:
                return found


def insert_page_break(mdFile):
    mdFile.new_line()
    mdFile.new_line('\\newpage')
    mdFile.new_line()
    return mdFile


def create_title_page(mdFile):

    #open the title.yml file and add variables from cherrytree personal node
    with open('report-sections/title.yml') as title:
        personal_node = get_node_by_name('Personal')
        personal = json.loads(personal_node['txt'])
        title_arguments = [personal['name'],
                           personal['exam_date'],
                           personal['osid'],
                           personal['email']]
        title = title.read()
        mdFile.new_paragraph(title.format(*title_arguments))

    mdFile.new_paragraph('\\newpage')
    mdFile.new_paragraph('\\tableofcontents')
    mdFile.new_paragraph('\\setcounter{tocdepth}{4}')
    mdFile.new_paragraph('\\setcounter{secnumdepth}{3}')
    mdFile.new_paragraph('\\newpage')
    return mdFile


def create_document(name):
    mdFile = MdUtils(file_name=name)
    return mdFile

def get_cve(cve_id):
    cve = CVE.get_cve_obj(cve_id)


def _add_rich_object_to_md(mdFile, rich_object):
    if rich_object['type'] == 'image':
        mdFile.new_line(mdFile.new_inline_image(
            text='',
            path='images/{}'.format(rich_object['name'])))
    if rich_object['type'] == 'codebox':
        mdFile.insert_code(rich_object['txt'])
    return mdFile

#get the contents of a rich node, with possible images and codeboxes
def rich_node_to_md(mdFile, node, label=None):
    text = node['txt']
    image_objects = write_images_in_node(node)
    codebox_objects = get_codebox_in_node(node) 
    
    #append the image and codebox lists and sort by offse
    rich_objects = image_objects + codebox_objects
    rich_objects = sorted(rich_objects, key=lambda k: k['offset']) 
   
    #TODO: put this in another method:
    #no rich objects are present, just add possible label and text
    if not len(rich_objects):
        #if a label is passed, avoid a new paragraph when writing text
        if label:
            mdFile.new_paragraph(label)
            mdFile.write(text)
        else: 
            mdFile.new_paragraph(text)
        return mdFile

    index = 0
    for rich_object in rich_objects:
        
        #for the label in the exploit/privesc overview page
        if label:
            mdFile.new_paragraph(label)
        
        offset = rich_object['offset'] 
        
        #is this the first rich object?
        if(index == 0):
            mdFile.new_paragraph(text[:offset])
            _add_rich_object_to_md(mdFile, rich_object) 
        #is this the last rich object?
        elif(index+1 == len(rich_objects)):
            prev_rich_object = rich_objects[index-1]
           
            '''account for newline characters, added by rich_object inserts, 
            by subtracting 'index' from 'offset'''
            mdFile.new_paragraph(text[prev_rich_object['offset']-index:offset-index])
            _add_rich_object_to_md(mdFile, rich_object)
            
            #add the remaining text
            mdFile.new_paragraph(text[offset-index:])
        #somehwere in between
        else:
            prev_rich_object = rich_objects[index-1]
            
            '''account for newline characters, added by rich_object inserts, 
            by subtracting 'index' from 'offset'''
            mdFile.new_paragraph(text[prev_rich_object['offset']-index:offset-index])
            _add_rich_object_to_md(mdFile, rich_object)
        index += 1

    return mdFile

#create an informational summary page for the exploit/privesc part of a machine
def create_summary(mdFile, node):
    cve_id_node = get_child_node_by_name(node, 'CVE-ID')

    #only do this if a cve id is supplied
    if cve_id_node:
        cve_id = cve_id_node['txt']
        cve_obj = CVE.get_cve_obj(cve_id)
        for key in cve_obj:
            cve_item = cve_obj[key]
            mdFile.new_paragraph('**{}**: {}'
                    .format(cve_item['label'],cve_item['text']))

    for summary_node in node['children']:
        if summary_node['name'] == 'CVE-ID':
            continue
        rich_node_to_md(mdFile, summary_node,
                "**{}**: ".format(summary_node['name']))

    insert_page_break(mdFile)
    return mdFile


def create_machine_titlepage(mdFile, overview_node): 
    #Summary
    ip = get_child_node_by_name(overview_node, 'Host IP')['txt']
    hostname = get_child_node_by_name(overview_node, 'Hostname')['txt']
    mdFile.new_header(level=1, title='System IP: {} ({})'.format(ip, hostname))
    mdFile.new_header(level=2, title='Summary')
    mdFile.new_paragraph(get_child_node_by_name(overview_node, 'High level summary')['txt'])
    insert_page_break(mdFile)
    return mdFile
    


def create_md_for_node(mdFile, node, level=2,
                       skip_parent=False, header_name=None, no_header=False):
   
    #some 'special' nodes should be skipped
    #TODO: do this better
    skip_node_names = ['Proof', 'Appendix']

    if node['name'] in skip_node_names:
        return mdFile
    
    if not header_name:
        header_name = node['name']
    #check if the initial node should be included
    if not skip_parent:
        #no_header probably also means a page break is not needed
        if level < 3 and not no_header:
            insert_page_break(mdFile)
        mdFile.new_line()
        if not no_header:
            mdFile.new_header(level=level, title=header_name)
        rich_node_to_md(mdFile, node)

    #do the same for all subnodes (recursively)
    for subnode in node['children']:
        create_md_for_node(mdFile, subnode, level+1, header_name=subnode['name'])

    return mdFile


def create_proof_appendix(mdFile, host_nodes):
    mdFile.new_line()
    mdFile.write('\\section{{Overview local and proof contents}}')  
    list_of_strings = ['**IP**', '**local.txt contents**', '**proof.txt contents**']

    for host in host_nodes:
        local_node = get_child_node_by_name(host, 'local.txt')
        local_contents = get_child_node_by_name(local_node, 'contents')['txt']
        
        proof_node = get_child_node_by_name(host, 'proof.txt')
        proof_contents = get_child_node_by_name(proof_node, 'contents')['txt']

        #ip = get_child_node_by_name(host, 'Host IP')['txt']
        ip = host['name']
        local = "\\footnotesize {}".format(
                local_contents if len(local_contents) else '-')
        proof = "\\footnotesize {}".format(
                proof_contents if len(proof_contents) else '-')
        list_of_strings.extend([ip, local, proof])

    mdFile.new_table(columns=3, rows=len(host_nodes)+1,
                     text=list_of_strings)

    return mdFile


def add_hosts_to_report(mdFile, host_nodes):
    for host_node in host_nodes:
        simple_mode = False

        #no overview node? Let's assume simple mode
        if not get_child_node_by_name(host_node, 'Overview'):
           simple_mode = True
        #simple_mode assumes no overview node and basically everything in one node
        if simple_mode:
            insert_page_break(mdFile) 
            mdFile = create_md_for_node(mdFile, host_node, level=1)
        else:
            #using the more extensive template
            overview_node = get_child_node_by_name(host_node, 'Overview')
            enum_node = get_child_node_by_name(host_node, 'Service enumeration')
            exploit_node = get_child_node_by_name(host_node, 'Exploitation')
            privesc_node = get_child_node_by_name(host_node, 'Privilege escalation')

            insert_page_break(mdFile)
            mdFile = create_machine_titlepage(mdFile, overview_node)
            mdFile = create_md_for_node(mdFile, enum_node)

            #exploitation header
            insert_page_break(mdFile)
            mdFile.new_header(level=2, title="Exploitation")
            mdFile = create_summary(mdFile, exploit_node['children'][0]) 

            #Assumption: the first node is for the summary/initial page
            #remove initial node from exploit
            #because create_summary was used for that
            exploit_node['children'].pop(0)

            #exploitation 
            mdFile = create_md_for_node(mdFile, exploit_node, skip_parent=True)

            #privesc header
            insert_page_break(mdFile)
            mdFile.new_header(level=2, title="Privilege escalation")
            mdFile = create_summary(mdFile, privesc_node['children'][0])

            #remove initial node from privesc because
            #create_summary was used for that
            privesc_node['children'].pop(0)

            #privesc 
            mdFile = create_md_for_node(mdFile, privesc_node, skip_parent=True)
    return mdFile


def create_appendices(mdFile, host_nodes):
    insert_page_break(mdFile)
    mdFile.write('\\appendix')
    mdFile = create_proof_appendix(mdFile, host_nodes)

    for host in host_nodes:
        appendix_node = get_child_node_by_name(host, 'Appendix')
        for appendix in appendix_node['children']:
            insert_page_break(mdFile)
            header_name = appendix['name']
            mdFile.write('\\section{{{}}}'.format(header_name))
            create_md_for_node(mdFile, appendix, no_header=True)
    return mdFile


def create_report():
    exam_hosts_node = get_node_by_name('Hosts')
    host_nodes = populate_childs_of_node(exam_hosts_node)['children']
    personal = json.loads(get_node_by_name('Personal')['txt'])
    
    #create the output directory, document and the title page
    output_directory = 'report/{}'.format(personal['exam_date'])
    if not os.path.exists(output_directory):
        os.makedirs(output_directory)

    mdFile = create_document('{}/OSCP-{}-Exam-Report.md'
            .format(output_directory, personal['osid']))
    mdFile = create_title_page(mdFile)

    #static parts
    #convert date for introduction  
    exam_date = datetime.datetime.strptime(personal['exam_date'], '%m-%d-%Y')
    personal['exam_date'] = exam_date.strftime('%A, %B %d, %Y')
    introduction_personal = [personal['osid'], personal['exam_date']]

    mdFile = write_static_part(mdFile, 'report-sections/static/header1.md')
    mdFile = write_static_part(mdFile,
                               'report-sections/static/introduction.md', 
                               introduction_personal)
    mdFile = write_static_part(mdFile, 'report-sections/static/hl-summary.md')
    mdFile = write_static_part(mdFile, 'report-sections/static/methodologies.md')
    insert_page_break(mdFile)
    mdFile = write_static_part(mdFile, 'report-sections/static/information-gathering.md')

    #insert list of exam network hosts
    host_names = [host['name'] for host in host_nodes]
    mdFile.new_list(items=host_names, marked_with='-')

    #adding machines here, wrap this in a function later
    add_hosts_to_report(mdFile, host_nodes)

    #TODO: make the static part optional
    insert_page_break(mdFile)
    mdFile = write_static_part(mdFile, 'report-sections/static/housecleaning.md')

    #write appendix
    mdFile = create_appendices(mdFile, host_nodes)

    #create the actual file
    mdFile.create_md_file()


parser = argparse.ArgumentParser()
parser.add_argument("cherrytree", help="path to your cherrytree ctb file")
args = parser.parse_args()

#connect() uses this
cherrytree = args.cherrytree

#Create markdown report
create_report()

#generate pdf
personal = json.loads(get_node_by_name('Personal')['txt'])
subprocess.run(["/bin/sh",
                "docker_run.sh",
                personal['osid'], 
                personal['exam_date']])

