import xml.etree.ElementTree as ET
import json


def get_elements(xml_path):
    try:
        tree = ET.parse(xml_path)
        oval_definitions = tree.getroot()
        element_dict = {}
        for element in oval_definitions:
            element_tag = element.tag[
                          element.tag.index('}') + 1:]  # {http://oval.mitre.org/XMLSchema/oval-definitions-5}generator
            element_dict[element_tag] = element
        return oval_definitions, element_dict
    except IOError as e:
        print(e)


def get_definition_info(definition):
    prefix = '{http://oval.mitre.org/XMLSchema/oval-definitions-5}'

    info = {'id': definition.get('id'),
            'description': definition.find(f'{prefix}metadata/{prefix}description').text.replace('\n', ''),
            'title': definition.find(f'{prefix}metadata/{prefix}title').text,
            'fix': definition.find(f'{prefix}criteria/{prefix}criterion').get('comment')}

    reference = definition.findall(f'{prefix}metadata/{prefix}reference')
    info['reference'] = {'CVE': [], 'RHSA': []}
    for ref in reference:
        info['reference'][ref.get('source')].append(ref.get('ref_url'))

    advisory = definition.find(f'{prefix}metadata/{prefix}advisory')
    info['cve'] = []
    for item in advisory:
        if 'cve' in item.tag:
            info['cve'].append({item.text: item.get('cvss3')[:item.get('cvss3').find('/')]})

    criteria = definition.findall(f'{prefix}criteria/')
    comment_list = []
    for criterion in criteria:
        if criterion.get('comment') is not None:
            comment_list.append(criterion.get('comment'))
    info['criteria'] = comment_list

    return info


elems = get_elements('rhel-8.oval.xml')[1]

vulnerabilities = []
for definition in elems['definitions'][:3]:
    infor = get_definition_info(definition)
    vulnerabilities.append(infor)

with open('output.json', 'w') as wfile:
    json.dump(vulnerabilities, wfile, indent=4)
