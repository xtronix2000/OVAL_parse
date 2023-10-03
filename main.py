import xml.etree.ElementTree as ET
import json

# Парсинг файла
tree = ET.parse('rhel-8.oval.xml')
root = tree.getroot()

# Список словарей для хранения информации об уязвимостях
vulnerabilities = []

# Итерируемся по тегам definition 
for definition in root.findall('.//{http://oval.mitre.org/XMLSchema/oval-definitions-5}definition')[:3]:
    # Словарь с основной информацией об уязвимости
    vuln = {}
    vuln['id'] = definition.get('id')
    vuln['title'] = definition.find('.//{http://oval.mitre.org/XMLSchema/oval-definitions-5}metadata/{http://oval.mitre.org/XMLSchema/oval-definitions-5}title').text
    vuln['fix'] = definition.find('.//{http://oval.mitre.org/XMLSchema/oval-definitions-5}criteria/{http://oval.mitre.org/XMLSchema/oval-definitions-5}criterion').get('comment')
    vuln['cve'] = []
    
    # Пробег по всем ссылкам, у которых ref_id содержит 'CVE'    
    for item in definition.find('.//{http://oval.mitre.org/XMLSchema/oval-definitions-5}metadata/{http://oval.mitre.org/XMLSchema/oval-definitions-5}advisory'):
        if 'cve' in item.tag:  
           vuln['cve'].append({item.text: item.get('cvss3')[:item.get('cvss3').find('/')]})
 
    vuln['description'] = definition.find('.//{http://oval.mitre.org/XMLSchema/oval-definitions-5}metadata/{http://oval.mitre.org/XMLSchema/oval-definitions-5}description').text.replace('\n', '')
    # Добавление описание уязвимости в список
    vulnerabilities.append(vuln)
 
# Вывод в терминал 
#for i, dct in enumerate(vulnerabilities, start=1):
    #!print('Vuln', i)
    #for k, v in dct.items():
        #print(f'{k.upper()}: {v}')
    #print()

# Преобразование в упрощенный формат
with open('output.json', 'w') as wfile:
    json.dump(vulnerabilities, wfile, indent=4)
