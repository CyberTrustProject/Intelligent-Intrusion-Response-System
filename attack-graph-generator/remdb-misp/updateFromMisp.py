from flask import Flask
from pymisp import ExpandedPyMISP
from keys import misp_url, misp_key, misp_verifycert
from datetime import date,datetime,timedelta
import sqlite3
import os
import json
import requests


db_filename = os.environ['VULNERABILITY_DATABASE_PATH']

connection = sqlite3.connect(db_filename)
cursor = connection.cursor()

headers = {
    'Authorization': misp_key,
    'Accept': 'application/json',
    'Content-type': 'application/json'
}

today = date.today() 
yesterday = str(today - timedelta(days = 40)) + "%"
print("[UPDATE] Daily RemediationDB Update for -> " + yesterday)

data = {"returnFormat":"json", "page":"1", "limit":"5", "value": yesterday }

response = requests.post(misp_url + '/events/restSearch', headers = headers, data = json.dumps(data))

for event in response.json()['response']:
    for vuln in event['Event']['Object']:

        rel_events = []
        rel_events_ids = []
        timestamp = 1545730073
        dt_object = datetime.fromtimestamp(timestamp)
        cve_id = ''
        vuln_confs = []
        pubtime = ''
        description = ''
        modtime = ''
        cvss_score = 0.0
        cvss_str = ''
        refs = []
        refs_tags = []
        summary = ''
        credit = ''

        if vuln['name'] == "weakness":
            continue
        

        for attribute in vuln['Attribute']:
            if attribute['object_relation'] == 'id':
                cve_id = attribute['value']
            if attribute['object_relation'] == 'published':
                pubtime = attribute['value']
            if attribute['object_relation'] == 'description':
                description = attribute['value']
            if attribute['object_relation'] == 'modified':
                modtime = attribute['value']
            if attribute['object_relation'] == 'cvss-score':
                cvss_score = attribute['value']
            if attribute['object_relation'] == 'cvss-string':
                cvss_str = attribute['value']
            if attribute['object_relation'] == 'references':
                refs.append(attribute['value'])
                refs_tags.append(attribute['comment'])
            if attribute['object_relation'] == 'summary':
                summary = attribute['value']
            if attribute['object_relation'] == 'credit':
                credit = attribute['value']

        print("+-------Update Info-------+")
        print("CVE:", cve_id)
        print("Related Events IDs:")
        for r in rel_events_ids:
            print("\t", r)

        print("Summary:", summary)
        print("Publication datetime:", pubtime)
        print("Last modification datetime:", modtime)
        print("CVSS string:", cvss_str)
        print("CVSS score:", cvss_score)
        print("Vulnerable Configurations:")

        for vc in vuln_confs:
            print("\t", vc)

        print("References:")
        y = 0
        for r in refs:
            print("\t", r)
            print("\t\t", refs_tags[y])
            y = y + 1
        print("Credit/Source:", credit)
        print("")
        print("")
        print("Description:")
        print(description)
        print("+------------------------+")

    
        if credit == 'nvd':
            if  cvss_str.split('/')[0] == 'CVSS:3.0' or  cvss_str.split('/')[0] == 'CVSS:3.1':

                attackVector = ''
                attackComplexity = ''
                privilegesRequired = ''
                userInteraction =  ''
                scope =  ''
                confidentiality = ''
                integrity = ''
                availability = '' 

                attackVector = cvss_str.split('/')[1].split(':')[1]
                attackComplexity = cvss_str.split('/')[2].split(':')[1]
                privilegesRequired = cvss_str.split('/')[3].split(':')[1]
                userInteraction = cvss_str.split('/')[4].split(':')[1]
                scope = cvss_str.split('/')[5].split(':')[1]
                confidentiality = cvss_str.split('/')[6].split(':')[1]
                integrity = cvss_str.split('/')[7].split(':')[1]
                availability = cvss_str.split('/')[8].split(':')[1]

                if attackVector == "N":
                    attackVector = "NETWORK"

                if attackVector == "A":
                    attackVector = "ADJACENT_NETWORK"

                if attackVector == "L":
                    attackVector = "LOCAL"

                if attackVector == "P":
                    attackVector = "PHYSICAL"

                if attackComplexity == "L":
                    attackComplexity = "LOW"

                if attackComplexity == "H":
                    attackComplexity = "HIGH"

                if privilegesRequired == "N":
                    privilegesRequired = "NONE"

                if privilegesRequired == "L":
                    privilegesRequired = "LOW"

                if privilegesRequired == "H":
                    privilegesRequired = "HIGH"

                if userInteraction == "N":
                    userInteraction = "NONE"

                if userInteraction == "R":
                    userInteraction = "REQUIRED"

                if scope == "U":
                    scope = "UNCHANGED"
                
                if scope == "C":
                    scope = "CHANGED"

                if confidentiality == "H":
                    confidentiality = "HIGH"

                if confidentiality == "L":
                    confidentiality = "LOW"

                if confidentiality == "N":
                    confidentiality = "NONE"

                if availability == "H":
                    availability = "HIGH"

                if availability == "L":
                    availability = "LOW"

                if availability == "N":
                    availability = "NONE"

                if integrity == "H":
                    integrity = "HIGH"

                if integrity == "L":
                    integrity = "LOW"

                if integrity == "N":
                    integrity = "NONE"

            else:

                attackVector = ''
                attackComplexity = ''
                privilegesRequired = ''
                userInteraction =  ''
                scope =  ''
                confidentiality = ''
                integrity = ''
                availability = '' 

                attackVector = cvss_str.split('/')[0].split(':')[1]
                attackComplexity = cvss_str.split('/')[1].split(':')[1]
                privilegesRequired = cvss_str.split('/')[2].split(':')[1]
            
                confidentiality = cvss_str.split('/')[3].split(':')[1]
                integrity = cvss_str.split('/')[4].split(':')[1]
                availability = cvss_str.split('/')[5].split(':')[1]

                if attackVector == "N":
                    attackVector = "NETWORK"

                if attackVector == "A":
                    attackVector = "ADJACENT_NETWORK"

                if attackVector == "L":
                    attackVector = "LOCAL"


                if attackComplexity == "L":
                    attackComplexity = "LOW"

                if attackComplexity == "H":
                    attackComplexity = "HIGH"

                if privilegesRequired == "N":
                    privilegesRequired = "NONE"

                if privilegesRequired == "L":
                    privilegesRequired = "LOW"

                if privilegesRequired == "H":
                    privilegesRequired = "HIGH"

                userInteraction = ""
                scope = ""

                if confidentiality == "C":
                    confidentiality = "COMPLETE"

                if confidentiality == "P":
                    confidentiality = "PARTIAL"

                if confidentiality == "N":
                    confidentiality = "NONE"

                if availability == "C":
                    availability = "COMPLETE"

                if availability == "P":
                    availability = "PARTIAL"

                if availability == "N":
                    availability = "NONE"

                if integrity == "C":
                    integrity = "COMPLETE"

                if integrity == "P":
                    integrity = "PARTIAL"

                if integrity == "N":
                    integrity = "NONE"

            cursor.execute(
                "SELECT * FROM vulnerability WHERE vulnerability.cve = ?", (cve_id, ))
            row = cursor.fetchall()
            empty = ""

            id_vulnerability = 0
            id_cvss = 0

            if row is empty:

                cursor.execute("INSERT INTO cvss(score, attack_vector, attack_complexity, authentication_priviledges, user_interaction, scope, confidentiality_impact, integrity_impact, availability_impact)  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",(cvss_score, attackVector, attackComplexity, privilegesRequired, userInteraction, scope, confidentiality, integrity, availability))
                lastrow_CVSS = 0
                lastrow_CVSS = cursor.lastrowid
           
                cursor.execute("INSERT INTO vulnerability(cve,description,cvss_id) values(? ,? ,?)", (cve_id, description, str(lastrow_CVSS)))
                lastrow_Vulnerability = cursor.lastrowid

                for link in refs:
                    link1 = link
                    link2 = ""
                    tagsSTR = ""

                    tags = ((''.join(refs_tags[i]))[1:len((''.join(refs_tags[i])))-1]).replace(' ','').replace("'",'').split(',')
                    for tag in tags:
                        if tag == "VendorAdvisory":
                            tagsSTR = tagsSTR + "," + "Vendor Advisory"
                        elif tag == "ThirdPartyAdvisory":
                            tagsSTR = tagsSTR + "," + "Third Party Advisory"
                        else:
                            tagsSTR = tagsSTR + "," + tag

                    tagsSTR = tagsSTR[1:]
                    if "Patch" in tagsSTR.split(',') or "Vendor Advisory" in tagsSTR.split(',') or "Third Party Advisory" in tagsSTR.split(','):
                        cursor.execute("INSERT INTO patchs(link, description, tags)  VALUES (?,?,?)", (link1, link2, tagsSTR.lstrip()))
                        lastrow_Patch = cursor.lastrowid
                        cursor.execute("INSERT INTO patchs_vulnerability(id_patch,id_vulnerability) VALUES(?,?)",(lastrow_Patch, lastrow_Vulnerability ))

                    connection.commit()
                  
            else :

                id_vulnerability = row[0][0]
                id_cvss = row[0][3]
                
                cursor.execute("UPDATE cvss SET score = ?, attack_vector = ?, attack_complexity = ?, authentication_priviledges = ?, user_interaction = ?, scope = ?, confidentiality_impact = ?, integrity_impact = ?, availability_impact = ? WHERE id = ?",(cvss_score, attackVector, attackComplexity, privilegesRequired, userInteraction, scope, confidentiality, integrity, availability,int(id_cvss)))
                cursor.execute("UPDATE vulnerability SET  description = ? WHERE id = ?",(description, int(id_vulnerability)))
                connection.commit()
                
               

                for link in refs:

                    cursor.execute("SELECT id FROM patchs WHERE link = ?", (link, ))
                    
                    row_patch = cursor.fetchall()

                    if row_patch is empty:
                        link1 = link
                        link2 = ""
                        tagsSTR = ""

                        tags = ((''.join(refs_tags[i]))[1:len((''.join(refs_tags[i])))-1]).replace(' ','').replace("'",'').split(',')
                        for tag in tags:
                            if tag == "VendorAdvisory":
                                tagsSTR = tagsSTR + "," + "Vendor Advisory"
                            elif tag == "ThirdPartyAdvisory":
                                tagsSTR = tagsSTR + "," + "Third Party Advisory"
                            else:
                                tagsSTR = tagsSTR + "," + tag

                        tagsSTR = tagsSTR[1:]
                        if "Patch" in tagsSTR.split(',') or "Vendor Advisory" in tagsSTR.split(',') or "Third Party Advisory" in tagsSTR.split(','):
                            
                            cursor.execute("INSERT INTO patchs(link, description, tags)  VALUES (?,?,?)", (link1, link2, tagsSTR.lstrip()))
                            lastrow_Patch = cursor.lastrowid
                            cursor.execute("INSERT INTO patchs_vulnerability(id_patch,id_vulnerability) VALUES(?,?)",(lastrow_Patch, int(id_vulnerability)))
                     
                exit()

            connection.commit()
        

print("[UPDATE] Finished")
connection.close()
