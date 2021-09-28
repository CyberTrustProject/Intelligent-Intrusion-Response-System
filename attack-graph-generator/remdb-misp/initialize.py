import sqlite3
import json
import tqdm
import os 

db_filename = os.environ['VULNERABILITY_DATABASE_PATH']
reject_str = '** REJECT **'
nvd_url = 'https://nvd.nist.gov/vuln/data-feeds'
commit_step = 1000

counter = 1

def init_db_structure(connection, cursor):
    progressbar = init_progressbar('     Initializing Tables', 'steps', 2)

    cursor.execute("DROP TABLE cvss")
    cursor.execute("DROP TABLE vulnerability")
    cursor.execute("DROP TABLE patchs")
    cursor.execute("DROP TABLE patchs_vulnerability")
    progressbar.update(1)

    cursor.execute("CREATE TABLE cvss (id INTEGER PRIMARY KEY AUTOINCREMENT, score REAL, attack_vector TEXT, attack_complexity TEXT, authentication_priviledges TEXT, user_interaction TEXT,scope TEXT, confidentiality_impact TEXT, integrity_impact TEXT, availability_impact TEXT, exploit_code_maturity TEXT DEFAULT '-1', remediation_level TEXT DEFAULT '-1', report_confidence TEXT DEFAULT '-1')")
    cursor.execute("CREATE TABLE vulnerability (id INTEGER PRIMARY KEY AUTOINCREMENT, cve TEXT UNIQUE, description TEXT, cvss_id INTEGER)")
    cursor.execute("CREATE TABLE patchs (id INTEGER PRIMARY KEY AUTOINCREMENT, link TEXT, description TEXT, tags TEXT)")
    cursor.execute("CREATE TABLE patchs_vulnerability (id_patch INTEGER, id_vulnerability INTEGER)")
    progressbar.update(1)

    connection.commit()

def init_progressbar(description, unit_name, iterations):
    return tqdm.tqdm(desc=description, unit=unit_name, dynamic_ncols=True, total=iterations)


def parse_json_cve_cvss(connection, cursor, filename):
    with open(filename, encoding="utf-8") as json_file:
        global counter
        data = json.load(json_file, encoding="utf-8")
        iteration = 1

        progressbar = init_progressbar('    ' + filename.split('/')[2], 'records', len(data['CVE_Items']))
        for cve in data['CVE_Items']:
            idcvss = cve['cve']['CVE_data_meta']['ID']
            value = str(cve['cve']['description']['description_data'][0]["value"])

            if reject_str not in value:
                if len(cve['impact']) >= 1:
                    if 'baseMetricV3' in cve['impact']:

                        base = cve["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
                        av = str(cve["impact"]["baseMetricV3"]["cvssV3"]["attackVector"])
                        ac = str(cve["impact"]["baseMetricV3"]["cvssV3"]["attackComplexity"])
                        au = str(cve["impact"]["baseMetricV3"]["cvssV3"]["privilegesRequired"])
                        user_int = str(cve["impact"]["baseMetricV3"]["cvssV3"]["userInteraction"])
                        scope = str(cve["impact"]["baseMetricV3"]["cvssV3"]["scope"])
                        impact = str(cve["impact"]["baseMetricV3"]["cvssV3"]["confidentialityImpact"])
                        integrity = str(cve["impact"]["baseMetricV3"]["cvssV3"]["integrityImpact"])
                        availability = str(cve["impact"]["baseMetricV3"]["cvssV3"]["availabilityImpact"])

                    else:
         
                        base = cve["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
                        av = str(cve["impact"]["baseMetricV2"]["cvssV2"]["accessVector"])
                        ac = str(cve["impact"]["baseMetricV2"]["cvssV2"]["accessComplexity"])
                        au = str(cve["impact"]["baseMetricV2"]["cvssV2"]["authentication"])
                        impact = str(cve["impact"]["baseMetricV2"]["cvssV2"]["confidentialityImpact"])
                        integrity = str(cve["impact"]["baseMetricV2"]["cvssV2"]["integrityImpact"])
                        availability = str(cve["impact"]["baseMetricV2"]["cvssV2"]["availabilityImpact"])
                        user_int = ""
                        scope = ""                       
               
                else:
                    base = 0
                    av = ""
                    ac = ""
                    au = ""
                    user_int = ""
                    scope = ""
                    integrity = ""
                    impact = ""
                    availability = ""
                    
                

                cursor.execute("INSERT INTO cvss(score, attack_vector, attack_complexity, authentication_priviledges, user_interaction, scope, confidentiality_impact, integrity_impact, availability_impact)  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",(base, av, ac, au, user_int, scope, impact, integrity, availability))

                cursor.execute("INSERT INTO vulnerability(cve,description,cvss_id) values(? ,? ,?)",(idcvss, value, counter))
                counter += 1

            if iteration % commit_step == 0:
                connection.commit()

            iteration += 1
            progressbar.update(1)

        connection.commit()


def parse_json_patch(connection, cursor, filename):
    with open(filename, encoding="utf-8") as json_file:
        data = json.load(json_file, encoding="utf-8")
        global combos
        global counter
        iteration = 1

        progressbar = init_progressbar('    ' + filename.split('/')[2], 'records', len(data['CVE_Items']))
        for cve in data['CVE_Items']:
            idcvss = cve['cve']['CVE_data_meta']['ID']

            cursor.execute("SELECT id FROM vulnerability WHERE cve = ?",(idcvss,))
            row = cursor.fetchall()


            for link in cve['cve']['references']['reference_data']:
                link1 = link['url']
                link2 = link['name']
                tagsSTR = ""

                for tag in link['tags']:
                    if tag == "Vendor Advisory":
                        tagsSTR = tagsSTR + "," + "Vendor Advisory"
                    elif tag == "Third Party Advisory":
                        tagsSTR = tagsSTR + "," + "Third Party Advisory"
                    else:
                        tagsSTR = tagsSTR + "," + tag

                tagsSTR = tagsSTR[1:]
                if "Patch" in tagsSTR.split(',') or "Vendor Advisory" in tagsSTR.split(',') or "Third Party Advisory" in tagsSTR.split(','):
                    cursor.execute("INSERT INTO patchs(link, description, tags)  VALUES (?,?,?)", (link1, link2, tagsSTR.lstrip()))
                    cursor.execute("INSERT INTO patchs_vulnerability(id_patch,id_vulnerability) VALUES(?,?)",(counter, ((("".join(map(str, row))).replace('(','')).replace(')','')).replace(',','')))
                    counter += 1

            if iteration % commit_step == 0:
                connection.commit()

            iteration += 1

            progressbar.update(1)

        connection.commit()

# ------------------------------------------------------------------------------

connection = sqlite3.connect(db_filename)
cursor = connection.cursor()

print('[INFO] Initializing DB tables.')
init_db_structure(connection, cursor)
print('')

print('[INFO] Parsing CVE & CVSS info.')
parse_json_cve_cvss(connection, cursor, './json/nvdcve-1.1-2002.json')
parse_json_cve_cvss(connection, cursor, './json/nvdcve-1.1-2003.json')
parse_json_cve_cvss(connection, cursor, './json/nvdcve-1.1-2004.json')
parse_json_cve_cvss(connection, cursor, './json/nvdcve-1.1-2005.json')
parse_json_cve_cvss(connection, cursor, './json/nvdcve-1.1-2006.json')
parse_json_cve_cvss(connection, cursor, './json/nvdcve-1.1-2007.json')
parse_json_cve_cvss(connection, cursor, './json/nvdcve-1.1-2008.json')
parse_json_cve_cvss(connection, cursor, './json/nvdcve-1.1-2009.json')
parse_json_cve_cvss(connection, cursor, './json/nvdcve-1.1-2010.json')
parse_json_cve_cvss(connection, cursor, './json/nvdcve-1.1-2011.json')
parse_json_cve_cvss(connection, cursor, './json/nvdcve-1.1-2012.json')
parse_json_cve_cvss(connection, cursor, './json/nvdcve-1.1-2013.json')
parse_json_cve_cvss(connection, cursor, './json/nvdcve-1.1-2014.json')
parse_json_cve_cvss(connection, cursor, './json/nvdcve-1.1-2015.json')
parse_json_cve_cvss(connection, cursor, './json/nvdcve-1.1-2016.json')
parse_json_cve_cvss(connection, cursor, './json/nvdcve-1.1-2017.json')
parse_json_cve_cvss(connection, cursor, './json/nvdcve-1.1-2018.json')
parse_json_cve_cvss(connection, cursor, './json/nvdcve-1.1-2019.json')
parse_json_cve_cvss(connection, cursor, './json/nvdcve-1.1-2020.json')
print('[INFO] ' + str(counter - 1) + ' records processed.\n')

counter = 1

print('[INFO] Parsing PATCH info.')
parse_json_patch(connection, cursor, './json/nvdcve-1.1-2002.json')
parse_json_patch(connection, cursor, './json/nvdcve-1.1-2003.json')
parse_json_patch(connection, cursor, './json/nvdcve-1.1-2004.json')
parse_json_patch(connection, cursor, './json/nvdcve-1.1-2005.json')
parse_json_patch(connection, cursor, './json/nvdcve-1.1-2006.json')
parse_json_patch(connection, cursor, './json/nvdcve-1.1-2007.json')
parse_json_patch(connection, cursor, './json/nvdcve-1.1-2008.json')
parse_json_patch(connection, cursor, './json/nvdcve-1.1-2009.json')
parse_json_patch(connection, cursor, './json/nvdcve-1.1-2010.json')
parse_json_patch(connection, cursor, './json/nvdcve-1.1-2011.json')
parse_json_patch(connection, cursor, './json/nvdcve-1.1-2012.json')
parse_json_patch(connection, cursor, './json/nvdcve-1.1-2013.json')
parse_json_patch(connection, cursor, './json/nvdcve-1.1-2014.json')
parse_json_patch(connection, cursor, './json/nvdcve-1.1-2015.json')
parse_json_patch(connection, cursor, './json/nvdcve-1.1-2016.json')
parse_json_patch(connection, cursor, './json/nvdcve-1.1-2017.json')
parse_json_patch(connection, cursor, './json/nvdcve-1.1-2018.json')
parse_json_patch(connection, cursor, './json/nvdcve-1.1-2019.json')
parse_json_patch(connection, cursor, './json/nvdcve-1.1-2020.json')

connection.commit()
connection.close()
