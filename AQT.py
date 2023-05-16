########################################################################
######### AQT - ACAS QUERY TOOL v1 #####################################
########################################################################

# GUI:
import PySimpleGUI as Sg
# TENABLE:
from tenable.sc import TenableSC
# EMAIL:
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
# WORDCLOUD:
from wordcloud import WordCloud
from wordcloud import STOPWORDS
# SYS:
import os
import base64
import json
from time import sleep
import datetime
import re
import csv
from random import randrange
from uuid import uuid4
# LOGGING:
from logging import basicConfig
import logging
# GRAPHS:
import matplotlib
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
# PDF
import fitz

# TODO: build out theme chooser instead of only one theme:
Sg.theme("DarkGrey11")

# IMAGES: TODO: move this base64 var into the actual email button element:
email = b'iVBORw0KGgoAAAANSUhEUgAAABoAAAAWCAIAAABR6hviAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAGdSURBVDhPvZQ/L4NRFMbfL6AfoHwAumMXXbVlJA0b8WcjlZo0qbCQkDAwEAYGEhJdOhAWBkwWX8YvnpPb5r15//RN48lJc+65zzk99zmnDf4budzAfHUWw7FQZqytLH28vfx8f2E4FLWLXlGcnHhqP1Ll6uJsaDCP4XAkyJWR0qAwMnx5fkrmc7s1PjZq0T9wJMgVBGgWjQLq7Da3YX++v85UShb1sFCdgwANcqSgTiacRNUhQINMyuryokUF2pZMJ0cHaGTRFIBMComkd94uOY4P9zOsAikkqqKFOKginU+XpyyaAugrfZRuUTyEoFutwv3tdWigPiBAg0wKidLR7lROPjvl3u505EVOB4J6HTS3gJHlBI5ahXptXVPCcDjicOXzidsBL3QNaEdt8smiYTpS1J9YQjkStM97Ow2XjKO18Lc3rhzSSmY6slAXCHIFobNoMeVQl9mjTsxwuYIALWEUW5sb+A93N746ITBfaJD1CwuXo5D+RRDLoikAmRQS1YdFNTIMRfi2nkwqYzRr5RBVnWc20rsn0ycEwS/lZqINzQ9nuAAAAABJRU5ErkJggg=='

# load docs:
# load docs:
doc64List = []
pdfDoc = fitz.open("docs/AQT.pdf")
for page in pdfDoc:
    img = page.get_pixmap()
    img.save("docs/imgs/page-%i.png" % page.number)

for file in os.listdir("{}/docs/imgs".format(os.getcwd())):
    with open("{}/docs/imgs/{}".format(os.getcwd(), file), "rb") as image_file:
        enc = base64.b64encode(image_file.read())
        doc64List.append(enc)

# TODO: pack these file calls into a function:
with open("configs/search.cache") as searchCache:
    searches = []
    for line in searchCache:
        searches.append(line.strip())

with open("configs/query.cache") as queryCache:
    queries = []
    for line in queryCache:
        queries.append(line.strip())

with open("configs/advQuery.cache") as advQueryCache:
    advQueries = []
    for line in advQueryCache:
        advQueries.append(line.strip())

with open("configs/solutionFilter.cache") as solutionFilterCache:
    solQueries = []
    for line in solutionFilterCache:
        solQueries.append(line.strip())

with open("configs/easy.config") as easyCon:
    easyList = []
    for line in easyCon:
        easyList.append(line.strip())
with open("configs/intermediate.config") as interCon:
    interList = []
    for line in interCon:
        interList.append(line.strip())
with open("configs/hard.config") as hardCon:
    hardList = []
    for line in hardCon:
        hardList.append(line.strip())

with open("configs/insane.config") as insaneCon:
    insaneList = []
    for line in insaneCon:
        insaneList.append(line.strip())

with open("configs/scanHistory.cache") as scanHistory:
    scanHist = []
    scanHistList = []
    resultScanHistList = []

    scanz = scanHistory.read()
    for data in scanz.splitlines():
        spli = data.split(",")
        scanHistList.append(spli[0])
        resultScanHistList.append(spli[1])

# ACAS right click menu:
# removed Remediation, Verifier, Quick/Ideal Solutions:
# TODO: update right click menus in realtime to check for VSphere enabled
right_click_menu = ['',
                    ['ACAS Query', [['IP Address', 'Plugin ID', 'Severity', 'Run Advanced Query']],
                     "Send to Scanner", "Send to Solutionizer", "Send to VSphere", "Flip to CSV",
                     "Save Data for Export"]]

# vSphere right click menu: a space is added to the end of each element which differentiates it from
# the ACAS menu without needed to change the terminology
vSphere_RCM = ['',
               ['vSphere Query', [['IP Address ', 'Run Advanced Query ']],
                "Send to Scanner ", "Send to ACAS", "Flip to CSV ", "Save Data for Export "]]

recipients = ['', '']  # TODO: remove this and fix errors it may cause
# exemptIPs = ["", ""]
exemptPlugins = ['108797', '55786', '164453', '51873', '164422',
                 # TODO: remove this and instead add exempt plugins to config tab / code functionality for it
                 '156032', '156860', '161948', '92522', '164422', '97435', '127905',
                 '166316', '166807', '51873', '35453', '122615', '34460', '126641']


def alternateConvertAll(vSphereDictioniary: dict, ACASList: list, filepath: str, v):
    with open(filepath, 'w', newline='') as csvfile:
        csvWriter = csv.writer(csvfile)
        pluginHeader = ['ip', 'Plugin ID', 'Severity']
        if v['exportACASNotes'] == True:
            pluginHeader.append('acas_notes')
        if v['exportIncludeACASReason'] == True:
            pluginHeader.append('acas_reason')
        if v['exportIncludeACASExemption'] == True:
            pluginHeader.append('exempt_plugin')

        for item in ['VM_name', 'hostname', 'guest_os', 'power_state']:
            pluginHeader.append(item)
        if v['exportVSphereNotes'] == True:
            pluginHeader.append("vSphere Notes")
        if v['exportVSphereReason'] == True:
            pluginHeader.append("vSphere Reason")
        if v['exportVSphereImpact'] == True:
            pluginHeader.append("quarantine_impact")

        csvWriter.writerow(pluginHeader)

        for item in ACASList:
            if v['exportIncludeExemptedPlugins'] == True or item.get('exempt') == False:
                toWrite = []
                currentIP = item.get('ip')
                toWrite.append(item.get('ip'))
                toWrite.append(item.get('pluginID'))
                toWrite.append(item.get('severity').get('name'))
                if v['exportACASNotes'] == True:
                    toWrite.append(item.get('notes'))
                if v['exportIncludeACASReason'] == True:
                    toWrite.append(item.get('reason'))
                if v['exportIncludeACASExemption'] == True:
                    toWrite.append(item.get('exempt'))
                try:
                    toWrite.append(vSphereDictioniary.get(currentIP).get('name'))
                    toWrite.append(vSphereDictioniary.get(currentIP).get('host_name'))
                    toWrite.append(vSphereDictioniary.get(currentIP).get('guest_os'))
                    toWrite.append(vSphereDictioniary.get(currentIP).get('power_state'))
                    if v['exportVSphereNotes'] == True:
                        toWrite.append(vSphereDictioniary.get(currentIP).get('notes'))
                    if v['exportVSphereReason'] == True:
                        toWrite.append(vSphereDictioniary.get(currentIP).get('reason'))
                    if v['exportVSphereImpact'] == True:
                        toWrite.append(vSphereDictioniary.get(currentIP).get('quarantine_impact'))
                except AttributeError:
                    print("vSphere Data Export Att Error")
                    pass

                print(toWrite)
                newList = [toWrite]
                csvWriter.writerows(newList)


# ACASlayout = [[Sg.Check("Export ACAS Data", key = "exportACASData")],
# 	       					[Sg.Check("Include Exempted Plugins", key = "exportIncludeExemptedPlugins")],
# 							[Sg.Check("Include Plugin Exemption", key = "exportIncludeACASExemption")],
# 							[Sg.Check("Include Reason", key = "exportIncludeACASReason")],
# 							[Sg.Check("Include Plugin Notes", key = "exportACASNotes")]]
# 	vSpherelayout = [[Sg.Check("Export vSphere Data", key = "exportVSphereData")],
# 						[Sg.Check("Include Quarantine Impact", key = "exportVSphereImpact")],
# 						[Sg.Check("Include Reason", key = "exportVSphereReason")],
# 						[Sg.Check("Include VM Notes", key = "exportVSphereNotes")]]
def defaultConvertAll(vSphereDictioniary: dict, ACASList: list, filepath: str):
    with open(filepath, 'w', newline='') as csvfile:
        csvWriter = csv.writer(csvfile)
        pluginHeader = ['ip', 'Plugin ID', 'Severity']
        pluginHeader.append('acas_notes')
        pluginHeader.append('acas_reason')
        pluginHeader.append('exempt_plugin')

        for item in ['VM_name', 'hostname', 'guest_os', 'power_state']:
            pluginHeader.append(item)
        pluginHeader.append("vSphere Notes")
        pluginHeader.append("vSphere Reason")
        pluginHeader.append("quarantine_impact")

        csvWriter.writerow(pluginHeader)

        for item in ACASList:
            toWrite = []
            currentIP = item.get('ip')
            toWrite.append(item.get('ip'))
            toWrite.append(item.get('pluginID'))
            toWrite.append(item.get('severity').get('name'))
            toWrite.append(item.get('notes'))

            toWrite.append(item.get('reason'))

            toWrite.append(item.get('exempt'))
            try:
                toWrite.append(vSphereDictioniary.get(currentIP).get('name'))
                toWrite.append(vSphereDictioniary.get(currentIP).get('host_name'))
                toWrite.append(vSphereDictioniary.get(currentIP).get('guest_os'))
                toWrite.append(vSphereDictioniary.get(currentIP).get('power_state'))

                toWrite.append(vSphereDictioniary.get(currentIP).get('notes'))

                toWrite.append(vSphereDictioniary.get(currentIP).get('reason'))

                toWrite.append(vSphereDictioniary.get(currentIP).get('quarantine_impact'))
            except AttributeError:
                print("vSphere Data Export Att Error")
                pass

            newList = [toWrite]
            csvWriter.writerows(newList)


def defaultConvertAllvAnchor(vSphereQueries: list, ACASList: list, filepath: str):
    with open(filepath, 'w', newline='') as csvfile:
        csvWriter = csv.writer(csvfile)
        # csvWriter.writerow(['VM_name', 'hostname', 'guest_os', 'power_state', 'vSphere Notes', 'vSphere Reason', 'quarantine_impact'])

        for entry in vSphereQueries:
            toWrite = []
            toWrite.append(entry.get('name'))
            toWrite.append(entry.get('host_name'))
            toWrite.append(entry.get('guest_os'))
            toWrite.append(entry.get('power_state'))
            headerRow = ['VM_name', 'hostname', 'guest_os', 'power_state']

            headerRow.append("vSphere Notes")
            toWrite.append(entry.get('notes'))

            headerRow.append("vSphere Reason")
            toWrite.append(entry.get('reason'))

            headerRow.append("quarantine_impact")
            toWrite.append(entry.get('quarantine_impact'))
            csvWriter.writerow(headerRow)

            csvWriter.writerow(toWrite)
            toWrite.clear()
            blank = []
            csvWriter.writerow(blank)
            pluginHeader = ['ip', 'Plugin ID', 'Severity']

            pluginHeader.append('acas_notes')

            pluginHeader.append('acas_reason')

            pluginHeader.append('exempt_plugin')
            # ['ip', 'Plugin ID', 'Severity', 'acas_notes', 'acas_reason', 'exempt_plugin']
            csvWriter.writerow(pluginHeader)
            for num in entry.get('vulnUUID'):
                for item in ACASList:
                    vulnData = []
                    if item.get('customUUID') == num:
                        vulnData.append(item.get('ip'))
                        vulnData.append(item.get('pluginID'))
                        vulnData.append(item.get('severity').get('name'))

                        vulnData.append(item.get('notes'))

                        vulnData.append(item.get('reason'))

                        vulnData.append(item.get('exempt'))
                        csvWriter.writerow(vulnData)
                    vulnData.clear()


def convertAllvAnchor(vSphereQueries: list, ACASList: list, filepath: str, v):
    with open(filepath, 'w', newline='') as csvfile:
        csvWriter = csv.writer(csvfile)
        # csvWriter.writerow(['VM_name', 'hostname', 'guest_os', 'power_state', 'vSphere Notes', 'vSphere Reason', 'quarantine_impact'])

        for entry in vSphereQueries:
            toWrite = []
            toWrite.append(entry.get('name'))
            toWrite.append(entry.get('host_name'))
            toWrite.append(entry.get('guest_os'))
            toWrite.append(entry.get('power_state'))
            headerRow = ['VM_name', 'hostname', 'guest_os', 'power_state']
            if v['exportVSphereNotes'] == True:
                headerRow.append("vSphere Notes")
                toWrite.append(entry.get('notes'))
            if v['exportVSphereReason'] == True:
                headerRow.append("vSphere Reason")
                toWrite.append(entry.get('reason'))
            if v['exportVSphereImpact'] == True:
                headerRow.append("quarantine_impact")
                toWrite.append(entry.get('quarantine_impact'))
            csvWriter.writerow(headerRow)

            csvWriter.writerow(toWrite)
            toWrite.clear()
            blank = []
            csvWriter.writerow(blank)
            pluginHeader = ['ip', 'Plugin ID', 'Severity']
            if v['exportACASNotes'] == True:
                pluginHeader.append('acas_notes')
            if v['exportIncludeACASReason'] == True:
                pluginHeader.append('acas_reason')
            if v['exportIncludeACASExemption'] == True:
                pluginHeader.append('exempt_plugin')
            # ['ip', 'Plugin ID', 'Severity', 'acas_notes', 'acas_reason', 'exempt_plugin']
            csvWriter.writerow(pluginHeader)
            for num in entry.get('vulnUUID'):
                for item in ACASList:
                    vulnData = []
                    if item.get('customUUID') == num:
                        if v['exportIncludeExemptedPlugins'] == True or item.get('exempt') != "True":
                            vulnData.append(item.get('ip'))
                            vulnData.append(item.get('pluginID'))
                            vulnData.append(item.get('severity').get('name'))
                            if v['exportACASNotes'] == True:
                                vulnData.append(item.get('notes'))
                            if v['exportIncludeACASReason'] == True:
                                vulnData.append(item.get('reason'))
                            if v['exportIncludeACASExemption'] == True:
                                vulnData.append(item.get('exempt'))
                            csvWriter.writerow(vulnData)
                    vulnData.clear()
    # print(toWrite)
    # newList = [toWrite, vulnData]
    # csvWriter.writerows(newList)


def getPlugin(pluginID):
    pluginInfo = sc.plugins.details(pluginID, fields=['id', 'name', 'description', 'severity', 'solution'])
    return pluginInfo


def afunc(parameter):
    possibleParams = ['ip', 'severity']

    testParams = "ip=192.168.0.121&severity=low"

    splParam = testParams.split("&")
    print(splParam)

    buildFunc = ""
    for x in splParam:
        fin = x.split("=")
        buildFunc = buildFunc + "('{}', '=', '{}'),".format(fin[0], fin[1])
        print(buildFunc)  # wow this worked cool

    av = sc.analysis.vulns(("{}".format(buildFunc)))

    mainWindow['resultML'].update(av)
    Sg.show_debugger_window()


def getSeverity(sc, sev):
    vulnList = []

    analysisVulns = sc.analysis.vulns(('severity', '=', sev))
    print(analysisVulns.next())
    print(analysisVulns)
    for vuln in analysisVulns:
        vulnList.append('{ip}:{pluginID}:{pluginName}:{severity}'.format(**vuln) + "\n")

    return vulnList


def getVulnsSubnet(sc, ip, sev):
    vulnList = []

    analysisVulns = sc.analysis.vulns(('ip', '=', "{}".format(ip)), ('severity', '=', sev))
    # print(analysisVulns.next())
    print(analysisVulns)
    for vuln in analysisVulns:
        vulnList.append('{ip}:{pluginID}:{pluginName}:{severity}'.format(**vuln) + "\n")

    return vulnList


def getVulns(sc, ip, sev):
    vulnList = []

    analysisVulns = sc.analysis.vulns(('ip', '=', str(ip)),
                                      ('severity', '=', sev))
    print(analysisVulns.next())
    print(analysisVulns)
    for vuln in analysisVulns:
        vulnList.append('{ip}:{pluginID}:{pluginName}:{severity}'.format(**vuln) + "\n")

    return vulnList


def getVulnsList(sc, ip, sev):
    vulnList = []

    try:
        analysisVulns = list(sc.analysis.vulns(('ip', '=', str(ip)),
                                               ('severity', '=', sev)))
    except:
        pass

    for item in analysisVulns:
        print(item.get('pluginID'))
        vulnList.append(item)

    f = open('configs/vulnIdentity.json')
    data = json.load(f)
    f.close()

    for item in vulnList:
        found = False
        while not found:
            for value in data:
                if item.get('ip') == data[value][0].get("ip") and item.get('pluginID') == data[value][0].get(
                        'pluginID'):
                    item['customUUID'] = str(value)
                    item['notes'] = data[value][0].get('notes')
                    item['exempt'] = data[value][0].get('exempt')
                    item['reason'] = data[value][0].get('reason')
                    found = True
                    break
            if not found:
                newID = str(uuid4())
                data[newID] = [{"ip": item.get('ip'), "pluginID": item.get('pluginID'), "notes": "", "exempt": False,
                                "reason": ""}]
                item['customUUID'] = newID
                item['notes'] = data[value][0].get('notes')
                item['exempt'] = data[value][0].get('exempt')
                item['reason'] = data[value][0].get('reason')
                found = True

    toDump = data
    json_object = json.dumps(toDump, indent=4)
    with open("configs/vulnIdentity.json", "w") as outFile:
        outFile.write(json_object)

    return vulnList


def addVulnUUID(vSphereList: list):
    for item in vSphereList:
        item['vulnUUID'] = []

    f = open('configs/vulnIdentity.json')
    data = json.load(f)
    f.close()

    for item in vSphereList:
        for value in data:
            if item.get('IP Address') == data[value][0].get("ip"):
                item.get("vulnUUID").append(str(value))
    return vSphereList


def getUUID(lines):
    temp = []  # turn query into list by each line
    query = str(lines).splitlines()
    for line in query:
        temp.append(line.split(":"))
    idList = []

    for item in temp:
        idList.append(item[-1])
    return idList


def getExempt(lines):
    temp = []  # turn query into list by each line
    query = str(lines).splitlines()
    for line in query:
        temp.append(line.split(":"))
    exList = []

    for item in temp:
        exList.append(item[-2])
    return exList


def getReasons(lines):
    temp = []
    query = str(lines).splitlines()

    for line in query:
        temp.append(line.split("|"))
    reasons = []
    for item in temp:
        reasons.append(item[3])
    return reasons


def getNotes(lines):
    temp = []
    query = str(lines).splitlines()

    for line in query:
        temp.append(line.split("|"))
    notes = []
    for item in temp:
        notes.append(item[1])
    return notes


def saveFields(lines):
    try:
        notes = getNotes(lines)
        exList = getExempt(lines)
        ids = getUUID(lines)
        reasons = getReasons(lines)

        f = open('configs/vulnIdentity.json')
        data = json.load(f)
        f.close()
        for i in range(len(ids)):
            data[ids[i]][0]['notes'] = notes[i]
            data[ids[i]][0]['exempt'] = exList[i]
            data[ids[i]][0]['reason'] = reasons[i]

        toDump = data
        json_object = json.dumps(toDump, indent=4)
        with open("configs/vulnIdentity.json", "w") as outFile:
            outFile.write(json_object)
    except IndexError:
        Sg.popup_ok("Error, a | was removed, please re-query to fix")


def saveFieldsvSphere(lines):
    try:
        notes = getNotes(lines)
        ids = getUUID(lines)
        impact = getImpact(lines)
        reasons = getReasons(lines)

        f = open('configs/vmIdentity.json')
        data = json.load(f)
        f.close()
        for i in range(len(ids)):
            data[ids[i]][0]['notes'] = notes[i]
            data[ids[i]][0]['quarantine_impact'] = impact[i]
            data[ids[i]][0]['reason'] = reasons[i]

        toDump = data
        json_object = json.dumps(toDump, indent=4)
        with open("configs/vmIdentity.json", "w") as outFile:
            outFile.write(json_object)
    except IndexError:
        Sg.popup_ok("Error, a | was removed, please re-query to fix")


def saveNotesAll(lines, newNote, file_path: str):
    try:
        ids = getUUID(lines)

        f = open(file_path)
        data = json.load(f)
        f.close()

        for i in range(len(ids)):
            data[ids[i]][0]['notes'] = newNote

        toDump = data
        json_object = json.dumps(toDump, indent=4)
        with open(file_path, "w") as outFile:
            outFile.write(json_object)
    except IndexError:
        Sg.popup_ok("Error, a | was removed, please re-query to fix")


def saveReasonsAll(lines, newReason, file_path: str):
    try:
        ids = getUUID(lines)

        f = open(file_path)
        data = json.load(f)
        f.close()

        for i in range(len(ids)):
            data[ids[i]][0]['reason'] = newReason

        toDump = data
        json_object = json.dumps(toDump, indent=4)
        with open(file_path, "w") as outFile:
            outFile.write(json_object)
    except IndexError:
        Sg.popup_ok("Error, a | was removed, please re-query to fix")


def saveExemptAll(lines, newExempt, file_path: str):
    try:
        ids = getUUID(lines)

        f = open(file_path)
        data = json.load(f)
        f.close()

        for i in range(len(ids)):
            data[ids[i]][0]['exempt'] = newExempt

        toDump = data
        json_object = json.dumps(toDump, indent=4)
        with open(file_path, "w") as outFile:
            outFile.write(json_object)
    except IndexError:
        Sg.popup_ok("Error, a | was removed, please re-query to fix")


def saveImpactAll(lines, newImpact, file_path: str):
    try:
        ids = getUUID(lines)

        f = open(str(file_path))
        data = json.load(f)
        f.close()

        for i in range(len(ids)):
            data[ids[i]][0]['quarantine_impact'] = newImpact

        toDump = data
        json_object = json.dumps(toDump, indent=4)
        with open(file_path, "w") as outFile:
            outFile.write(json_object)
    except IndexError:
        Sg.popup_ok("Error, a | was removed, please re-query to fix")


def updateList(vulnList: list):
    f = open('configs/vulnIdentity.json')
    data = json.load(f)
    f.close()

    for item in vulnList:
        found = False
        while not found:
            for value in data:
                if item.get('ip') == data[value][0].get("ip") and item.get('pluginID') == data[value][0].get(
                        'pluginID'):
                    item['customUUID'] = str(value)
                    item['notes'] = data[value][0].get('notes')
                    item['exempt'] = data[value][0].get('exempt')
                    item['reason'] = data[value][0].get('reason')
                    found = True
                    break
            if found != True:
                newID = str(uuid4())
                data[newID] = [{"ip": item.get('ip'), "pluginID": item.get('pluginID'), "notes": "", "exempt": False,
                                "reason": "none"}]
                item['customUUID'] = newID
                item['notes'] = data[value][0].get('notes')
                item['exempt'] = data[value][0].get('exempt')
                item['reason'] = data[value][0].get('reason')
                found = True
    return vulnList


def updateVMList(vmList: list):
    f = open('configs/vmIdentity.json')
    data = json.load(f)
    f.close()

    for item in vmList:
        found = False
        while not found:
            for value in data:
                if item.get('IP Address') == data[value][0].get("ip"):
                    item['customUUID'] = str(value)
                    item['notes'] = data[value][0].get('notes')
                    item['reason'] = data[value][0].get('reason')
                    item['quarantine_impact'] = data[value][0].get('quarantine_impact')
                    found = True
                    break
            if found != True:
                newID = str(uuid4())
                data[newID] = [{"ip": item.get('IP Address'), "notes": "", "reason": "", "quarantine_impact": ""}]
                item['customUUID'] = newID
                item['notes'] = data[value][0].get('notes')
                item['reason'] = data[value][0].get('reason')
                item['quarantine_impact'] = data[value][0].get('quarantine_impact')
                found = True
    return vmList


def updateVMDict(vmDict: dict):
    f = open('configs/vmIdentity.json')
    data = json.load(f)
    f.close()

    for key in vmDict:
        found = False
        while not found:
            for value in data:
                if vmDict[key].get('IP Address') == data[value][0].get("ip"):
                    vmDict[key]['customUUID'] = str(value)
                    vmDict[key]['notes'] = data[value][0].get('notes')
                    vmDict[key]['reason'] = data[value][0].get('reason')
                    vmDict[key]['quarantine_impact'] = data[value][0].get('quarantine_impact')
                    found = True
                    break
            if found != True:
                newID = str(uuid4())
                data[newID] = [{"ip": item.get('IP Address'), "notes": "", "reason": "", "quarantine_impact": ""}]
                vmDict[key]['customUUID'] = newID
                vmDict[key]['notes'] = data[value][0].get('notes')
                vmDict[key]['reason'] = data[value][0].get('reason')
                vmDict[key]['quarantine_impact'] = data[value][0].get('quarantine_impact')
                found = True
    return vmDict


def getImpact(lines):
    temp = []
    query = str(lines).splitlines()

    for line in query:
        temp.append(line.split("|"))
    notes = []
    for item in temp:
        notes.append(item[5])
    return notes


def clearWindow():
    mainWindow['resultML'].update('', append=False)
    return "Complete"


def autoClear():
    if v['autoClear'] == True:
        mainWindow['resultML'].update("")


def email(data, sender, receiver):
    emailAsStrings = data
    mailServer = smtplib.SMTP('192.168.0.14', 25)
    body = MIMEText(emailAsStrings)
    mailServer.sendmail("{}".format(sender), "{}".format(receiver), body.as_string())
    print("Sent email")
    loggy("Sent Email", "INFO")


def emailDoc(filePaths: list, sender: str, receiver: str, subject: str):
    mailServer = smtplib.SMTP('192.168.15.14', 25)
    message = MIMEMultipart()
    message['From'] = sender
    message['To'] = receiver
    message['Subject'] = subject

    message.attach(MIMEText('See your saved CSV documents: ', 'plain'))
    for filePath in filePaths:
        attachment = MIMEBase('application', "octet-stream")
        attachment.set_payload(open(filePath, "rb").read())
        encoders.encode_base64(attachment)
        fileNames = filePath.split("/")
        fileName = fileNames[-1]
        print(fileName)
        attachment.add_header('Content-Decomposition', 'attachment', filename=str(fileName))
        attachment['Content-Disposition'] = 'attachment; filename={}'.format(fileName)

        message.attach(attachment)

    text = message.as_string()

    mailServer.sendmail("{}".format(sender), "{}".format(receiver), text)
    print("Sent email")
    loggy("Sent Solutionizer Email With Attachments", "INFO")


def tab(i):
    return [[Sg.Text(f'Parser {i}')], [Sg.Multiline('', size=(140, 25), key=f'Input {i}')]]


def loadConfig():
    try:
        with open("configs/acasTool.config", "r") as config:
            config = json.load(config)
            mainWindow['sendParser'].update(config['parser'])
            mainWindow['scanRepoID'].update(config['scanRepoID'])
            mainWindow['name'].update(config['name'])
            mainWindow['description'].update(config['description'])
            # mainWindow['email_complete'].update(config['email_complete'])
            # mainWindow['email_launch'].update(config['email_launch'])
            # mainWindow['max_time'].update(config['max_time'])
            mainWindow['policy_id'].update(config['policy_id'])
            # mainWindow['scan_zone'].update(config['scan_zone'])
            mainWindow['targets'].update(config['targets'])
            # mainWindow['vhosts'].update(config['vhosts'])
            mainWindow['cloudStopWords'].update(config['cloudStopWords'])
            mainWindow['emailSender'].update(config['emailSender'])
            mainWindow['emailRecipient'].update(config['emailRecipient'])
            mainWindow['autoClear'].update(config['autoClear'])
            # mainWindow['logDIR'].update(config['logDirectory'])
            mainWindow['scanCreds'].update(config['scanCreds'])
            mainWindow['APIkey'].update(config['APIkey'])
            mainWindow['APIsec'].update(config['APIsec'])
            mainWindow['vSphereUN'].update(config['vSphereUN'])
            mainWindow['vSpherePW'].update(config['vSpherePW'])
            if config['vSpherePluginEnabled'] == 1:
                # vSpherePluginEnabled = True # TODO: add saving config for vsphere / window element
                mainWindow['vSphereAPIEnabled'].Update(config['vSpherePluginEnabled'])
            else:
                # vSpherePluginEnabled = False
                mainWindow['vSphereAPIEnabled'].Update(value=False)
    except:
        loggy("Could not Load Configs", "ERROR")

    # configs["cloudStopWords"] = v["cloudStopWords"]
    # mainWindow["emailSender"].update(config["emailSender"])
    # mainWindow["emailRecipient"].update(config["emailRecipient"])
    # configs['autoClear'] = v['autoClear']
    # configs['logDirectory'] = v['logDIR']


def loadScanConfig():
    try:
        with open("configs/acasTool.config", "r") as config:
            config = json.load(config)
            mainWindow['scanRepoID'].update(config['scanRepoID'])
            mainWindow['name'].update(config['name'])
            mainWindow['description'].update(config['description'])
            # mainWindow['email_complete'].update(config['email_complete'])
            # mainWindow['email_launch'].update(config['email_launch'])
            # mainWindow['max_time'].update(config['max_time'])
            mainWindow['policy_id'].update(config['policy_id'])
            # mainWindow['scan_zone'].update(config['scan_zone'])
            mainWindow['targets'].update(config['targets'])
            # mainWindow['vhosts'].update(config['vhosts'])
            mainWindow['scanCreds'].update(config['scanCreds'])
    except:
        loggy("Could not Load Scan Configs", "ERROR")


def saveScanConfig():
    try:
        with open("configs/acasTool.config") as config:
            configs = json.load(config)
            configs['scanRepoID'] = v['scanRepoID']
            configs['name'] = v['name']
            configs['description'] = v['description']
            # configs['email_complete'] = v['email_complete']
            # configs['email_launch'] = v['email_launch']
            # configs['max_time'] = v['max_time']
            configs['policy_id'] = v['policy_id']
            # configs['scan_zone'] = v['scan_zone']
            configs['targets'] = v['targets']
            # configs['vhosts'] = v['vhosts']
            configs['scanCreds'] = v['scanCreds']
        saveTo = open('acasTool.config', "w+")
        json.dump(configs, saveTo)
        saveTo.close()
    # loggy("Saved Scan Configs", "INFO")
    except:
        loggy("Could not Save Scan Configs", "ERROR")


def saveConfig():
    try:
        with open("configs/acasTool.config") as config:
            configs = json.load(config)
            configs['scanRepoID'] = v['scanRepoID']
            configs['name'] = v['name']
            configs['description'] = v['description']
            # configs['email_complete'] = v['email_complete']
            # configs['email_launch'] = v['email_launch']
            # configs['max_time'] = v['max_time']
            configs['policy_id'] = v['policy_id']
            # configs['scan_zone'] = v['scan_zone']
            configs['targets'] = v['targets']
            # configs['vhosts'] = v['vhosts']
            configs["cloudStopWords"] = v["cloudStopWords"]
            configs["emailSender"] = v["emailSender"]
            configs["emailRecipient"] = v["emailRecipient"]
            configs['autoClear'] = v['autoClear']
            # configs['logDirectory'] = v['logDIR']
            configs['scanCreds'] = v['scanCreds']
            # config['cloudStopWords'] = v['cloudStopWords']
            configs['APIkey'] = v['APIkey']
            configs['APIsec'] = v['APIsec']
            configs['vSpherePluginEnabled'] = v['vSphereAPIEnabled']
            configs['vSphereUN'] = v['vSphereUN']
            configs['vSpherePW'] = v['vSpherePW']

        saveTo = open('acasTool.config', "w+")
        json.dump(configs, saveTo)
        saveTo.close()
    # loggy("Saved Configs", "INFO")
    except:
        loggy("Could not Save Configs", "ERROR")


index = 0  # tracking index for new parser tabz
indexList = []
saveSearch = False
saveSearch2 = False
sendParser = False
sendParser2 = False

defaultStopWords = """Medium'""", "Critical", "Multiple Vulnerabilities", "Medium", """Low'""", """4'""", """1'""", """3'""", """2'""", """critical'""", "low", "high", "High'", "2", """description'""", "the", "name'", """Severity'""", """id'"""
generatedTabs = False

basicConfig(filename='acas.log', level=logging.INFO)
logging.info(" {} Launched AQT".format(datetime.date.today()))


def testButtons():
    x = range(0, 5)
    xList = []
    for y in x:
        xList.append(Sg.Button("", size=(1, 1), border_width=0))
    return xList


def getIPVM(lines):
    temp = []  # turn query into list by each line
    query = str(lines).splitlines()
    for line in query:
        temp.append(line.split(":"))
    exList = []

    for item in temp:
        exList.append(item[0])
    return exList


def clearSearchItems(search, listVulns):
    sorted = []
    if len(search) > 0:
        for entry in listVulns:
            current = '{ip}:{pluginID}:{pluginName}:'.format(**entry) + entry.get('severity').get(
                'name') + ':notes: |' + entry.get('notes') + "|" + ':reason: |' + entry.get('reason') + "|"

            # sev = entry.get('severity').get('name')
            # 		mainWindow['resultML'].update('{ip}:{pluginID}:{pluginName}'.format(**entry) + ":" + sev, append=True)
            # 		mainWindow['resultML'].update(':notes: |' + entry.get('notes') + "|", append=True)
            # 		mainWindow['resultML'].update(':reason: |' + entry.get('reason') + "|", append=True)
            # 		mainWindow['resultML'].update(':{exempt}:{customUUID}'.format(**entry) + '\n', append=True)
            if str(current).find(search) == -1:
                sorted.append(entry)
        print("finished search")
        return sorted
    else:
        return listVulns


def clearvSphereSearchItems(search: str, vmList: list):
    sorted = []
    if len(search) > 0:
        for item in vmList:
            current = '{IP Address}:{name}:{host_name}:{guest_os}:{power_state}'.format(
                **item) + ':notes: |' + item.get('notes') + "|" + ':reason: |' + item.get(
                'reason') + "|" + ':quarantine_impact: |' + item.get('quarantine_impact') + "|"
            # mainWindow['vSphereML'].update('{IP Address}:{name}:{host_name}:{guest_os}:{power_state}'.format(**item), append=True)
            # mainWindow['vSphereML'].update(':notes: |' + item.get('notes') + "|", append=True)
            # mainWindow['vSphereML'].update(':reason: |' + item.get('reason') + "|", append=True)
            # mainWindow['vSphereML'].update(':quarantine_impact: |' + item.get('quarantine_impact') + "|", append=True)
            # mainWindow['vSphereML'].update(":" + str(item.get("customUUID")) + "\n", append=True)
            if str(current).find(search) == -1:
                sorted.append(item)
        print("finished search")
        return sorted
    else:
        return vmList


def filterSolution(vulns: list, search: str):
    output = []
    for vuln in vulns:
        if str(vuln.get("solution")).find(search) != -1:
            output.append(vuln)

    return output


def getSuggestions(vulns: list, simple: list, intermediate: list, hard: list, insane: list):
    suggestions = {'simple': [], 'intermediate': [], 'hard': [], 'insane': [], 'unknown': []}

    for item in vulns:
        found = False
        while not found:
            if not found:
                for key in insane:
                    if str(item.get('solution').lower()).find(key.lower()) > 0:
                        suggestions.get('insane').append(item)
                        found = True
                        break
            if not found:
                for key in hard:
                    if str(item.get('solution').lower()).find(key.lower()) > 0:
                        suggestions.get('hard').append(item)
                        found = True
                        break
            if not found:
                for key in intermediate:
                    if str(item.get('solution').lower()).find(key.lower()) > 0:
                        suggestions.get('intermediate').append(item)
                        found = True
                        break
            if not found:
                for key in simple:
                    print("Simple Key: {}".format(key))
                    if str(item.get('solution').lower()).find(key.lower()) > 0:
                        suggestions.get('simple').append(item)
                        found = True
                        break

            if found == False:
                suggestions.get('unknown').append(item)
                found = True

    return suggestions


def updateKeys(dropDown, fileName: str, value: str, updateType: int):
    if updateType == 0:
        with open(fileName, 'r') as keys:
            lines = keys.readlines()
        with open(fileName, "w") as keys:
            for line in lines:
                if line.strip() != str(value):
                    keys.write(line)
        with open(fileName, 'r') as keys:
            listKeys = []
            for line in keys:
                listKeys.append(line.strip())
            dropDown.update(values=listKeys)

            listKeys.reverse()
            dropDown.update(values=listKeys)

    if updateType == 1:
        with open(fileName, 'r+') as keys:
            if len(value) > 0:
                keys.write("\n{}".format(value))
                # x = searchCache.read()
                newList = []
                # solSearches = []
                for line in keys:
                    newList.append(line)
                # solSearches.append("{}".format(line.strip()))
                newList.append(value)
                # print(solSearches)
                newList.reverse()
                dropDown.update(values=newList)

    return ('completed update')


def functionalityCheck(action: str):
    errors = {
        "ACASConnection": "You are not connected to ACAS, please click the 'outlet'.",
        "emptyList": "Unable to send, nothing in list"
    }

    if action == "IP Address":
        try:
            if sc == TenableSC:
                return 1
            else:
                return 1
        except NameError:
            return errors.get('ACASConnection')
    if action == "Plugin ID":
        try:
            if sc == TenableSC:
                return 1
            else:
                return 1
        except NameError:
            return errors.get('ACASConnection')
    if action == "Send to":
        try:
            if len(mainWindowList) > 0:
                return 1
            else:
                return 1
        except NameError:
            return errors.get('emptyList')


# 	return filtered

def getIPList(outputList: list):
    addresses = []
    for item in outputList:
        if item.get('ip') not in addresses:
            addresses.append(item.get('ip'))
    return addresses


class Data(object):
    def __init(self):
        self.x = 1

    def save():
        pass

    def load():
        pass

    def saveScan():
        pass

    def loadScan():
        pass


def convertCSV(output: list, filepath: str):  # ACAS export
    with open(filepath, 'w') as csvfile:
        csvWriter = csv.writer(csvfile)
        csvWriter.writerow(['ip', 'pluginID', 'solution', 'severity'])
        toWrite = []
        for item in output:
            toWrite.append(item.get('ip'))
            toWrite.append(item.get('pluginID'))
            toWrite.append(item.get('solution'))
            toWrite.append(item.get('severity').get('name'))
            csvWriter.writerow(toWrite)
            toWrite.clear()


def convertAll(output: list, output2: list, filepath: str):
    with open(filepath, 'w') as csvfile:
        csvWriter = csv.writer(csvfile)
        csvWriter.writerow(
            ['ip', 'name', 'hostname', 'Plugin ID', 'Solution', 'Severity', 'guest_os', 'power_state', 'ACAS Notes',
             'vSphere Notes', 'ACAS Reason', 'vSphere Reason', 'quarantine_impact', 'ACAS Exempt', 'vSphere Exempt'])

        toWrite = []
        for item in output:
            toWrite.append(item.get('IP Address'))
            toWrite.append(item.get('name'))
            toWrite.append(item.get('host_name'))
            toWrite.append(item.get('guest_os'))
            toWrite.append(item.get('power_state'))
            toWrite.append(item.get('notes'))
            toWrite.append(item.get('reason'))
            toWrite.append(item.get('quarantine_impact'))
            csvWriter.writerow(toWrite)
            toWrite.clear()

        for item in output2:
            toWrite.append(item.get('ip'))
            toWrite.append(item.get('pluginID'))
            toWrite.append(item.get('solution'))
            toWrite.append(item.get('severity').get('name'))
            toWrite.append(item.get('notes'))
            toWrite.append(item.get('reason'))
            toWrite.append(item.get('exempt'))
            csvWriter.writerow(toWrite)
            toWrite.clear()


def convertvSphereCSV(output: list, filepath: str):  # vSphere Export
    with open(filepath, 'w') as csvfile:
        csvWriter = csv.writer(csvfile)
        csvWriter.writerow(
            ['ip', 'name', 'hostname', 'guest_os', 'power_state', 'notes', 'reason', 'quarantine_impact'])

        toWrite = []
        for item in output:
            toWrite.append(item.get('IP Address'))
            toWrite.append(item.get('name'))
            toWrite.append(item.get('host_name'))
            toWrite.append(item.get('guest_os'))
            toWrite.append(item.get('power_state'))
            toWrite.append(item.get('notes'))
            toWrite.append(item.get('reason'))
            toWrite.append(item.get('quarantine_impact'))
            csvWriter.writerow(toWrite)
            toWrite.clear()


def convertDifCSV(output: dict, filepath: str):
    with open(filepath, 'w') as csvfile:
        csvWriter = csv.writer(csvfile)
        csvWriter.writerow(['ip', 'pluginID', 'solution', 'difficulty', 'severity'])
        toWrite = []

        for item in output.get('simple'):
            toWrite.append(item.get('ip'))
            toWrite.append(item.get('pluginID'))
            toWrite.append(item.get('solution'))
            toWrite.append('easy')
            toWrite.append(item.get('severity').get('name'))
            csvWriter.writerow(toWrite)
            toWrite.clear()
        for item in output.get('intermediate'):
            toWrite.append(item.get('ip'))
            toWrite.append(item.get('pluginID'))
            toWrite.append(item.get('solution'))
            toWrite.append('intermediate')
            toWrite.append(item.get('severity').get('name'))
            csvWriter.writerow(toWrite)
            toWrite.clear()
        for item in output.get('hard'):
            toWrite.append(item.get('ip'))
            toWrite.append(item.get('pluginID'))
            toWrite.append(item.get('solution'))
            toWrite.append('hard')
            toWrite.append(item.get('severity').get('name'))
            csvWriter.writerow(toWrite)
            toWrite.clear()
        for item in output.get('insane'):
            toWrite.append(item.get('ip'))
            toWrite.append(item.get('pluginID'))
            toWrite.append(item.get('solution'))
            toWrite.append('insane')
            toWrite.append(item.get('severity').get('name'))
            csvWriter.writerow(toWrite)
            toWrite.clear()
        for item in output.get('unknown'):
            toWrite.append(item.get('ip'))
            toWrite.append(item.get('pluginID'))
            toWrite.append(item.get('solution'))
            toWrite.append('unknown')
            toWrite.append(item.get('severity').get('name'))
            csvWriter.writerow(toWrite)
            toWrite.clear()


def loggy(functionality, level):
    now = datetime.datetime.now()
    currentTime = now.strftime("%H:%M:%S")
    if level == "INFO":
        logging.info("{}, {}, {}".format(currentTime, datetime.date.today(), functionality))

    if level == "ERROR":
        logging.error("{}, {}, {}".format(currentTime, datetime.date.today(), functionality))

    if level == "WARNING":
        logging.warning("{}, {}, {}".format(currentTime, datetime.date.today(), functionality))

    mainWindow['logML'].update("{}, {}, {}, {}\n".format(currentTime, level, datetime.date.today(), functionality),
                               append=True)


def draw_figure(canvas, figure):
    figure_canvas_agg = FigureCanvasTkAgg(figure, canvas)
    figure_canvas_agg.draw()
    figure_canvas_agg.get_tk_widget().pack(side='top', fill='both', expand=1)
    return figure_canvas_agg


# VSPHERE data needed: [VM NAME, IP, PORTGROUP (NIC), GUEST OS, FOLDER, DATASTORE, TECHNICAL CONTACT]
class vSphere(object):
    def __init__(self):

        self.actionList = {

            "Get Guest Info": lambda: vsphere_client.vcenter.vm.guest.Identity.get(vm),
            "Get CPU Data": lambda: vsphere_client.vcenter.vm.hardware.Cpu.get(vm),
            "Get VM Disks": lambda: vsphere_client.vcenter.vm.hardware.Disk.list(vm),
            "Get Network Adapters": lambda: vsphere_client.vcenter.vm.hardware.Ethernet.list(vm),
            "Connect Network Adapters": lambda: vsphere_client.vcenter.vm.hardware.Ethernet.connect(vm, nic),
            "Disconnect Network Adapters": lambda: vsphere_client.vcenter.vm.hardware.Ethernet.disconnect(vm, nic),
            "Get Power State": lambda: vsphere_client.vcenter.vm.Power.get(vm),
            "Reboot Guest": lambda: vsphere_client.vcenter.vm.guest.Power.reboot(vm),
            "Shutdown Guest": lambda: vsphere_client.vcenter.vm.Power.shutdown(vm),
            "Power On VM": lambda: vsphere_client.vcenter.vm.Power.start(vm),
            "Power Off VM": lambda: vsphere_client.vcenter.vm.Power.stop(vm),
            "Suspend VM": lambda: vsphere_client.vcenter.vm.Power.suspend(vm),
            "Reset VM": lambda: vsphere_client.vcenter.vm.Power.reset(vm)

        }

        self.actionList2 = [

            "Get Guest Info",
            "Get VM Disks",
            "Get Network Adapters",
            "Connect Network Adapters",
            "Disconnect Network Adapters",
            "Get Power State",
            "Reboot Guest",
            "Shutdown Guest",
            "Power On VM",
            "Power Off VM",
            "Suspend VM",
            "Reset VM",
            "Get Memory",
            "Update Memory",
            "Get CPU Data",
            "Update CPU"

        ]

        loggy("Loaded VSphere Plugin Object", "INFO")

    def vConnect(self, UN, PW, server):
        self.vUN = UN
        self.vPW = PW
        self.vServer = server
        self.vConnected = False
        self.sshConn = False
        self.sshConn = False

        self.session = self.requests.session()
        self.session.verify = False
        self.urllib3.disable_warnings(self.urllib3.exceptions.InsecureRequestWarning)
        try:
            self.vsphere_client = self.vsphere_client_lib.create_vsphere_client(server=self.vServer, username=self.vUN,
                                                                                password=self.vPW, session=self.session)
        except:
            Sg.popup_ok("Unable to connect to VSphere, check creds")
        # self.vsphere_client = self.vsphere_client_lib.create_vsphere_client(server=self.vServer, username=self.vUN, password=self.vPW, session=self.session)
        self.connected = True

        loggy("Connected to VSphere", "INFO")

    def enableVSphere(self):
        from importlib import import_module
        self.requests = import_module("requests")
        self.urllib3 = import_module("urllib3")
        self.paramiko = import_module("paramiko")

        self.vsphere_client_lib = import_module("vmware.vapi.vsphere.client")
        self.v = import_module("com.vmware.vcenter_client")
        self.VM = self.v.VM
        self.VM2 = import_module("com.vmware.vcenter_client")
        from com.vmware.vcenter.vm_client import Power
        from com.vmware.vcenter.vm.hardware.adapter_client import Sata
        from com.vmware.vcenter.vm.hardware_client import Disk
        from com.vmware.vcenter.vm.hardware_client import Ethernet
        from com.vmware.vcenter_client import Network
        from com.vmware.vcenter.vm.hardware_client import (IdeAddressSpec,
                                                           SataAddressSpec,
                                                           ScsiAddressSpec)
        from com.vmware.vcenter_client import VM
        loggy("Imported VSphere Plugin", "INFO")

    # VSPHERE SETUP:

    def listAllVMs(self):  # test, works
        from com.vmware.vcenter_client import VM
        self.vmList = self.vsphere_client.vcenter.VM.list()
        dictVersion = {}
        vSphereVMsPoweredOff = 0

        for v in self.vmList:
            vms = self.vsphere_client.vcenter.VM.list(VM.FilterSpec(names=set([v.name])))
            # print(vms)
            vm = vms[0].vm
            try:
                guest_info = self.vsphere_client.vcenter.vm.guest.Identity.get(vm)
                dictVersion[str(guest_info.ip_address)] = {}
                dictVersion[str(guest_info.ip_address)]['IP Address'] = str(guest_info.ip_address)
                dictVersion[str(guest_info.ip_address)]['name'] = str(v.name)
                dictVersion[str(guest_info.ip_address)]['host_name'] = str(guest_info.host_name)
                dictVersion[str(guest_info.ip_address)]['guest_os'] = str(guest_info.name)
                dictVersion[str(guest_info.ip_address)]['power_state'] = str(v.power_state)

                f = open('configs/vmIdentity.json')
                data = json.load(f)
                f.close()

                outputList = []
                for key in dictVersion:
                    outputList.append(dictVersion[key])

                for item in outputList:
                    found = False
                    while not found:
                        for value in data:
                            if item.get('IP Address') == data[value][0].get("ip"):
                                item['customUUID'] = str(value)
                                item['notes'] = data[value][0].get('notes')
                                item['reason'] = data[value][0].get('reason')
                                item['quarantine_impact'] = data[value][0].get('quarantine_impact')
                                found = True
                                break
                        if found != True:
                            newID = str(uuid4())
                            data[newID] = [
                                {"ip": item.get('IP Address'), "notes": "", "reason": "", "quarantine_impact": ""}]
                            item['customUUID'] = newID
                            item['notes'] = data[value][0].get('notes')
                            item['reason'] = data[value][0].get('reason')
                            item['quarantine_impact'] = data[value][0].get('quarantine_impact')
                            found = True

                toDump = data
                json_object = json.dumps(toDump, indent=4)
                with open("configs/vmIdentity.json", "w") as outFile:
                    outFile.write(json_object)


            except:
                vSphereVMsPoweredOff += 1
                pass
            # vSphereVMsPoweredOff += 1
            # print("Unable to Query Guest Info for {}\n".format(v.name))
        tupleVersion = (outputList, dictVersion, vSphereVMsPoweredOff)
        return tupleVersion

    def findIPs(self):  # find and list available IP's
        loggy("Started Find IP Routine", "INFO")
        ipList = []
        for v in self.vmList:
            vms = self.vsphere_client.vcenter.VM.list(self.VM.FilterSpec(names=set([v.name])))
            # print(vms)
            vm = vms[0].vm
            try:
                guest_info = self.vsphere_client.vcenter.vm.guest.Identity.get(vm)
                ipList.append(guest_info.ip_address)
            except:
                print("Cannot get Guest Info")

        newList = []
        numberList = []

        for x in ipList:
            if "." in x:
                if ".46." in x:
                    # print(x.split(".")[3])
                    newList.append(x.split(".")[3])
                # print(newList)

        mainWindow['vSphereML'].update("Online IP's: >{}<: {}\n\n".format(len(newList), newList), append=True)

        for y in range(2, 255):
            numberList.append(y)

        print(newList)
        print(numberList)

        finalList = []

        for u in numberList:
            if str(u) not in newList:
                finalList.append(str(u))

        mainWindow['vSphereML'].update("Available IP's: >{}<: {}\n\n".format(len(finalList), finalList), append=True)
        loggy("Find IP Complete, {} Online, {} Free".format(len(newList), len(finalList)), "INFO")


def analyze(v, mainWindow):  # this counts things in the output to display
    print(v)
    print(mainWindow['resultML'])
    print(mainWindow)
    print(v['resultML'])
    # sleep(2)
    ipPattern = re.compile(
        r'^(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    ipList = []
    for line in v['resultML'].splitlines():
        ipList.append(ipPattern.search(v['resultML']))

    lows = v['resultML'].count("Low")
    meds = v['resultML'].count("Medium")
    highs = v['resultML'].count("High")
    crits = v['resultML'].count("Critical")
    exempts = v['resultML'].count("True")
    # print(lows)
    # crits = v['resultML'].count("Critical")

    # print(ipList)
    strippedDupes = list(set(ipList))
    noIPDupes = len(strippedDupes)
    # print(strippedDupes)

    # PLUGINS:

    pluginList = []
    for line in v['resultML'].splitlines():
        y = line.split(":")
        z = y[1].split(" ")
        # pluginList.append(z)
        # print(z[0])
        pluginList.append(z[0])
    totalPlugins = len(pluginList)
    noDupes = list(set(pluginList))
    totalUniquePlugins = len(noDupes)

    mainWindow['analyzeText'].update(
        "IP's: {}, Unique IP's: {}, Plugins: {}, Unique Plugins: {}, Lows: {}, Meds: {}, Highs: {}, Crits: {}, Exempts: {}".format(
            len(ipList), noIPDupes, totalPlugins, totalUniquePlugins, lows, meds, highs, crits, exempts))


def tab(i):  # this is for generating new tabs on queries
    return [[Sg.Multiline("", key=f'parserML{index}', size=(140, 25), horizontal_scroll=True)],
            [Sg.Button(f'Save Parsed Output{index}'), Sg.Button(f'Email Parsed Output{i}'),
             Sg.Button("Remove Tab", key=f'removeTab{index}')]]


# vulnList.append('{ip}:{pluginID}:{pluginName}:{severity}'.format(**vuln) + "\n")

def make_window(oldLoc, opacity=0.95, theme=None):
    clearTab = [[Sg.Multiline("", key="resultML", size=(140, 25), horizontal_scroll=True)]]
    csvTab = [[Sg.Column([[Sg.Table(values=[
        ["192.168.46.252", "42873", "SSL Medium Strength Ciper Suites Supported SWEET32", "Medium", "IGNORE",
         "TC2 Exemption", "JOMIS"],
        ["192.168.46.252", "57608", "SMB Signing not Required", "Medium", "Need Fix", "None", "JOMIS"]],
                                    headings=["IP Address", "PORT", "Description", "Severity", "Notes", "Reason",
                                              "Repository"],
                                    max_col_width=2000,
                                    select_mode="extended",
                                    auto_size_columns=False,
                                    # display_row_numbers = True, # this throws an error
                                    col_widths=[11, 5, 30, 6, 20, 20],
                                    hide_vertical_scroll=True,
                                    justification='left',
                                    # alternating_row_color='lightgrey',
                                    num_rows=50, key="csvTable")]], size=(984, 400), scrollable=True)]]

    graphTab = [[Sg.Canvas(key='graphCanvas')], [Sg.Button("Graph Severities", key="graphIt")]]

    mainTab = [[Sg.Text("Query:"), Sg.Combo(queries, default_value=queries[0], key="query", size=(20, 1)),
                Sg.Radio("Any", key="anyV", group_id="critGroup", default=True, enable_events=True),
                Sg.Radio("Low", key="lowV", group_id="critGroup", enable_events=True),
                Sg.Radio("Med", key="medV", group_id="critGroup", enable_events=True),
                Sg.Radio("High", key="highV", group_id="critGroup", enable_events=True),
                Sg.Radio("Crit", key="critV", group_id="critGroup", enable_events=True),
                Sg.Text("", size=(3, 0)),
                Sg.Text("Adv. Query:"),
                Sg.Combo(advQueries, default_value=advQueries[0], key="advQueries", size=(45, 1), enable_events=True),
                Sg.Button("", border_width=0, key="advQuery", tooltip="Run Advanced Query",
                          image_data=b'iVBORw0KGgoAAAANSUhEUgAAABgAAAAXCAYAAAARIY8tAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAKOSURBVEhLtZVdSFNhGMf/y6CibZVkHzurmy6cFhFNt24kEhcUGK0uR2ndNNJJd9YKjArJu5ijFYXMcN05m4EXFSV4k8uJF+b0us4ML/qYg65ivc9zPnI5Ohtbv7G9e9/z8P+f932e8xyTff+BPP4jG+gn+30Ftt07eKw2bBAJP0Bs+CkmX0/A2+6pqhEb2G02JGdSePN2Ej1dfqTeTyHg7wB+/eSgSmCDz5kMT0KRKE54TmMs8RLnzp7BO7GjSo3YIJ1egqvJyQuo2aIbDT58jJNtrbqRtKdWiSkDNpBlZQcFdyqM4uOvcLztlG40En2C+3dvlGXEBguLSzyRJInHtVi37yow2idiyjHi54CqhhJLAiRmhNt5iIvBZtsLWeQvFH6E5OxH9WohvAO6y1wuB6vFwotGTKfm4bvcjes3+2ASn4H+OxgZGoTr6EE14g811m21t+nPkcONqKvbKUp1ii+Ugry8gnhiAovpBdjtEjov+OBpbUH2xzfMzc1i0+atyhFRcKfvvCjNdj0fxaBqG34eV2froZz0dPu5ItNC5+q1oHJEGiaT2LDB14h8XmltWqy+g4F7QV7ovdXPYzlQ0r1i9+7mJmQyy4g+i2H0RYJzu1GNQaOjHqNj4+qsNEg40HUFkmg1JExJpwIgSJxgAypTs9mM7OoqLxrxL+G/YYMGh4Mn08kZHotBN9EhquTSRR8sopypOfYG+yB/+apGFIcN6HgIWZa5RaylmDA9WEbCGmwgSTaeFIiLvuQVHVUTpg5LOSpVWEM5ooZ6vjNGCAdEG6B2TZBwKBxZt7NS4TKNDYXxSRwPddVqCWvwg0YvHKphasnU8JzHWvidUKk4oXdTt6tZVNEHvX6rA/AbCYgNqT960G4AAAAASUVORK5CYII=')],
               # Sg.ButtonMenu('Query',  right_click_menu, key='launchMenu')],
               [
                   Sg.Button("", key="connect", border_width=0, tooltip="Connect to ACAS",
                             image_data=b'iVBORw0KGgoAAAANSUhEUgAAABsAAAAVCAYAAAC33pUlAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAHRSURBVEhLY5SRU/7PQCfABKXJBtISQgybVi9g2L9jLZg2N9aBymACsi379OEVg4aqHMP0yX0MT589Z5g8bSbD9Zu3GKorSqAqMAHhYPz7nSEwwI/B3MwEzNXSUGfg5eUFs0Hgy5cvDPYungx8AmIMQX5uDLlZ6QyOHsFQWVTAAqVxgqUL5zJISUkynDpzFszfs+8Aw5Onzxg+f/rMcO3GTYanT5+CLSIGELQMZBEoiNZt2gUVQQPMnFAGAoDiDwauAx2UVVAFZlOcQLABkOOQMQzQxDJQKMDw9VsPoaI0sgwXAFsGSsbxUUHw/IKMqQnACSQvO5MhPjaKYeHiZQyfPn8GS8AAKClTC4B9FhzoB7ZowdK1KOENwtQEYMt4eHgwfEQLQJMEghzn0ya0QUWJtMzM1JhBSlwQjEHFFyGAK58RLEFAikGJZOnCOVARCPgMDHZQcXX9+k2GhcvWQUUhAFdcE7QMllBAVQkIgAtiPl4GPmBhDCqcE+KiGW4AS/uTZ6+A5fEBgpbBwNMX76D0cTANAqDUW1OWy9DR2ggVYYAX2NgAuIoBRSQouMhN6qAKU1paClwTrN2wEWctQJXUCApCkEN3HziOt7qhYxuEgQEAkRzGQ2DlCR8AAAAASUVORK5CYII='),
                   Sg.Button("", tooltip="Clear Output", border_width=0, key="Clear Window",
                             image_data=b'iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsIAAA7CARUoSoAAAAKISURBVEhLY5SRU/7PQEPABKWJAkF+bgzTJrQx8HGzQkUIA6Is+PThFdjg3Kx0Bk0NdTAmFhC0AGT4kgVzGGRlpBmy8ooYvnz5wiAtLQWVJQwIWpAQFwN2cXR8CsP1Ww8ZTp46w+Di5ACVJQwIWgAKlvUbNzN8+vobzN+9dz/YQmkJITCfEMBrAcwQkKEwcPLsFYZnz54zVFeUgIOPECAukj99hrIgIDO3EOyL6opSqAhugNeC6zdugGlzMxMwDQOg4KqormcICvBjyM2Ih4piB8x8/EINUDYYgLz988dXBnYObjCWlRJnsLWxYli3cTtUBQQ8ff6KgfH/X4bI8BAwfeHydagMKkDxASgDbVq3kmHa5H6oCCT8paWksGauBUvXghNAfGwUg6aaPFQUFaBY0NnWBDbM3NQEruHTZ0j48/Lygml0MGn6AoYbN28xdLY2QkVQAdwCkIEa6mrgsAVpmDapj6GjuRKsEcR/+uIdVCUmaGnvBjvA3FgHKoIAcAtArgYBUDKMjk9mWLh4GQMjIyPDqdNnGTJzCsByuADIclAOx1aEsEBpBk1NdYZTZ86C2XwCYuDwhQNmTigDN7h24ybYDHSAN5lSA8AtAJUxZibGROVObACkF2QGOoBbsAdaHLg6O4FpUgAscq8DgwkdwC0A5U5QHBBbxsAASG1udjq4fAKVtugAJQ5agckNlHJA5T8xloDUgMojUN4pq6qDiqICFAtAvgApBFUuB3ZvYzAz0obKYAJQSQtyCKg8AuUdXPkEa6UPKhaqK0vBEfcZmJNBkQdKhiAgA6zNQIUfyNWgYAE5CF8mxNuqALnS1dkRbCAol4MAOKyBloHKKFCmJARo3GxhYAAAASz0wYbe/AkAAAAASUVORK5CYII='),
                   Sg.Button("", key="saveSession", border_width=0, tooltip="Save Session",
                             image_data=b'iVBORw0KGgoAAAANSUhEUgAAABUAAAAYCAYAAAAVibZIAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsIAAA7CARUoSoAAAAFYSURBVEhLY5SRU/7PQGUAN9TFwYKBl5cXLIgMbty8xXD91kMojzgANrSzpYrBzMQYKoQKQIZm5ldCecQBsKH7d6xlmDxtJsO6TbugwpQBJihNVTB4DHV1sGT49OEVlIcJSDY0LzOBoaqihMHV2QkqgglIMtTcWIch0N+XYf3GzQwnz16BimICog0FGdjR2gg2cNL0BVBR7IAoQ0kxEARYoDROIC0hBDYQBKSkJBk6mnFnhOvXbzIsXLaOtDBlZGQkiEGAoEufvnjHUFFdD3btkydPGSbPWAiVwQ2IcikopkEGBwX4MeRmxENFcQOivU+KwSSFKchgUAoAGQxKEbgASYaCAChJtXX0MOzeuw8qgglINhQEdh84zsAnIAblYQKyDCUEaGIouOSfPrGdQUNdDSqECq7fuMmQVVAF5REHwIaCysbgAH8GXj7Mig9kKFkVH5RNJcDAAABP73AkcmltYwAAAABJRU5ErkJggg=='),
                   Sg.Button("", key="loadSession", border_width=0, tooltip="Load Session",
                             image_data=b'iVBORw0KGgoAAAANSUhEUgAAABUAAAAYCAYAAAAVibZIAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsIAAA7CARUoSoAAAAFFSURBVEhLY5SRU/7PQGUANvTTh1cMQQF+DLy8vFBhBLhx8xbD9VsPoTziANjQzpYqBjMTY6gQKgAZmplfCeURB8CG7t+xlmHytJkM6zbtggpTBpigNFXB4DEUFLEuDhZQHiYgy1BXZyeG6opShoToYKgIKiDL0JNnrzCs37iZIT42isHcWAcqigBkh+mk6QvABne0NmIYTFFE4TKYBUrjBKBw09BQg/JwA5DBMQmpDE9fvCPOpYyMjHgxOiDo0gVL10JZ2EFeZgIDAzCLV1TXg10JAhSFKcjAQH9fsIGgFAEDZBuKy0AQIMtQUEyDDFy4eBmGgSBAlqG79+5jaOvowRneZBnKJyDGsPvAcSgPE1AUUbgATQwFl/zTJ7YzaKhjzzXXb9xkyCqogvKIA/CKLzjAn4GXD7PiAxlKVsUHZVMJMDAAAEndb3Vk/Y2FAAAAAElFTkSuQmCC'),
                   Sg.Button("", key="analyze", border_width=0, tooltip="Analyze Data",
                             image_data=b'iVBORw0KGgoAAAANSUhEUgAAABoAAAATCAYAAACORR0GAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsIAAA7CARUoSoAAAAKgSURBVEhLvZVfSFNxFMePiVS4rfBBcpMeLNKop7RJb+YaEYEUe2vmFgUlpiREMyf9Y9OZQbE0fSjQ0uxFCl/nbOFDaQlB0Wbvm+FDhFv0ELJ+3+Nva/fuXhsRfcZlv9/53Xu+v3N/55xbVLlzV5r+AwULmUpLyGyuoL011TyPxpYokVim1e8/ef4nNhRa/bZCrtNOcpxsIovZLK1K4okETT2fprEnE2TaXi6t+egK2RsOUXvbeTIajRSejVAo/JKjyESACBGd3XaYbI0NlEwmKTg0QjORN7yuJk8IUfT7b9ER4QACvr7bRMVb5aoOaz+o5+oVFpwRG/J4r+VFpxCCyPjoQ95pb+AOhSKv5Uph4C10d13myJvd5xRim+Q/Mzx4j0W6vNe1RcTOrQf28YWxGjyDZ+Hjwf270rpOsWlb2Q0M3E4HHT92lG+cX/zIi7nU1+7naHEmuNwtTopFP1F8eUXesQ7msLtFEhWl1+j9hyjbOSLLjjKRXadE5jzVFMHuA/6bcvIbtmlEBh/wBZ/wDVio4+IFrong0DAb1dhtjXKUT731oBwpgS/4PCMiB9kzSovfvwY+jSYjj1koODjCBdnR1spGNaHwrBwpSaVSNL/wVs6UwBd8wjdgofiXr9l3ikPPQ9QRkkSNr29As8bgI3Pm8A0UddTv6yZrXa1u5uHgM2fCkeiIIEkW3i2Sp6dXWjUKdmLsEdVU7yF/YEC3neiRKdjY0mdyus4qCjZbR2DzllKafDZJu6uquJlWVpTT3Nwr8YJL5B06iEi9nk5yiQxD22ptv7RxC8oFu0PaGwwG7l9oqthpblNF5Che9EUkBg5er23pCgG8SndLMzlONPG3SAvUytSLaRp9PP53nwk1iMBiMSs+fPF4osAPH9EvR/gfj+m5KikAAAAASUVORK5CYII='),
                   Sg.Button("", key="wut", border_width=0,
                             image_data=b'iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAALTSURBVEhLtZU9TFNRFMdPjU62xDgYaQ0OxvZVndSAm/000UQ0fiwWeDViJGgZjBKDxsGoAyaaABIMGgu2q4ODJpaWOimgqwU2hlbjYAytk0N9/9N3n++zkaA/QqHn3vv/33fuuee5drTtqtN/pKnB6o9vFIuEKR4Nk8/npaAU4HhpcYnK5Qrl8rM0U5illi3bOG6HrQGE5e4Ene9JkMfjoUrlC4t+Vn7BHsUIZl5vK1WrVXo+naWpF1lbI4sBxDPppyyQLxRp5PEErf78pY4aadm8iQYu91E0EuINdCV7LSYGA4gXc6/J5XLR4NBtKi2vqCPNCfp30vD9O1Sv1ykUP2Yw2aD+1XYO8YTc+9fiAHOxBmuhAS2BZpDs6eK0YOdOKWkG1mAtNKAlYAM4JrvPcc7XsnMzWAsNaImnYIN4NMLVggNdL9CAFjSBahDmUtSnBjuIhQ6Rb/tWNWIFY5ijzzk0oAVNsBEfuEQoMz2nT56goRvXuM47zybVqJGJsUfkdrvJpfzkiu/VaOMi4o4AfgIp4NcukQDfa7UazS98UiNW5uY/8hy7teLWa1Vkpvz1Ox0/I9Pd4VE1YgVjmIO5TrDB4tIyX/9/BbSgCdgAjUuS/Bww03FgH99UM4hhzA6kB5qADdAVfV4v9xYzqIbxkYeU6pNJ2t1G7fv38v+IiUrRAw0cMDQB9yKU2buZN/RhboHuPRjjAT2nOo9wZ0XFABwsOujLV2/5u55bgynqaD9Ih2NHuSdpzQ4iqf5L1D9w1fE2iyd0aiVIG55sdPyJZq4Z4CmyU8+UVLUqbffimvsRzDPpSSorlywhX9A6qlamCGCg0REnbQ/WCczFmkYn/iMODPcAA8gddoFHvXn9iu3BCzCGOZiLNSLveixvNIB0oeWKgy1XKlQqmV6ZwQBXnjjw9HTGIg5sDQQwQlcUL320FIBLJF76uXzBVljQ1GD9EP0GeXVUD+L8Kv4AAAAASUVORK5CYII='),
                   Sg.Text("", size=(84, 1)),
                   Sg.Radio("Clear", group_id="format", default=True, key="clearForm"),
                   Sg.Radio("CSV", group_id="format", key="csvForm")],

               [Sg.TabGroup([[Sg.Tab('Clear', clearTab, key="clearTab"), Sg.Tab("CSV", csvTab, key="csvTab")]],
                            tab_location="topright")

                # [Sg.Multiline("", key="resultML", size=(140, 25), horizontal_scroll=True)

                # Sg.Column([[Sg.Button("", size = (1,1), border_width=0) for x in range(0, 5)]], scrollable=True, size=(5, 400))
                ],

               [
                   Sg.Button("", tooltip="Save Data to Disk", border_width=0,
                             image_data=b'iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsIAAA7CARUoSoAAAAHsSURBVEhLY5SRU/7PQEPABKWJAgnRwWBMCiDJAk1NdTAmBbCACHNjHYbqihIGXl5esCAyuH7jJkNWQRWUhwqmT2xn0FBXg/IQ4PPnzwytHT0MJ89egVhQU1nKcA1o0MlTZ8AKkAHIAlxg0tQZDJoamD4yNzMBO9gvNAFiAQ8PD9jwdZt2gRUQC67fegjG2ICZiTGYJikOyAEDb8HmNQsZcjPioTwEyMtMYNi0egGUhxsQtGDt+k0MQQF+DK4OllARBjA70N+XYd2GzVAR3AAcyfjAgqVrGfj4eBmqgKkClPxAABSB6zduBssRAkTFwaTpC8AGgvIJCIPYIDFiANGR3NLexXDj5i0wBrGJBURbwCcgxpCZXwnGIDaxgGgLyAU0twBcH+zfsZbh5OkzWMsicgCoLNLW1GDwDYmHWAAqTUEFHqhMogb48uULMCF0g0tTgjUaHzcrw8a1KxgqquvBGkAA5KCO1kYG/+AIhk9ff4PFcAGCceDi7AimT546DaZBAMaGyeEDeC349OEVQ0JsFMOpM2cZGJg5oaJAAGSDxEByIDX4ADMfv1ADlI0BmusqGDSAFcr16zcZRIT5GTTVleGYD5ijQZWNsqIiw+Fjp6A6MAHeOACVpIQi/tmz5wzRSTlQHiagcbOFgQEAyZqgC7mrf3oAAAAASUVORK5CYII='),
                   Sg.Button("", tooltip="Email Data", key='emailMainWindow', border_width=0,
                             image_data=b'iVBORw0KGgoAAAANSUhEUgAAABoAAAAWCAYAAADeiIy1AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsIAAA7CARUoSoAAAALYSURBVEhLvZVbSJNhGMf/driIdEUXUdPqIvBAXXWyrtLcgoJZKkg0sxVEttRA8mxBpWtpWLiaRWFD5mVaCl20mbsrqe4CD3ddOKOLCDW6iKj3//ht9bl9Ou3wk4+98zl973NaUtrmrT/wH1imfSbE1OePsOTslYfnxZDwjQrzD8Jx4jhSUlLk+/T0NDru3kMw9Eq+L8SCN8pK3wJ/lwcVzrMYGRtHrvWwPDw31lWLjDoLYXgj0+qVaKi7iOzduxAOT6Km4TImPnzSpLOkbliHVtdVmM0bMfz6DVzum5j68k2T6okJxNzzTQuP5mNmZgbN19sw/PadJo2PNWcfKsvLkJycjN4n/Whxt8G0dr0mnUUX6Pc6eLz34ev2xxgYwRd0lJZIilm/R9096BsIaFItENPk9bQj1WzG4IuQukUrsHyVprJIvn9FU30N8g7kYCIchrOiStIpzdDpuSVBgoNDqhaXlh6EKFv6oC/65AWIBGIxWXBLXi5CgWfYs2ObCJdC9s7t4oO+6JPBSLS9H6siHik6Jm17Q3WS97ZLuipRqEsbd8sV8UFf9BlBN0fMZW2TC87KKqwxmeD3PUBjdbnkPQKLrtsKSkYd6tKGtvQxt81XaJ86Rsbfw366XLrwVKkdQyoVPtVFVktuNBUsdCA4pDrNLmPALu3tfy6yeMy7GWi433JIck2HSeqPQ8mHZ/6PAakzXxAyb6DI8LJZ+p4OwFZYjEDopTw8cxR4Q+ro0hkHw0CcLb/voWwI3qCj06cbXp6bWz0iow51aWNE3ECySFVxN6WlosRxRm5gBGXUoS5tjBZsTCCHvQjejnaV+0nJ/dxFGg/q2AqKxYa2BTarJvlFNJBJ7Tf3tXqcVLuO9Th3oT7hPSeojUAb2laeLxNf9BlBdl1P1x0pOBkZHUNArY8/waq2QlZmhpxH1fDyBaJLldsgMyNdhH8LBqlVv2Mc3pjfo38D8BP4+EBAHaJTGQAAAABJRU5ErkJggg=='),
                   Sg.Button("", key="wordcloud", tooltip="Wordcloud", border_width=0,
                             image_data=b'iVBORw0KGgoAAAANSUhEUgAAABoAAAAUCAYAAACTQC2+AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsIAAA7CARUoSoAAAAJxSURBVEhLvZVdSJNRGMf/KlLhtkKa1DYqCmxCF4FzC4K+nIWEi1k0LEwHUSmsD5AwISgoii66GH2YBGmx6qIhVnQzN6WI2igoirY36K69RRdh20Caqb3P45lQcx/N0e9ivOd5z/Y7zznPeVZiWLFmGv+B/EST4zDXmaDX6xCPx/EhLCEiSdAsqRITcpNVpKkoR093FyyK5G9IeOu2BwN3PHkJM4ostetw8fxZJBIJuK/0wucPAGWLEBv7hhqjEbvtNth3NSEckdDpOsHvsjGnqKZ6Ja65L8MfGMXJntMZV0wZewZu4kcsBluzI2tmaSJa8ajvCaLyF3QcOyWimSHZkPe+soV30e/ximg6ZZrFlWfEM7NpowU7G3fgeFc34olxEc3Mz4kpxGNjOHTQCYtpPVavMiAUfAmUlosZM6SJnK0OJJNJ3HvwWERyEwy+UL4zAa12KTaY61iKqV94+y4sZswhatlrRzQq4+nzkIjkZsHCCoSlTxgOPMONvj5UabVocexByfQk3ghZKX8KaL+Na6sRU0q3UKgg3Nf7MTj0CG2t+6BfVsnxWRGVMx0qlXMw9EpEC+fchUv8W3QNCBaRle4MrWKztRHB1+/55XygzHz+EVi3beExi5wH9kNWyplSzueW58tn5azVajU/s8hiNrG92BiU3kjbR7BIpVLxoNhQj0wlwKKI9BHW+pm9LBbNtu3Q6ZbDO/iQxyxyX+2FXqeD60gbB+cDtTB7UwNcnYe5uKJfv3N8ttcd7WjnbhyVZfiGRwq6S3QmDfVbuQBIQsWV4o+mSl27XalAs6lWRP4NOng6E9quVCYpMv4fFRfgN6av5EusNbJyAAAAAElFTkSuQmCC'),
                   Sg.InputCombo(searches, default_value=searches[0], size=(40, 1), auto_size_text=False,
                                 key="searchWords"),
                   Sg.Button("", key="search", bind_return_key=True, tooltip="Execute Search", border_width=0,
                             image_data=b'iVBORw0KGgoAAAANSUhEUgAAABcAAAAXCAIAAABvSEP3AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAI5SURBVDhPY5SRU2agGGCY8vd7YICfq7OjpoY6kHf9xs2nT58tWLzs6Yt3EHmsAMWUID+3hNgoXl7eU2fOnjx1BigiIy1lbmoiJSV58vSZrNxCPgExiEo0gDAlLzMh0N93774DLe1dDMycEEEIMDfWqaks/f//f0xC6qevv6GiSABqCtAVuVnpk6fNXLdpF0QCHfz9vnTh3P8M//2CwjFdxAQi/n4HegToCpxGAAEzZ2ZuobSUVF52JlQECYBMCQr0B4YFyCN4AdAv6zduDgrwhfKRAMgUYIwAgxMtLLCC3Xv3A+2TlhCC8mEAZIqGuhokRgiC67ceAklzMxMIFw7A4UIxAJly4+YtYLqA8AmAv9+BxOdPnyE8OACZAkygZqbGED5+4OrsBCR3790H4cIByBRgmAGjEJi0IEJ4QEJcNNZ4ALvl1kOgXHVFCcTBuEBCdDAwKyxYtBTKRwLQ0C2vrGVkZFyycA4fNytEBA0AjYiPjQL6HRJNaICZjx8c+UysW7du9fHySEtJ5OPh/PTx/Zt3H0Hif7+7ONk21ZXb2lgBIwGY0YGyp85cBEkhAZQ8/enDq4S4mMS4aB4eHqgQGAD1T5o6A+gKSI5dt2HT5BkLoXJggFG+gM3S1NAAxr20tBQwUkExghScWA2C+QgJsHNwf/7y/enzV9dv3r334AnQs1AJMDh55gI/L1dQgB+y17CYQhBgGkSOKUAAN+jZk8dA95JpChAADQIaASxJf/7+hyV0SQYMDACvTuLhjlzNKAAAAABJRU5ErkJggg=='),
                   Sg.Button("", key="clearItems", bind_return_key=True, tooltip="Remove Searched Items",
                             border_width=0,
                             image_data=b'iVBORw0KGgoAAAANSUhEUgAAABkAAAAZCAYAAADE6YVjAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAABdSURBVEhLY5SRU/7PQGPABKVpCkYtIQmMWkISGLWEJAC3xMDICMqiHBgaG0NZEAAvu+bNncVw/cZNsCClQFNDnSEpOQ3KQ7KElmA0dZEERi0hCYxaQhIYLpYwMAAA9rMLb/+93MUAAAAASUVORK5CYII='),
                   Sg.Button("", key="saveSearch", border_width=0, tooltip="Toggle Saving Searches",
                             image_data=b'iVBORw0KGgoAAAANSUhEUgAAABcAAAAXCAYAAADgKtSgAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsIAAA7CARUoSoAAAAJiSURBVEhLtZVLaBNRFIb/aalSbSbQithJUDRgje60VtxI2yTutL7AR1oTpfiCuBTsQkRF7DZWKgglauPOShVcaC2h4mOGWCoopUiLi2YKomgSpUipcc71pk7SeSH4wXCHcy7/PXPOPWcE72pfAf+JCr4aIi6vwrXL59Hfdx2eVbXc6hzTyEm4P3ELgiBgOqPC5apB+/EY9zrDMHK9cDjSicSdJDySBP/6NXyHMxaJlwvnfsxBfvMOqjqDSMcRvssZJeJGwkXiN25i29ZGhJq3c4s9laK79iK9WAkTmZlPcLuW4UTnMYg11VDk11poVdxrDBO3Ey4ip8eQz31DtCOM6NEwvPUrsXRJBaYmPxgexG5L95UubNzQYClcwvysJt6OUKAFklTPTBlVZYUfSmlfxGHiyb4eZHM55lRG33OXQ7SDQoFWBIMtaGrcgrb9hxYCZAU913UBblFE99VLrGGaNm9iTkdUVuNp6hUyWi+Uw3Ke/z6LgcHHUBQZvnVrWU5Z0dJv+TZrzp6OYm/bLjwYfISRl6PcqrstxOcvWQwNP18oGq3jE5Pca4xeON6b4NY/GHbowMMnbHPszEmWUzOshAlDcSLe08tWuhVG2AkTpuJUqGfDKQQDzdzwl6IwUSiYT2xzcQ1ZSbOBpU+NPmJ69u3ZjdipCPeWUlLQcqjzqBNpaE19nF6UCupYGgl0gNHtshSnlt7ZugN1K+rgb/AxkfIcWx1gLa6Rz37F4YMH4NfGg1nxzA5w9A+lwUbYzZ1i2m7fvYdE8r595MTPuV/ssYO+QCjMw+uRMPJCcRb5vwH8BkJuE0gT8P8VAAAAAElFTkSuQmCC'),
                   Sg.Button("", key="sendParser", tooltip="Push results to Parser Tab", border_width=0,
                             image_data=b'iVBORw0KGgoAAAANSUhEUgAAABkAAAAZCAYAAADE6YVjAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAIeSURBVEhLY1TR1P/PQGOA1xIbUx0GF2dHBi0NdQZeXl6Gz58/M1y7cZNhz979DEdOX4GqIgywWuLlbMWQm5UOZt+4eYvh5KkzDJ+AFvABLTI3M2HQUFcDy02aOoNh+77jYDY+gGFJX2sVgybQ5es3bmaYtWgNVBQTpMWFMAT6+zJcB/qsqLoNKoodoFjS31bNICMtxVBWVcdw/+lbqChuoCgtzNDV1sTw+MlTvBYxQWlwEIGCgVgLQACkDqQe5HOQflwAbgkoDkBBRKwFMABSD9IHi0NsAGyJrakumIMvDvABmD6YOegAbImLiyM4FVECQPpB5mADYEtA+QCUTCkBIP2a0KSNDsCW8PDwgPMBJeDp02cMjIyMUB4qAFvy5csXcEajBBw+fZkhND4bykMFYEtARYWZqTFYgBYAbMmePfvBaZ1WAGwJyKsgACoqKAGgAhUbYBYSlWgAMd6/fcUQHxvFcOzoYYYPn7+DJUkBoDxSXVHKwMXOzHDu0nWoKATALbl9/zGDiYE2Q1CAL8OZ0ydJtujRs1cM3BwsQP1+GBbBLQGBnXsPM1iZGYJ9hM1FhMDZi9ewWkSwPgEV5bD6hFiQGBcNruQWLl7GsGLDTvw1IyicQUUFqEQAZVhSwakzZxnq2yfht4RcsGrBFHDuj45PYfjFwA5JwtQE6BaAANUsYWP4CbcAVLzALAABqllibmoCtwAd0CROUAEDAwDjas5sJxYwuwAAAABJRU5ErkJggg=='),
                   Sg.Button("", key="revert", tooltip="Revert to original query", border_width=0,
                             image_data=b'iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsIAAA7CARUoSoAAAAKISURBVEhLY5SRU/7PQEPABKWJAkF+bgzTJrQx8HGzQkUIA6Is+PThFdjg3Kx0Bk0NdTAmFhC0AGT4kgVzGGRlpBmy8ooYvnz5wiAtLQWVJQwIWpAQFwN2cXR8CsP1Ww8ZTp46w+Di5ACVJQwIWgAKlvUbNzN8+vobzN+9dz/YQmkJITCfEMBrAcwQkKEwcPLsFYZnz54zVFeUgIOPECAukj99hrIgIDO3EOyL6opSqAhugNeC6zdugGlzMxMwDQOg4KqormcICvBjyM2Ih4piB8x8/EINUDYYgLz988dXBnYObjCWlRJnsLWxYli3cTtUBQQ8ff6KgfH/X4bI8BAwfeHydagMKkDxASgDbVq3kmHa5H6oCCT8paWksGauBUvXghNAfGwUg6aaPFQUFaBY0NnWBDbM3NQEruHTZ0j48/Lygml0MGn6AoYbN28xdLY2QkVQAdwCkIEa6mrgsAVpmDapj6GjuRKsEcR/+uIdVCUmaGnvBjvA3FgHKoIAcAtArgYBUDKMjk9mWLh4GQMjIyPDqdNnGTJzCsByuADIclAOx1aEsEBpBk1NdYZTZ86C2XwCYuDwhQNmTigDN7h24ybYDHSAN5lSA8AtAJUxZibGROVObACkF2QGOoBbsAdaHLg6O4FpUgAscq8DgwkdwC0A5U5QHBBbxsAASG1udjq4fAKVtugAJQ5agckNlHJA5T8xloDUgMojUN4pq6qDiqICFAtAvgApBFUuB3ZvYzAz0obKYAJQSQtyCKg8AuUdXPkEa6UPKhaqK0vBEfcZmJNBkQdKhiAgA6zNQIUfyNWgYAE5CF8mxNuqALnS1dkRbCAol4MAOKyBloHKKFCmJARo3GxhYAAAASz0wYbe/AkAAAAASUVORK5CYII='),
                   Sg.Check("Overwrite Parser", key="oParser", tooltip="Erase /Overwrite First Parser Tab",
                            visible=False),
                   Sg.Check("Generate New Parser Tabs", tooltip="Autcreate Parser Tabs", key="autoParserTab",
                            visible=False),
                   # Sg.Text("#:", key = "searchCount")

               ]]
    ACASlayout = [
        [Sg.Check("Include Exempted Plugins", key="exportIncludeExemptedPlugins")],
        [Sg.Check("Include Plugin Exemption", key="exportIncludeACASExemption")],
        [Sg.Check("Include Reason", key="exportIncludeACASReason")],
        [Sg.Check("Include Plugin Notes", key="exportACASNotes")]]
    vSpherelayout = [[Sg.Check("Export All Online VMs", key="exportAllVM")],
                     [Sg.Check("Include Quarantine Impact", key="exportVSphereImpact")],
                     [Sg.Check("Include Reason", key="exportVSphereReason")],
                     [Sg.Check("Include VM Notes", key="exportVSphereNotes")]]

    exportTab = [[Sg.Column([[Sg.Check("Enable Custom Column Generation on Exports", key="enableCustomExport")],
                             [Sg.Frame("ACAS:", ACASlayout), Sg.Frame("vSphere:", vSpherelayout),
                              # Sg.Frame("VSphere Columns:", vSphereLayout)
                              ], [Sg.Text("Primary Pivot Key:"),
                                  Sg.Radio("Vulnerability", key="Vulnerability", group_id="exportKey"),
                                  Sg.Radio("VM", key='VM', group_id="exportKey")], [
                                 Sg.Button("Export", key="finalExport"),
                                 Sg.Button("Export and Email", key="finalExportAndEmail")]])]]

    vSphereTab = [[Sg.Column([[

        Sg.Text("vQuery:"),
        Sg.Combo(queries, default_value=queries[0], key="vQuery", size=(20, 1)),
        Sg.Text("", size=(39, 0)),
        Sg.Text("Adv. Query:"),
        Sg.Combo("ip==192.168.46.252&online==True&tag==Backup",
                 default_value="ip==192.168.46.252&online==True&tag==Backup", key="vAdvQueries", size=(45, 1)),
        Sg.Button("", border_width=0, key="vAdvQuery", tooltip="Run Advanced Query",
                  image_data=b'iVBORw0KGgoAAAANSUhEUgAAABgAAAAXCAYAAAARIY8tAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAKOSURBVEhLtZVdSFNhGMf/y6CibZVkHzurmy6cFhFNt24kEhcUGK0uR2ndNNJJd9YKjArJu5ijFYXMcN05m4EXFSV4k8uJF+b0us4ML/qYg65ivc9zPnI5Ohtbv7G9e9/z8P+f932e8xyTff+BPP4jG+gn+30Ftt07eKw2bBAJP0Bs+CkmX0/A2+6pqhEb2G02JGdSePN2Ej1dfqTeTyHg7wB+/eSgSmCDz5kMT0KRKE54TmMs8RLnzp7BO7GjSo3YIJ1egqvJyQuo2aIbDT58jJNtrbqRtKdWiSkDNpBlZQcFdyqM4uOvcLztlG40En2C+3dvlGXEBguLSzyRJInHtVi37yow2idiyjHi54CqhhJLAiRmhNt5iIvBZtsLWeQvFH6E5OxH9WohvAO6y1wuB6vFwotGTKfm4bvcjes3+2ASn4H+OxgZGoTr6EE14g811m21t+nPkcONqKvbKUp1ii+Ugry8gnhiAovpBdjtEjov+OBpbUH2xzfMzc1i0+atyhFRcKfvvCjNdj0fxaBqG34eV2froZz0dPu5ItNC5+q1oHJEGiaT2LDB14h8XmltWqy+g4F7QV7ovdXPYzlQ0r1i9+7mJmQyy4g+i2H0RYJzu1GNQaOjHqNj4+qsNEg40HUFkmg1JExJpwIgSJxgAypTs9mM7OoqLxrxL+G/YYMGh4Mn08kZHotBN9EhquTSRR8sopypOfYG+yB/+apGFIcN6HgIWZa5RaylmDA9WEbCGmwgSTaeFIiLvuQVHVUTpg5LOSpVWEM5ooZ6vjNGCAdEG6B2TZBwKBxZt7NS4TKNDYXxSRwPddVqCWvwg0YvHKphasnU8JzHWvidUKk4oXdTt6tZVNEHvX6rA/AbCYgNqT960G4AAAAASUVORK5CYII=')],
        # Sg.ButtonMenu('Query',  right_click_menu, key='launchMenu')],
        [
            Sg.Button("", key="vConnect", border_width=0, tooltip="Connect to vSphere",
                      image_data=b'iVBORw0KGgoAAAANSUhEUgAAABsAAAAVCAYAAAC33pUlAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAHRSURBVEhLY5SRU/7PQCfABKXJBtISQgybVi9g2L9jLZg2N9aBymACsi379OEVg4aqHMP0yX0MT589Z5g8bSbD9Zu3GKorSqAqMAHhYPz7nSEwwI/B3MwEzNXSUGfg5eUFs0Hgy5cvDPYungx8AmIMQX5uDLlZ6QyOHsFQWVTAAqVxgqUL5zJISUkynDpzFszfs+8Aw5Onzxg+f/rMcO3GTYanT5+CLSIGELQMZBEoiNZt2gUVQQPMnFAGAoDiDwauAx2UVVAFZlOcQLABkOOQMQzQxDJQKMDw9VsPoaI0sgwXAFsGSsbxUUHw/IKMqQnACSQvO5MhPjaKYeHiZQyfPn8GS8AAKClTC4B9FhzoB7ZowdK1KOENwtQEYMt4eHgwfEQLQJMEghzn0ya0QUWJtMzM1JhBSlwQjEHFFyGAK58RLEFAikGJZOnCOVARCPgMDHZQcXX9+k2GhcvWQUUhAFdcE7QMllBAVQkIgAtiPl4GPmBhDCqcE+KiGW4AS/uTZ6+A5fEBgpbBwNMX76D0cTANAqDUW1OWy9DR2ggVYYAX2NgAuIoBRSQouMhN6qAKU1paClwTrN2wEWctQJXUCApCkEN3HziOt7qhYxuEgQEAkRzGQ2DlCR8AAAAASUVORK5CYII='),
            Sg.Button("", tooltip="Clear Output", border_width=0, key="v Clear Window",
                      image_data=b'iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsIAAA7CARUoSoAAAAKISURBVEhLY5SRU/7PQEPABKWJAkF+bgzTJrQx8HGzQkUIA6Is+PThFdjg3Kx0Bk0NdTAmFhC0AGT4kgVzGGRlpBmy8ooYvnz5wiAtLQWVJQwIWpAQFwN2cXR8CsP1Ww8ZTp46w+Di5ACVJQwIWgAKlvUbNzN8+vobzN+9dz/YQmkJITCfEMBrAcwQkKEwcPLsFYZnz54zVFeUgIOPECAukj99hrIgIDO3EOyL6opSqAhugNeC6zdugGlzMxMwDQOg4KqormcICvBjyM2Ih4piB8x8/EINUDYYgLz988dXBnYObjCWlRJnsLWxYli3cTtUBQQ8ff6KgfH/X4bI8BAwfeHydagMKkDxASgDbVq3kmHa5H6oCCT8paWksGauBUvXghNAfGwUg6aaPFQUFaBY0NnWBDbM3NQEruHTZ0j48/Lygml0MGn6AoYbN28xdLY2QkVQAdwCkIEa6mrgsAVpmDapj6GjuRKsEcR/+uIdVCUmaGnvBjvA3FgHKoIAcAtArgYBUDKMjk9mWLh4GQMjIyPDqdNnGTJzCsByuADIclAOx1aEsEBpBk1NdYZTZ86C2XwCYuDwhQNmTigDN7h24ybYDHSAN5lSA8AtAJUxZibGROVObACkF2QGOoBbsAdaHLg6O4FpUgAscq8DgwkdwC0A5U5QHBBbxsAASG1udjq4fAKVtugAJQ5agckNlHJA5T8xloDUgMojUN4pq6qDiqICFAtAvgApBFUuB3ZvYzAz0obKYAJQSQtyCKg8AuUdXPkEa6UPKhaqK0vBEfcZmJNBkQdKhiAgA6zNQIUfyNWgYAE5CF8mxNuqALnS1dkRbCAol4MAOKyBloHKKFCmJARo3GxhYAAAASz0wYbe/AkAAAAASUVORK5CYII='),
            # Sg.Button("", key = "saveSession", border_width=0, tooltip="Save Session", image_data=b'iVBORw0KGgoAAAANSUhEUgAAABUAAAAYCAYAAAAVibZIAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsIAAA7CARUoSoAAAAFYSURBVEhLY5SRU/7PQGUAN9TFwYKBl5cXLIgMbty8xXD91kMojzgANrSzpYrBzMQYKoQKQIZm5ldCecQBsKH7d6xlmDxtJsO6TbugwpQBJihNVTB4DHV1sGT49OEVlIcJSDY0LzOBoaqihMHV2QkqgglIMtTcWIch0N+XYf3GzQwnz16BimICog0FGdjR2gg2cNL0BVBR7IAoQ0kxEARYoDROIC0hBDYQBKSkJBk6mnFnhOvXbzIsXLaOtDBlZGQkiEGAoEufvnjHUFFdD3btkydPGSbPWAiVwQ2IcikopkEGBwX4MeRmxENFcQOivU+KwSSFKchgUAoAGQxKEbgASYaCAChJtXX0MOzeuw8qgglINhQEdh84zsAnIAblYQKyDCUEaGIouOSfPrGdQUNdDSqECq7fuMmQVVAF5REHwIaCysbgAH8GXj7Mig9kKFkVH5RNJcDAAABP73AkcmltYwAAAABJRU5ErkJggg=='),
            # Sg.Button("", key = "loadSession", border_width=0, tooltip="Load Session", image_data=b'iVBORw0KGgoAAAANSUhEUgAAABUAAAAYCAYAAAAVibZIAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsIAAA7CARUoSoAAAAFFSURBVEhLY5SRU/7PQGUANvTTh1cMQQF+DLy8vFBhBLhx8xbD9VsPoTziANjQzpYqBjMTY6gQKgAZmplfCeURB8CG7t+xlmHytJkM6zbtggpTBpigNFXB4DEUFLEuDhZQHiYgy1BXZyeG6opShoToYKgIKiDL0JNnrzCs37iZIT42isHcWAcqigBkh+mk6QvABne0NmIYTFFE4TKYBUrjBKBw09BQg/JwA5DBMQmpDE9fvCPOpYyMjHgxOiDo0gVL10JZ2EFeZgIDAzCLV1TXg10JAhSFKcjAQH9fsIGgFAEDZBuKy0AQIMtQUEyDDFy4eBmGgSBAlqG79+5jaOvowRneZBnKJyDGsPvAcSgPE1AUUbgATQwFl/zTJ7YzaKhjzzXXb9xkyCqogvKIA/CKLzjAn4GXD7PiAxlKVsUHZVMJMDAAAEndb3Vk/Y2FAAAAAElFTkSuQmCC'),
            Sg.Button("", key="analyze", border_width=0, tooltip="v Analyze Data",
                      image_data=b'iVBORw0KGgoAAAANSUhEUgAAABoAAAATCAYAAACORR0GAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsIAAA7CARUoSoAAAAKgSURBVEhLvZVfSFNxFMePiVS4rfBBcpMeLNKop7RJb+YaEYEUe2vmFgUlpiREMyf9Y9OZQbE0fSjQ0uxFCl/nbOFDaQlB0Wbvm+FDhFv0ELJ+3+Nva/fuXhsRfcZlv9/53Xu+v3N/55xbVLlzV5r+AwULmUpLyGyuoL011TyPxpYokVim1e8/ef4nNhRa/bZCrtNOcpxsIovZLK1K4okETT2fprEnE2TaXi6t+egK2RsOUXvbeTIajRSejVAo/JKjyESACBGd3XaYbI0NlEwmKTg0QjORN7yuJk8IUfT7b9ER4QACvr7bRMVb5aoOaz+o5+oVFpwRG/J4r+VFpxCCyPjoQ95pb+AOhSKv5Uph4C10d13myJvd5xRim+Q/Mzx4j0W6vNe1RcTOrQf28YWxGjyDZ+Hjwf270rpOsWlb2Q0M3E4HHT92lG+cX/zIi7nU1+7naHEmuNwtTopFP1F8eUXesQ7msLtFEhWl1+j9hyjbOSLLjjKRXadE5jzVFMHuA/6bcvIbtmlEBh/wBZ/wDVio4+IFrong0DAb1dhtjXKUT731oBwpgS/4PCMiB9kzSovfvwY+jSYjj1koODjCBdnR1spGNaHwrBwpSaVSNL/wVs6UwBd8wjdgofiXr9l3ikPPQ9QRkkSNr29As8bgI3Pm8A0UddTv6yZrXa1u5uHgM2fCkeiIIEkW3i2Sp6dXWjUKdmLsEdVU7yF/YEC3neiRKdjY0mdyus4qCjZbR2DzllKafDZJu6uquJlWVpTT3Nwr8YJL5B06iEi9nk5yiQxD22ptv7RxC8oFu0PaGwwG7l9oqthpblNF5Che9EUkBg5er23pCgG8SndLMzlONPG3SAvUytSLaRp9PP53nwk1iMBiMSs+fPF4osAPH9EvR/gfj+m5KikAAAAASUVORK5CYII='),
            # Sg.Button("", key = "wut", border_width=0, image_data=b'iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAALTSURBVEhLtZU9TFNRFMdPjU62xDgYaQ0OxvZVndSAm/000UQ0fiwWeDViJGgZjBKDxsGoAyaaABIMGgu2q4ODJpaWOimgqwU2hlbjYAytk0N9/9N3n++zkaA/QqHn3vv/33fuuee5drTtqtN/pKnB6o9vFIuEKR4Nk8/npaAU4HhpcYnK5Qrl8rM0U5illi3bOG6HrQGE5e4Ene9JkMfjoUrlC4t+Vn7BHsUIZl5vK1WrVXo+naWpF1lbI4sBxDPppyyQLxRp5PEErf78pY4aadm8iQYu91E0EuINdCV7LSYGA4gXc6/J5XLR4NBtKi2vqCPNCfp30vD9O1Sv1ykUP2Yw2aD+1XYO8YTc+9fiAHOxBmuhAS2BZpDs6eK0YOdOKWkG1mAtNKAlYAM4JrvPcc7XsnMzWAsNaImnYIN4NMLVggNdL9CAFjSBahDmUtSnBjuIhQ6Rb/tWNWIFY5ijzzk0oAVNsBEfuEQoMz2nT56goRvXuM47zybVqJGJsUfkdrvJpfzkiu/VaOMi4o4AfgIp4NcukQDfa7UazS98UiNW5uY/8hy7teLWa1Vkpvz1Ox0/I9Pd4VE1YgVjmIO5TrDB4tIyX/9/BbSgCdgAjUuS/Bww03FgH99UM4hhzA6kB5qADdAVfV4v9xYzqIbxkYeU6pNJ2t1G7fv38v+IiUrRAw0cMDQB9yKU2buZN/RhboHuPRjjAT2nOo9wZ0XFABwsOujLV2/5u55bgynqaD9Ih2NHuSdpzQ4iqf5L1D9w1fE2iyd0aiVIG55sdPyJZq4Z4CmyU8+UVLUqbffimvsRzDPpSSorlywhX9A6qlamCGCg0REnbQ/WCczFmkYn/iMODPcAA8gddoFHvXn9iu3BCzCGOZiLNSLveixvNIB0oeWKgy1XKlQqmV6ZwQBXnjjw9HTGIg5sDQQwQlcUL320FIBLJF76uXzBVljQ1GD9EP0GeXVUD+L8Kv4AAAAASUVORK5CYII='),

        ], [Sg.Multiline("", key="vSphereML", size=(140, 25), horizontal_scroll=True)], [

            Sg.Button("", key="savevSphere", tooltip="Save Data to Disk", border_width=0,
                      image_data=b'iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsIAAA7CARUoSoAAAAHsSURBVEhLY5SRU/7PQEPABKWJAgnRwWBMCiDJAk1NdTAmBbCACHNjHYbqihIGXl5esCAyuH7jJkNWQRWUhwqmT2xn0FBXg/IQ4PPnzwytHT0MJ89egVhQU1nKcA1o0MlTZ8AKkAHIAlxg0tQZDJoamD4yNzMBO9gvNAFiAQ8PD9jwdZt2gRUQC67fegjG2ICZiTGYJikOyAEDb8HmNQsZcjPioTwEyMtMYNi0egGUhxsQtGDt+k0MQQF+DK4OllARBjA70N+XYd2GzVAR3AAcyfjAgqVrGfj4eBmqgKkClPxAABSB6zduBssRAkTFwaTpC8AGgvIJCIPYIDFiANGR3NLexXDj5i0wBrGJBURbwCcgxpCZXwnGIDaxgGgLyAU0twBcH+zfsZbh5OkzWMsicgCoLNLW1GDwDYmHWAAqTUEFHqhMogb48uULMCF0g0tTgjUaHzcrw8a1KxgqquvBGkAA5KCO1kYG/+AIhk9ff4PFcAGCceDi7AimT546DaZBAMaGyeEDeC349OEVQ0JsFMOpM2cZGJg5oaJAAGSDxEByIDX4ADMfv1ADlI0BmusqGDSAFcr16zcZRIT5GTTVleGYD5ijQZWNsqIiw+Fjp6A6MAHeOACVpIQi/tmz5wzRSTlQHiagcbOFgQEAyZqgC7mrf3oAAAAASUVORK5CYII='),
            Sg.Button("", tooltip="Email Data", key='emailMainWindow2', border_width=0,
                      image_data=b'iVBORw0KGgoAAAANSUhEUgAAABoAAAAWCAYAAADeiIy1AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsIAAA7CARUoSoAAAALYSURBVEhLvZVbSJNhGMf/driIdEUXUdPqIvBAXXWyrtLcgoJZKkg0sxVEttRA8mxBpWtpWLiaRWFD5mVaCl20mbsrqe4CD3ddOKOLCDW6iKj3//ht9bl9Ou3wk4+98zl973NaUtrmrT/wH1imfSbE1OePsOTslYfnxZDwjQrzD8Jx4jhSUlLk+/T0NDru3kMw9Eq+L8SCN8pK3wJ/lwcVzrMYGRtHrvWwPDw31lWLjDoLYXgj0+qVaKi7iOzduxAOT6Km4TImPnzSpLOkbliHVtdVmM0bMfz6DVzum5j68k2T6okJxNzzTQuP5mNmZgbN19sw/PadJo2PNWcfKsvLkJycjN4n/Whxt8G0dr0mnUUX6Pc6eLz34ev2xxgYwRd0lJZIilm/R9096BsIaFItENPk9bQj1WzG4IuQukUrsHyVprJIvn9FU30N8g7kYCIchrOiStIpzdDpuSVBgoNDqhaXlh6EKFv6oC/65AWIBGIxWXBLXi5CgWfYs2ObCJdC9s7t4oO+6JPBSLS9H6siHik6Jm17Q3WS97ZLuipRqEsbd8sV8UFf9BlBN0fMZW2TC87KKqwxmeD3PUBjdbnkPQKLrtsKSkYd6tKGtvQxt81XaJ86Rsbfw366XLrwVKkdQyoVPtVFVktuNBUsdCA4pDrNLmPALu3tfy6yeMy7GWi433JIck2HSeqPQ8mHZ/6PAakzXxAyb6DI8LJZ+p4OwFZYjEDopTw8cxR4Q+ro0hkHw0CcLb/voWwI3qCj06cbXp6bWz0iow51aWNE3ECySFVxN6WlosRxRm5gBGXUoS5tjBZsTCCHvQjejnaV+0nJ/dxFGg/q2AqKxYa2BTarJvlFNJBJ7Tf3tXqcVLuO9Th3oT7hPSeojUAb2laeLxNf9BlBdl1P1x0pOBkZHUNArY8/waq2QlZmhpxH1fDyBaJLldsgMyNdhH8LBqlVv2Mc3pjfo38D8BP4+EBAHaJTGQAAAABJRU5ErkJggg=='),
            Sg.Button("", key="wordcloud2", tooltip="Wordcloud", border_width=0,
                      image_data=b'iVBORw0KGgoAAAANSUhEUgAAABoAAAAUCAYAAACTQC2+AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsIAAA7CARUoSoAAAAJxSURBVEhLvZVdSJNRGMf/KlLhtkKa1DYqCmxCF4FzC4K+nIWEi1k0LEwHUSmsD5AwISgoii66GH2YBGmx6qIhVnQzN6WI2igoirY36K69RRdh20Caqb3P45lQcx/N0e9ivOd5z/Y7zznPeVZiWLFmGv+B/EST4zDXmaDX6xCPx/EhLCEiSdAsqRITcpNVpKkoR093FyyK5G9IeOu2BwN3PHkJM4ostetw8fxZJBIJuK/0wucPAGWLEBv7hhqjEbvtNth3NSEckdDpOsHvsjGnqKZ6Ja65L8MfGMXJntMZV0wZewZu4kcsBluzI2tmaSJa8ajvCaLyF3QcOyWimSHZkPe+soV30e/ximg6ZZrFlWfEM7NpowU7G3fgeFc34olxEc3Mz4kpxGNjOHTQCYtpPVavMiAUfAmUlosZM6SJnK0OJJNJ3HvwWERyEwy+UL4zAa12KTaY61iKqV94+y4sZswhatlrRzQq4+nzkIjkZsHCCoSlTxgOPMONvj5UabVocexByfQk3ghZKX8KaL+Na6sRU0q3UKgg3Nf7MTj0CG2t+6BfVsnxWRGVMx0qlXMw9EpEC+fchUv8W3QNCBaRle4MrWKztRHB1+/55XygzHz+EVi3beExi5wH9kNWyplSzueW58tn5azVajU/s8hiNrG92BiU3kjbR7BIpVLxoNhQj0wlwKKI9BHW+pm9LBbNtu3Q6ZbDO/iQxyxyX+2FXqeD60gbB+cDtTB7UwNcnYe5uKJfv3N8ttcd7WjnbhyVZfiGRwq6S3QmDfVbuQBIQsWV4o+mSl27XalAs6lWRP4NOng6E9quVCYpMv4fFRfgN6av5EusNbJyAAAAAElFTkSuQmCC'),
            Sg.InputCombo(searches, default_value=searches[0], size=(40, 1), auto_size_text=False, key="searchWords2"),
            Sg.Button("", key="search2", bind_return_key=True, tooltip="Execute Search", border_width=0,
                      image_data=b'iVBORw0KGgoAAAANSUhEUgAAABcAAAAXCAIAAABvSEP3AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAI5SURBVDhPY5SRU2agGGCY8vd7YICfq7OjpoY6kHf9xs2nT58tWLzs6Yt3EHmsAMWUID+3hNgoXl7eU2fOnjx1BigiIy1lbmoiJSV58vSZrNxCPgExiEo0gDAlLzMh0N93774DLe1dDMycEEEIMDfWqaks/f//f0xC6qevv6GiSABqCtAVuVnpk6fNXLdpF0QCHfz9vnTh3P8M//2CwjFdxAQi/n4HegToCpxGAAEzZ2ZuobSUVF52JlQECYBMCQr0B4YFyCN4AdAv6zduDgrwhfKRAMgUYIwAgxMtLLCC3Xv3A+2TlhCC8mEAZIqGuhokRgiC67ceAklzMxMIFw7A4UIxAJly4+YtYLqA8AmAv9+BxOdPnyE8OACZAkygZqbGED5+4OrsBCR3790H4cIByBRgmAGjEJi0IEJ4QEJcNNZ4ALvl1kOgXHVFCcTBuEBCdDAwKyxYtBTKRwLQ0C2vrGVkZFyycA4fNytEBA0AjYiPjQL6HRJNaICZjx8c+UysW7du9fHySEtJ5OPh/PTx/Zt3H0Hif7+7ONk21ZXb2lgBIwGY0YGyp85cBEkhAZQ8/enDq4S4mMS4aB4eHqgQGAD1T5o6A+gKSI5dt2HT5BkLoXJggFG+gM3S1NAAxr20tBQwUkExghScWA2C+QgJsHNwf/7y/enzV9dv3r334AnQs1AJMDh55gI/L1dQgB+y17CYQhBgGkSOKUAAN+jZk8dA95JpChAADQIaASxJf/7+hyV0SQYMDACvTuLhjlzNKAAAAABJRU5ErkJggg=='),
            Sg.Button("", key="clearItems2", bind_return_key=True, tooltip="Remove Searched Items", border_width=0,
                      image_data=b'iVBORw0KGgoAAAANSUhEUgAAABkAAAAZCAYAAADE6YVjAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAABdSURBVEhLY5SRU/7PQGPABKVpCkYtIQmMWkISGLWEJAC3xMDICMqiHBgaG0NZEAAvu+bNncVw/cZNsCClQFNDnSEpOQ3KQ7KElmA0dZEERi0hCYxaQhIYLpYwMAAA9rMLb/+93MUAAAAASUVORK5CYII='),
            Sg.Button("", key="saveSearch2", border_width=0, tooltip="Toggle Saving Searches",
                      image_data=b'iVBORw0KGgoAAAANSUhEUgAAABcAAAAXCAYAAADgKtSgAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsIAAA7CARUoSoAAAAJiSURBVEhLtZVLaBNRFIb/aalSbSbQithJUDRgje60VtxI2yTutL7AR1oTpfiCuBTsQkRF7DZWKgglauPOShVcaC2h4mOGWCoopUiLi2YKomgSpUipcc71pk7SeSH4wXCHcy7/PXPOPWcE72pfAf+JCr4aIi6vwrXL59Hfdx2eVbXc6hzTyEm4P3ELgiBgOqPC5apB+/EY9zrDMHK9cDjSicSdJDySBP/6NXyHMxaJlwvnfsxBfvMOqjqDSMcRvssZJeJGwkXiN25i29ZGhJq3c4s9laK79iK9WAkTmZlPcLuW4UTnMYg11VDk11poVdxrDBO3Ey4ip8eQz31DtCOM6NEwvPUrsXRJBaYmPxgexG5L95UubNzQYClcwvysJt6OUKAFklTPTBlVZYUfSmlfxGHiyb4eZHM55lRG33OXQ7SDQoFWBIMtaGrcgrb9hxYCZAU913UBblFE99VLrGGaNm9iTkdUVuNp6hUyWi+Uw3Ke/z6LgcHHUBQZvnVrWU5Z0dJv+TZrzp6OYm/bLjwYfISRl6PcqrstxOcvWQwNP18oGq3jE5Pca4xeON6b4NY/GHbowMMnbHPszEmWUzOshAlDcSLe08tWuhVG2AkTpuJUqGfDKQQDzdzwl6IwUSiYT2xzcQ1ZSbOBpU+NPmJ69u3ZjdipCPeWUlLQcqjzqBNpaE19nF6UCupYGgl0gNHtshSnlt7ZugN1K+rgb/AxkfIcWx1gLa6Rz37F4YMH4NfGg1nxzA5w9A+lwUbYzZ1i2m7fvYdE8r595MTPuV/ssYO+QCjMw+uRMPJCcRb5vwH8BkJuE0gT8P8VAAAAAElFTkSuQmCC'),
            Sg.Button("", key="sendParser2", tooltip="Push results to Parser Tab", border_width=0,
                      image_data=b'iVBORw0KGgoAAAANSUhEUgAAABkAAAAZCAYAAADE6YVjAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAIeSURBVEhLY1TR1P/PQGOA1xIbUx0GF2dHBi0NdQZeXl6Gz58/M1y7cZNhz979DEdOX4GqIgywWuLlbMWQm5UOZt+4eYvh5KkzDJ+AFvABLTI3M2HQUFcDy02aOoNh+77jYDY+gGFJX2sVgybQ5es3bmaYtWgNVBQTpMWFMAT6+zJcB/qsqLoNKoodoFjS31bNICMtxVBWVcdw/+lbqChuoCgtzNDV1sTw+MlTvBYxQWlwEIGCgVgLQACkDqQe5HOQflwAbgkoDkBBRKwFMABSD9IHi0NsAGyJrakumIMvDvABmD6YOegAbImLiyM4FVECQPpB5mADYEtA+QCUTCkBIP2a0KSNDsCW8PDwgPMBJeDp02cMjIyMUB4qAFvy5csXcEajBBw+fZkhND4bykMFYEtARYWZqTFYgBYAbMmePfvBaZ1WAGwJyKsgACoqKAGgAhUbYBYSlWgAMd6/fcUQHxvFcOzoYYYPn7+DJUkBoDxSXVHKwMXOzHDu0nWoKATALbl9/zGDiYE2Q1CAL8OZ0ydJtujRs1cM3BwsQP1+GBbBLQGBnXsPM1iZGYJ9hM1FhMDZi9ewWkSwPgEV5bD6hFiQGBcNruQWLl7GsGLDTvw1IyicQUUFqEQAZVhSwakzZxnq2yfht4RcsGrBFHDuj45PYfjFwA5JwtQE6BaAANUsYWP4CbcAVLzALAABqllibmoCtwAd0CROUAEDAwDjas5sJxYwuwAAAABJRU5ErkJggg=='),
            Sg.Button("", key="revert2", tooltip="Revert to original query", border_width=0,
                      image_data=b'iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsIAAA7CARUoSoAAAAKISURBVEhLY5SRU/7PQEPABKWJAkF+bgzTJrQx8HGzQkUIA6Is+PThFdjg3Kx0Bk0NdTAmFhC0AGT4kgVzGGRlpBmy8ooYvnz5wiAtLQWVJQwIWpAQFwN2cXR8CsP1Ww8ZTp46w+Di5ACVJQwIWgAKlvUbNzN8+vobzN+9dz/YQmkJITCfEMBrAcwQkKEwcPLsFYZnz54zVFeUgIOPECAukj99hrIgIDO3EOyL6opSqAhugNeC6zdugGlzMxMwDQOg4KqormcICvBjyM2Ih4piB8x8/EINUDYYgLz988dXBnYObjCWlRJnsLWxYli3cTtUBQQ8ff6KgfH/X4bI8BAwfeHydagMKkDxASgDbVq3kmHa5H6oCCT8paWksGauBUvXghNAfGwUg6aaPFQUFaBY0NnWBDbM3NQEruHTZ0j48/Lygml0MGn6AoYbN28xdLY2QkVQAdwCkIEa6mrgsAVpmDapj6GjuRKsEcR/+uIdVCUmaGnvBjvA3FgHKoIAcAtArgYBUDKMjk9mWLh4GQMjIyPDqdNnGTJzCsByuADIclAOx1aEsEBpBk1NdYZTZ86C2XwCYuDwhQNmTigDN7h24ybYDHSAN5lSA8AtAJUxZibGROVObACkF2QGOoBbsAdaHLg6O4FpUgAscq8DgwkdwC0A5U5QHBBbxsAASG1udjq4fAKVtugAJQ5agckNlHJA5T8xloDUgMojUN4pq6qDiqICFAtAvgApBFUuB3ZvYzAz0obKYAJQSQtyCKg8AuUdXPkEa6UPKhaqK0vBEfcZmJNBkQdKhiAgA6zNQIUfyNWgYAE5CF8mxNuqALnS1dkRbCAol4MAOKyBloHKKFCmJARo3GxhYAAAASz0wYbe/AkAAAAASUVORK5CYII='),
            Sg.Check("Overwrite Parser", key="oParser2", tooltip="Erase /Overwrite First Parser Tab", visible=False),
            Sg.Check("Generate New Parser Tabs", tooltip="Autcreate Parser Tabs", key="autoParserTab2", visible=False)],

        [Sg.Text("VM's: 0, Online: 0, Offline: 0", key="vSphereCounters")
         # [Sg.Button("Power On", border_width=0), Sg.Button("Power Off", border_width=0),
         # Sg.Button("Connect NIC", border_width=0), Sg.Button("Disconnect NIC", border_width=0),
         # Sg.Button("SSH", border_width=0), Sg.Button("Find IP's", key = "findIPs", border_width=0),
         # Sg.Button("View Logs", border_width=0)

         ]],
        right_click_menu=vSphere_RCM)]]

    logTab = [[Sg.Multiline("", key="logML", size=(140, 30), horizontal_scroll=True)]]

    genConfigTab = [[Sg.Column([[Sg.Check("Auto Clear Output on Each Query", key="autoClear")], [
        Sg.Check("VSphere API Integration", default=False, key="vSphereAPIEnabled")], [
                                    Sg.Check("Load ACAS Vuln Data to vSphere", default=True, key="getIDs")],
                                # TODO: safe mode will be default enabled:
                                # [Sg.Check("Safe Mode (Only Enable/Allow GET Commands; disable modifications)", key = "safeMode")],
                                [Sg.Button('Clear All Saved Searches', key='clearAllSearches'),
                                 Sg.Button("Clear Solutionizer D0-D3 Data", key="clearSolData")]
                                # [Sg.Check("Save All Output to Log DIR:"), Sg.Input("", key="logDIR")],

                                ], key="genCol")]]

    emailConfigTab = [[Sg.Column([[Sg.Text("Email Sender:", size=(20, 1)), Sg.Input("", key="emailSender")],
                                  [Sg.Text("Email Recipient(s) (CSV's):", size=(20, 1)),
                                   Sg.Input("", key="emailRecipient")]

                                  ])]]

    pluginConfigTab = [[Sg.Multiline("", key="exemptPluginsML", size=(100, 15))]]

    wordcloudConfigTab = [
        [Sg.Column([[Sg.Text("WordCloud Stop Words:"), Sg.Input("{}".format(defaultStopWords), key="cloudStopWords")]

                    ])]]

    # UNUSED:
    scanConfigTab = [[Sg.Column([[Sg.Text("Scan Name:", size=(15, 1)), Sg.Input("", key="name")],

                                 [Sg.Text("Repository ID:", size=(15, 1)), Sg.Input("", key='scanRepoID')],
                                 [Sg.Text("Scan Description:", size=(15, 1)), Sg.Input("", key='description')],
                                 [Sg.Text("Email When Complete? (True or False):", size=(15, 1)),
                                  Sg.Input("", key='email_complete')],
                                 [Sg.Text("Email When Started? (True or False)", size=(15, 1)),
                                  Sg.Input("", key='email_launch')],
                                 [Sg.Text("Time limit:", size=(15, 1)), Sg.Input("", key='max_time')],
                                 [Sg.Text("Policy ID:", size=(15, 1)), Sg.Input("", key='policy_id')],
                                 [Sg.Text("Scan Zone:", size=(15, 1)), Sg.Input("", key='scan_zone')],
                                 [Sg.Text("Targets (list)", size=(15, 1)), Sg.Input("", key='targets')],
                                 [Sg.Text("Virtual Host Logic? (True or False)", size=(15, 1)),
                                  Sg.Input("", key='vhosts')],
                                 [Sg.Button("Save Current Scan Configuration", key='saveScan'),
                                  Sg.Button("Load Scan Configuration", key='loadScan')]
                                 ])]]

    exemptACASToggle = ["Do Not Change", "Blank", "False", "True"]
    VMQuarantineImpactToggle = ["Do Not Change", "None", "Minor", "Major", "Catastrophic"]

    parserACAS = [[Sg.Text("Exempt: "), Sg.Combo(exemptACASToggle, default_value="Do Not Change", key="ACASExempt")], [
        Sg.Text("Reason: "), Sg.Input("", key="ACASReason")], [
                      Sg.Text("Notes:   "), Sg.Input("", key="ACASNotes")]]

    parserVSPHERE = [[Sg.Text("Quarantine Impact:"),
                      Sg.Combo(VMQuarantineImpactToggle, default_value="Do Not Change", key="VMImpact")], [
                         Sg.Text("Reason:                "), Sg.Input("", key="VMReason")], [
                         Sg.Text("Notes:                  "), Sg.Input("", key="VMNotes")]]

    parserTab1 = [[Sg.Multiline("", key="parserML", size=(140, 25), horizontal_scroll=True)],
                  [Sg.Frame("ACAS Bulk Data Modification", parserACAS)],

                  [Sg.Button("Email ACAS Parsed Output"),
                   Sg.Button("Apply ACAS Manual Changes"),
                   Sg.Button("Apply ACAS Bulk Changes", key="parserApplyBulkACAS"),
                   # Sg.Button("Apply vSphere Bulk Changes", key = "parserApplyBulkVM"),
                   ]]
    parserTab2 = [[Sg.Multiline("", key="parserML2", size=(140, 25), horizontal_scroll=True)],
                  [  # Sg.Frame("ACAS Bulk Data Modification", parserACAS),
                      Sg.Frame("vSphere Bulk Data Modification", parserVSPHERE)],

                  [Sg.Button("Email vSphere Parsed Output"),
                   Sg.Button("Apply vSphere Manual Changes"),
                   # Sg.Button("Apply ACAS Bulk Changes", key = "parserApplyBulkACAS"),
                   Sg.Button("Apply vSphere Bulk Changes", key="parserApplyBulkVM"),
                   ]]

    parserTab = [[Sg.TabGroup([[Sg.Tab("ACAS", parserTab1), Sg.Tab("vSphere", parserTab2)]])]]

    scannerTab = [[Sg.Column([[Sg.Text("Scan Name:", size=(15, 1)), Sg.Input("", key="name")],

                              [Sg.Text("Repository ID:", size=(15, 1)), Sg.Input("", key='scanRepoID')],
                              [Sg.Text("Scan Description:", size=(15, 1)), Sg.Input("", key='description')],
                              [Sg.Text("Creds (list):", size=(15, 1)), Sg.Input("", key='scanCreds')],
                              # [Sg.Text("Email When Complete? (True or False):", size = (15,1)), Sg.Input("", key='email_complete')],
                              # [Sg.Text("Email When Started? (True or False)", size = (15,1)), Sg.Input("", key='email_launch')],
                              # [Sg.Text("Time limit:", size = (15,1)), Sg.Input("", key='max_time')],
                              [Sg.Text("Policy ID:", size=(15, 1)), Sg.Input("", key='policy_id')],
                              # [Sg.Text("Scan Zone:", size = (15,1)), Sg.Input("", key='scan_zone')],
                              [Sg.Text("Targets (list)", size=(15, 1)), Sg.Input("", key='targets')],
                              # [Sg.Text("Virtual Host Logic? (True or False)", size = (15,1)), Sg.Input("", key='vhosts')],
                              [Sg.Text("", size=(43, 1)),
                               Sg.Button("", key='saveScan', border_width=0, tooltip="Save Scan Data",
                                         image_data=b'iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsIAAA7CARUoSoAAAAHsSURBVEhLY5SRU/7PQEPABKWJAgnRwWBMCiDJAk1NdTAmBbCACHNjHYbqihIGXl5esCAyuH7jJkNWQRWUhwqmT2xn0FBXg/IQ4PPnzwytHT0MJ89egVhQU1nKcA1o0MlTZ8AKkAHIAlxg0tQZDJoamD4yNzMBO9gvNAFiAQ8PD9jwdZt2gRUQC67fegjG2ICZiTGYJikOyAEDb8HmNQsZcjPioTwEyMtMYNi0egGUhxsQtGDt+k0MQQF+DK4OllARBjA70N+XYd2GzVAR3AAcyfjAgqVrGfj4eBmqgKkClPxAABSB6zduBssRAkTFwaTpC8AGgvIJCIPYIDFiANGR3NLexXDj5i0wBrGJBURbwCcgxpCZXwnGIDaxgGgLyAU0twBcH+zfsZbh5OkzWMsicgCoLNLW1GDwDYmHWAAqTUEFHqhMogb48uULMCF0g0tTgjUaHzcrw8a1KxgqquvBGkAA5KCO1kYG/+AIhk9ff4PFcAGCceDi7AimT546DaZBAMaGyeEDeC349OEVQ0JsFMOpM2cZGJg5oaJAAGSDxEByIDX4ADMfv1ADlI0BmusqGDSAFcr16zcZRIT5GTTVleGYD5ijQZWNsqIiw+Fjp6A6MAHeOACVpIQi/tmz5wzRSTlQHiagcbOFgQEAyZqgC7mrf3oAAAAASUVORK5CYII='),
                               Sg.Button("", key='loadScan', border_width=0, tooltip="Load Scan Data",
                                         image_data=b'iVBORw0KGgoAAAANSUhEUgAAABUAAAAYCAYAAAAVibZIAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsIAAA7CARUoSoAAAAFFSURBVEhLY5SRU/7PQGUANvTTh1cMQQF+DLy8vFBhBLhx8xbD9VsPoTziANjQzpYqBjMTY6gQKgAZmplfCeURB8CG7t+xlmHytJkM6zbtggpTBpigNFXB4DEUFLEuDhZQHiYgy1BXZyeG6opShoToYKgIKiDL0JNnrzCs37iZIT42isHcWAcqigBkh+mk6QvABne0NmIYTFFE4TKYBUrjBKBw09BQg/JwA5DBMQmpDE9fvCPOpYyMjHgxOiDo0gVL10JZ2EFeZgIDAzCLV1TXg10JAhSFKcjAQH9fsIGgFAEDZBuKy0AQIMtQUEyDDFy4eBmGgSBAlqG79+5jaOvowRneZBnKJyDGsPvAcSgPE1AUUbgATQwFl/zTJ7YzaKhjzzXXb9xkyCqogvKIA/CKLzjAn4GXD7PiAxlKVsUHZVMJMDAAAEndb3Vk/Y2FAAAAAElFTkSuQmCC'),
                               Sg.Button("", key="launchScan", tooltip="Launch Scan", border_width=0,
                                         image_data=b'iVBORw0KGgoAAAANSUhEUgAAABoAAAAaCAYAAACpSkzOAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAM/SURBVEhLvZZdSFNhGMcftS6khuVF5cy6CPTMutOUrsrSqCDNDPowm1BRmZEXZTqzD1FZH1S40qIuZtkH0bIVSBSZt02NgmqbF5XglnQR6RZeRKzzf8/7Hs/cR1tGP5jnvM97tv95Pl8TMhYtCdB/IJFf/wn6BamUNn8u+0xlWh6Nff9KxopyKlpTQAYpi1sVnC43Hawx8dU0hEqL11JlxQ7S6XT0orePPsg//MoxwPayZVFT3RHaWbmXvKPfmG0G+xsH8KLdcpHyl+dSt/0JtV3uoISkZL4rcPPrJHHlCCJd1hu01CBRXcNJsnRYw4iEJ2YhIZKxMJ3KjXvIMfiO74SSn5fLriJsICR0eTnLSK9P46tJkHAh4vvxk9nwbCAQoP7X79laACGXe4ivFIKKAQk+VLWPr0IpKdsWJGJuOc3uEUbhYeDXBL183kOW9mvU/fgZswE1dHgAIkjw6nVl6gdfAK3m86pINI7X15Lf7yfrzS5uUVA9MjebWFmuLFxPKXPmsU3drJlkt91j5dty1sJsWuAVEN4IL6d6A5hHUuZiysvNkUv1qioCzrQ2sberNTVySzAQECJ4qQa5dxwDgyEiIBHVhAd8Ph/ZHtm5WcmXlJUpi5wIEg8HRLqs18nj/UIHqmu4NZiEbIMUQHgEHq+XnE43FcpVFilkWjDfOiwXmEi5cXfEl0pEgpF0jAsk3NE/SLI42xwbH2fXSBSuWqF6Ek0EJKWkpJ7Cjc8/QR8/j8gxfkMP7T0oQ9q+dQvpZifLtrfsYQHC3dR4jIy7ytn67v0H9Gl4lN1HIuJk6LxtY/2xeVMxVe83cqtSOH1ynyC0ovRjIUQI/SRARWnFTEerqb1NyQeaN1x1RUIVQjiuXGplXd371BbUI5237jAx4UXV4fqYmleLKoSO1h5eYrwAhNEre4EqjMcLLUwI3pSWbGQGLdow4sSUpEy+Ur4jcufxeNk1GkzIICnlrAXTV3vW4PRM1+uZAMoaBYFwIpRiOkSDCYnzQ4DBir7QgqMaQADHtFN+kYKiDTGHkg1VdDcGKn7M6XJFbDwUCXLVbD5HrqFhbo2NuP45wUwb8Xj+OPvCoVZdLKCk/0aEiOg3a911+fbK3RAAAAAASUVORK5CYII=')],
                              [Sg.Text("")],
                              [Sg.Text("", size=(1, 15))],
                              [Sg.Text("ScanID/ResultID:"),
                               Sg.Combo(scanHistList, size=(20, 1), readonly=True, key="scanIDDD"),
                               Sg.Combo(resultScanHistList, size=(20, 1), readonly=True, key="resultIDDD")],
                              [Sg.Button("Query Scan Status", size=(23, 1), key="queryScan"),
                               Sg.Button("Query Result Status", size=(23, 1), key="queryResult"),
                               Sg.Button("Update", key="updateProgress")],
                              [Sg.ProgressBar(10, orientation='h', size=(35, 5), bar_color=("lightblue", "grey"),
                                              key="progress")
                               ]], vertical_alignment="top"),

                   # RIGHT SIDE COLUMN:
                   Sg.Column([[Sg.Multiline("", key="scanOutput", size=(72, 33))], [
                       Sg.Button("", key="clearScanOutput", border_width=0,
                                 image_data=b'iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsIAAA7CARUoSoAAAAKISURBVEhLY5SRU/7PQEPABKWJAkF+bgzTJrQx8HGzQkUIA6Is+PThFdjg3Kx0Bk0NdTAmFhC0AGT4kgVzGGRlpBmy8ooYvnz5wiAtLQWVJQwIWpAQFwN2cXR8CsP1Ww8ZTp46w+Di5ACVJQwIWgAKlvUbNzN8+vobzN+9dz/YQmkJITCfEMBrAcwQkKEwcPLsFYZnz54zVFeUgIOPECAukj99hrIgIDO3EOyL6opSqAhugNeC6zdugGlzMxMwDQOg4KqormcICvBjyM2Ih4piB8x8/EINUDYYgLz988dXBnYObjCWlRJnsLWxYli3cTtUBQQ8ff6KgfH/X4bI8BAwfeHydagMKkDxASgDbVq3kmHa5H6oCCT8paWksGauBUvXghNAfGwUg6aaPFQUFaBY0NnWBDbM3NQEruHTZ0j48/Lygml0MGn6AoYbN28xdLY2QkVQAdwCkIEa6mrgsAVpmDapj6GjuRKsEcR/+uIdVCUmaGnvBjvA3FgHKoIAcAtArgYBUDKMjk9mWLh4GQMjIyPDqdNnGTJzCsByuADIclAOx1aEsEBpBk1NdYZTZ86C2XwCYuDwhQNmTigDN7h24ybYDHSAN5lSA8AtAJUxZibGROVObACkF2QGOoBbsAdaHLg6O4FpUgAscq8DgwkdwC0A5U5QHBBbxsAASG1udjq4fAKVtugAJQ5agckNlHJA5T8xloDUgMojUN4pq6qDiqICFAtAvgApBFUuB3ZvYzAz0obKYAJQSQtyCKg8AuUdXPkEa6UPKhaqK0vBEfcZmJNBkQdKhiAgA6zNQIUfyNWgYAE5CF8mxNuqALnS1dkRbCAol4MAOKyBloHKKFCmJARo3GxhYAAAASz0wYbe/AkAAAAASUVORK5CYII='),
                       Sg.Button("", key="clearScanOutput", border_width=0,
                                 image_data=b'iVBORw0KGgoAAAANSUhEUgAAABoAAAAWCAYAAADeiIy1AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsIAAA7CARUoSoAAAALYSURBVEhLvZVbSJNhGMf/driIdEUXUdPqIvBAXXWyrtLcgoJZKkg0sxVEttRA8mxBpWtpWLiaRWFD5mVaCl20mbsrqe4CD3ddOKOLCDW6iKj3//ht9bl9Ou3wk4+98zl973NaUtrmrT/wH1imfSbE1OePsOTslYfnxZDwjQrzD8Jx4jhSUlLk+/T0NDru3kMw9Eq+L8SCN8pK3wJ/lwcVzrMYGRtHrvWwPDw31lWLjDoLYXgj0+qVaKi7iOzduxAOT6Km4TImPnzSpLOkbliHVtdVmM0bMfz6DVzum5j68k2T6okJxNzzTQuP5mNmZgbN19sw/PadJo2PNWcfKsvLkJycjN4n/Whxt8G0dr0mnUUX6Pc6eLz34ev2xxgYwRd0lJZIilm/R9096BsIaFItENPk9bQj1WzG4IuQukUrsHyVprJIvn9FU30N8g7kYCIchrOiStIpzdDpuSVBgoNDqhaXlh6EKFv6oC/65AWIBGIxWXBLXi5CgWfYs2ObCJdC9s7t4oO+6JPBSLS9H6siHik6Jm17Q3WS97ZLuipRqEsbd8sV8UFf9BlBN0fMZW2TC87KKqwxmeD3PUBjdbnkPQKLrtsKSkYd6tKGtvQxt81XaJ86Rsbfw366XLrwVKkdQyoVPtVFVktuNBUsdCA4pDrNLmPALu3tfy6yeMy7GWi433JIck2HSeqPQ8mHZ/6PAakzXxAyb6DI8LJZ+p4OwFZYjEDopTw8cxR4Q+ro0hkHw0CcLb/voWwI3qCj06cbXp6bWz0iow51aWNE3ECySFVxN6WlosRxRm5gBGXUoS5tjBZsTCCHvQjejnaV+0nJ/dxFGg/q2AqKxYa2BTarJvlFNJBJ7Tf3tXqcVLuO9Th3oT7hPSeojUAb2laeLxNf9BlBdl1P1x0pOBkZHUNArY8/waq2QlZmhpxH1fDyBaJLldsgMyNdhH8LBqlVv2Mc3pjfo38D8BP4+EBAHaJTGQAAAABJRU5ErkJggg==')
                   ]])]]

    remTab = [[Sg.Multiline("", key="remML", size=(140, 25), horizontal_scroll=True)],
              [Sg.Button("Save Rem Output"), Sg.Button("Email Rem Output")
               ]]

    solFilterTab = [[Sg.Multiline("", key="filteredSolutionML", horizontal_scroll=True, size=(140, 15))]]
    recSolTab = [[Sg.Multiline("", key="recSolutionML", horizontal_scroll=True, size=(140, 15))],
                 [Sg.Text("D0"), Sg.Combo(easyList, key="easy", size=(20, 1)),
                  Sg.Button("", border_width=0, image_size=(12, 12), enable_events=True, key="addDiffFilterD0",
                            image_data=b'iVBORw0KGgoAAAANSUhEUgAAABkAAAAZCAYAAADE6YVjAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAJzSURBVEhLvZXBTxNBFMa/CuFiGxLjQdroRRNYEsRQ8awgfwUENWpSQQkIbUSNMcZoUlCLKMGoUYn9H9Ba9Kwp0QtduHfBRGNie1/ne+5Cl+5uQYq/ZDrdnZnv7bz35k3g4KHDJnaZPVa/q9Q1Nu67bf13JTX1EHUNDdgbDOHX7yLq1f+2o22Idh7H4EAM8/PvrJneeLornhjDq7k0isUiwuEmaC3NaFWNLOnLyKtmGKsIhUI419+LieSkjLnhauRYNCoi3V0nMTQYQ6vWYo04WcrrePx0FtmFT/IRX3M5a8RJhZH9B5pgmiaS9+6g53SX9dafzIcFJK7fQiAQwI+1VevtBo7Acwc0kH7zYssGCOdyDddSowLuhG1qesY8orWb7zNZNfff4FpqUMvWZVt3F910ojOK2ScpMe7G3ftJ6W+OJ6R3I3Z5GJ+/5BxuE3c9Sj2QLGKQ/cjnVVap5gc1qEVNGzGSyX6UNPXKou1ADWpR00aMFAqGpGCtoBbPkE09f/TlFfR0n5IX5TAGur5iPSl3qXmk78wF6YmmNePGtbj19BceWp4dm6q1SyVN1VYNya72jg5EImHfzCK9/eelT8+9lN4LZhhD8G1xUZ5lJzRQ7padwpJETRsxwngUDENq0U6hBoNeHmMxMjI8imAwiOmZZ/LSCwaZzQ8WTGpRcx376P+XskKYAAW11bevn2/7YNJNfWcvIqIOoh1wG0cKc1B9kExm+d4qnMs1XLvZAKk4Jz+/r8nXDAxdxaUrI77JwDHO4Vyu4Vo3XG9GMhYfleu3VCopgbAE3HH9qkLJjGSQef1OTmwUxM14GqklFe6qPcAfpNSjHYHAlh4AAAAASUVORK5CYII='),
                  Sg.Button("", border_width=0, image_size=(12, 12), key="removeDiffFilterD0",
                            image_data=b'iVBORw0KGgoAAAANSUhEUgAAABkAAAAZCAYAAADE6YVjAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAJrSURBVEhLtZXLaxNRFMa/2NKNCQUVbBN0o9BOoVYaoy61tX+FIroQYqvFR1NEQUREIa3aWh8FBR/YnYjLaprq1mqKLsyj+0wrKILJfpzv9N46Y5LGTNIf3GTmPr5z73nc8e3YucvCBrNJ/W8oTa2tW66p57JMTN5BU0sLNvsD+PW7gGb7uXtPN8KRfRgajGJ29q2aWZmK7oqNjuDpixkUCgUEg+0wOjvQZTeSzuaQsZtpLiMQCODk8aMYi4/LWDnKGtkbDotIf98hDA9F0WV0qhE36UwW9x5MIzn/QTbxJZVSI25KjGxra4dlWYjfvI6BI32qd30Sc/MYvXwVPp8PP1aWVe9fXIHnCWhg5vmT/zZAOJdruJYaJfAkbJNTD63dRo/1LpG053qDa6lBLa3LtuYuuml/JIzp+xNi3CvRM+ew8CnldhuNvHr9RnbwLZ1Re/IONahFTX0SiUki+V7StFIW1QI1qEVNjRjJ501JwUZBLdaQppk/2dwSBvoPS4eTG7fiyGaX1NtqERJdlMQwOnDlUky9rcJx1o6m6t1lu7lqq4ZkV09vL0KhYN2ZpWGGMQRfFxflXU5CA0631AuvJGpqxAjjkTdNuYvqhRoMujPGa8W4dXsbDh6I4NHUXRnwCl31ceEzfn5fUT2OwPO6nrNzm5edV7iWWUUtJ65bmAmQt4/68tnjmguTbjp24hRCdiHqgGtcKcxBpiQn13IizuUarv3XACmpE/qSuxkcvoDTZ8+vmwwc4xzO5RpnHJyUfLQ0I7GL8vktFou2QFAq2/X5zeQkI/1+v8RgfOy2jJWjopFGUuKuxgP8ATlXoGLsydy5AAAAAElFTkSuQmCC'),
                  Sg.Text("D1"),
                  Sg.Combo(interList, key="intermediate", size=(20, 1)),
                  Sg.Button("", border_width=0, image_size=(12, 12), enable_events=True, key="addDiffFilterD1",
                            image_data=b'iVBORw0KGgoAAAANSUhEUgAAABkAAAAZCAYAAADE6YVjAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAJzSURBVEhLvZXBTxNBFMa/CuFiGxLjQdroRRNYEsRQ8awgfwUENWpSQQkIbUSNMcZoUlCLKMGoUYn9H9Ba9Kwp0QtduHfBRGNie1/ne+5Cl+5uQYq/ZDrdnZnv7bz35k3g4KHDJnaZPVa/q9Q1Nu67bf13JTX1EHUNDdgbDOHX7yLq1f+2o22Idh7H4EAM8/PvrJneeLornhjDq7k0isUiwuEmaC3NaFWNLOnLyKtmGKsIhUI419+LieSkjLnhauRYNCoi3V0nMTQYQ6vWYo04WcrrePx0FtmFT/IRX3M5a8RJhZH9B5pgmiaS9+6g53SX9dafzIcFJK7fQiAQwI+1VevtBo7Acwc0kH7zYssGCOdyDddSowLuhG1qesY8orWb7zNZNfff4FpqUMvWZVt3F910ojOK2ScpMe7G3ftJ6W+OJ6R3I3Z5GJ+/5BxuE3c9Sj2QLGKQ/cjnVVap5gc1qEVNGzGSyX6UNPXKou1ADWpR00aMFAqGpGCtoBbPkE09f/TlFfR0n5IX5TAGur5iPSl3qXmk78wF6YmmNePGtbj19BceWp4dm6q1SyVN1VYNya72jg5EImHfzCK9/eelT8+9lN4LZhhD8G1xUZ5lJzRQ7padwpJETRsxwngUDENq0U6hBoNeHmMxMjI8imAwiOmZZ/LSCwaZzQ8WTGpRcx376P+XskKYAAW11bevn2/7YNJNfWcvIqIOoh1wG0cKc1B9kExm+d4qnMs1XLvZAKk4Jz+/r8nXDAxdxaUrI77JwDHO4Vyu4Vo3XG9GMhYfleu3VCopgbAE3HH9qkLJjGSQef1OTmwUxM14GqklFe6qPcAfpNSjHYHAlh4AAAAASUVORK5CYII='),
                  Sg.Button("", border_width=0, image_size=(12, 12), key="removeDiffFilterD1",
                            image_data=b'iVBORw0KGgoAAAANSUhEUgAAABkAAAAZCAYAAADE6YVjAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAJrSURBVEhLtZXLaxNRFMa/2NKNCQUVbBN0o9BOoVYaoy61tX+FIroQYqvFR1NEQUREIa3aWh8FBR/YnYjLaprq1mqKLsyj+0wrKILJfpzv9N46Y5LGTNIf3GTmPr5z73nc8e3YucvCBrNJ/W8oTa2tW66p57JMTN5BU0sLNvsD+PW7gGb7uXtPN8KRfRgajGJ29q2aWZmK7oqNjuDpixkUCgUEg+0wOjvQZTeSzuaQsZtpLiMQCODk8aMYi4/LWDnKGtkbDotIf98hDA9F0WV0qhE36UwW9x5MIzn/QTbxJZVSI25KjGxra4dlWYjfvI6BI32qd30Sc/MYvXwVPp8PP1aWVe9fXIHnCWhg5vmT/zZAOJdruJYaJfAkbJNTD63dRo/1LpG053qDa6lBLa3LtuYuuml/JIzp+xNi3CvRM+ew8CnldhuNvHr9RnbwLZ1Re/IONahFTX0SiUki+V7StFIW1QI1qEVNjRjJ501JwUZBLdaQppk/2dwSBvoPS4eTG7fiyGaX1NtqERJdlMQwOnDlUky9rcJx1o6m6t1lu7lqq4ZkV09vL0KhYN2ZpWGGMQRfFxflXU5CA0631AuvJGpqxAjjkTdNuYvqhRoMujPGa8W4dXsbDh6I4NHUXRnwCl31ceEzfn5fUT2OwPO6nrNzm5edV7iWWUUtJ65bmAmQt4/68tnjmguTbjp24hRCdiHqgGtcKcxBpiQn13IizuUarv3XACmpE/qSuxkcvoDTZ8+vmwwc4xzO5RpnHJyUfLQ0I7GL8vktFou2QFAq2/X5zeQkI/1+v8RgfOy2jJWjopFGUuKuxgP8ATlXoGLsydy5AAAAAElFTkSuQmCC'),

                  Sg.Text("D2"), Sg.Combo(hardList, key="hard", size=(20, 1)),
                  Sg.Button("", border_width=0, image_size=(12, 12), enable_events=True, key="addDiffFilterD2",
                            image_data=b'iVBORw0KGgoAAAANSUhEUgAAABkAAAAZCAYAAADE6YVjAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAJzSURBVEhLvZXBTxNBFMa/CuFiGxLjQdroRRNYEsRQ8awgfwUENWpSQQkIbUSNMcZoUlCLKMGoUYn9H9Ba9Kwp0QtduHfBRGNie1/ne+5Cl+5uQYq/ZDrdnZnv7bz35k3g4KHDJnaZPVa/q9Q1Nu67bf13JTX1EHUNDdgbDOHX7yLq1f+2o22Idh7H4EAM8/PvrJneeLornhjDq7k0isUiwuEmaC3NaFWNLOnLyKtmGKsIhUI419+LieSkjLnhauRYNCoi3V0nMTQYQ6vWYo04WcrrePx0FtmFT/IRX3M5a8RJhZH9B5pgmiaS9+6g53SX9dafzIcFJK7fQiAQwI+1VevtBo7Acwc0kH7zYssGCOdyDddSowLuhG1qesY8orWb7zNZNfff4FpqUMvWZVt3F910ojOK2ScpMe7G3ftJ6W+OJ6R3I3Z5GJ+/5BxuE3c9Sj2QLGKQ/cjnVVap5gc1qEVNGzGSyX6UNPXKou1ADWpR00aMFAqGpGCtoBbPkE09f/TlFfR0n5IX5TAGur5iPSl3qXmk78wF6YmmNePGtbj19BceWp4dm6q1SyVN1VYNya72jg5EImHfzCK9/eelT8+9lN4LZhhD8G1xUZ5lJzRQ7padwpJETRsxwngUDENq0U6hBoNeHmMxMjI8imAwiOmZZ/LSCwaZzQ8WTGpRcx376P+XskKYAAW11bevn2/7YNJNfWcvIqIOoh1wG0cKc1B9kExm+d4qnMs1XLvZAKk4Jz+/r8nXDAxdxaUrI77JwDHO4Vyu4Vo3XG9GMhYfleu3VCopgbAE3HH9qkLJjGSQef1OTmwUxM14GqklFe6qPcAfpNSjHYHAlh4AAAAASUVORK5CYII='),
                  Sg.Button("", border_width=0, image_size=(12, 12), key="removeDiffFilterD2",
                            image_data=b'iVBORw0KGgoAAAANSUhEUgAAABkAAAAZCAYAAADE6YVjAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAJrSURBVEhLtZXLaxNRFMa/2NKNCQUVbBN0o9BOoVYaoy61tX+FIroQYqvFR1NEQUREIa3aWh8FBR/YnYjLaprq1mqKLsyj+0wrKILJfpzv9N46Y5LGTNIf3GTmPr5z73nc8e3YucvCBrNJ/W8oTa2tW66p57JMTN5BU0sLNvsD+PW7gGb7uXtPN8KRfRgajGJ29q2aWZmK7oqNjuDpixkUCgUEg+0wOjvQZTeSzuaQsZtpLiMQCODk8aMYi4/LWDnKGtkbDotIf98hDA9F0WV0qhE36UwW9x5MIzn/QTbxJZVSI25KjGxra4dlWYjfvI6BI32qd30Sc/MYvXwVPp8PP1aWVe9fXIHnCWhg5vmT/zZAOJdruJYaJfAkbJNTD63dRo/1LpG053qDa6lBLa3LtuYuuml/JIzp+xNi3CvRM+ew8CnldhuNvHr9RnbwLZ1Re/IONahFTX0SiUki+V7StFIW1QI1qEVNjRjJ501JwUZBLdaQppk/2dwSBvoPS4eTG7fiyGaX1NtqERJdlMQwOnDlUky9rcJx1o6m6t1lu7lqq4ZkV09vL0KhYN2ZpWGGMQRfFxflXU5CA0631AuvJGpqxAjjkTdNuYvqhRoMujPGa8W4dXsbDh6I4NHUXRnwCl31ceEzfn5fUT2OwPO6nrNzm5edV7iWWUUtJ65bmAmQt4/68tnjmguTbjp24hRCdiHqgGtcKcxBpiQn13IizuUarv3XACmpE/qSuxkcvoDTZ8+vmwwc4xzO5RpnHJyUfLQ0I7GL8vktFou2QFAq2/X5zeQkI/1+v8RgfOy2jJWjopFGUuKuxgP8ATlXoGLsydy5AAAAAElFTkSuQmCC'),

                  Sg.Text("D3"), Sg.Combo(insaneList, key="insane", size=(20, 1)),
                  Sg.Button("", border_width=0, image_size=(12, 12), enable_events=True, key="addDiffFilterD3",
                            image_data=b'iVBORw0KGgoAAAANSUhEUgAAABkAAAAZCAYAAADE6YVjAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAJzSURBVEhLvZXBTxNBFMa/CuFiGxLjQdroRRNYEsRQ8awgfwUENWpSQQkIbUSNMcZoUlCLKMGoUYn9H9Ba9Kwp0QtduHfBRGNie1/ne+5Cl+5uQYq/ZDrdnZnv7bz35k3g4KHDJnaZPVa/q9Q1Nu67bf13JTX1EHUNDdgbDOHX7yLq1f+2o22Idh7H4EAM8/PvrJneeLornhjDq7k0isUiwuEmaC3NaFWNLOnLyKtmGKsIhUI419+LieSkjLnhauRYNCoi3V0nMTQYQ6vWYo04WcrrePx0FtmFT/IRX3M5a8RJhZH9B5pgmiaS9+6g53SX9dafzIcFJK7fQiAQwI+1VevtBo7Acwc0kH7zYssGCOdyDddSowLuhG1qesY8orWb7zNZNfff4FpqUMvWZVt3F910ojOK2ScpMe7G3ftJ6W+OJ6R3I3Z5GJ+/5BxuE3c9Sj2QLGKQ/cjnVVap5gc1qEVNGzGSyX6UNPXKou1ADWpR00aMFAqGpGCtoBbPkE09f/TlFfR0n5IX5TAGur5iPSl3qXmk78wF6YmmNePGtbj19BceWp4dm6q1SyVN1VYNya72jg5EImHfzCK9/eelT8+9lN4LZhhD8G1xUZ5lJzRQ7padwpJETRsxwngUDENq0U6hBoNeHmMxMjI8imAwiOmZZ/LSCwaZzQ8WTGpRcx376P+XskKYAAW11bevn2/7YNJNfWcvIqIOoh1wG0cKc1B9kExm+d4qnMs1XLvZAKk4Jz+/r8nXDAxdxaUrI77JwDHO4Vyu4Vo3XG9GMhYfleu3VCopgbAE3HH9qkLJjGSQef1OTmwUxM14GqklFe6qPcAfpNSjHYHAlh4AAAAASUVORK5CYII='),
                  Sg.Button("", border_width=0, image_size=(12, 12), key="removeDiffFilterD3",
                            image_data=b'iVBORw0KGgoAAAANSUhEUgAAABkAAAAZCAYAAADE6YVjAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAJrSURBVEhLtZXLaxNRFMa/2NKNCQUVbBN0o9BOoVYaoy61tX+FIroQYqvFR1NEQUREIa3aWh8FBR/YnYjLaprq1mqKLsyj+0wrKILJfpzv9N46Y5LGTNIf3GTmPr5z73nc8e3YucvCBrNJ/W8oTa2tW66p57JMTN5BU0sLNvsD+PW7gGb7uXtPN8KRfRgajGJ29q2aWZmK7oqNjuDpixkUCgUEg+0wOjvQZTeSzuaQsZtpLiMQCODk8aMYi4/LWDnKGtkbDotIf98hDA9F0WV0qhE36UwW9x5MIzn/QTbxJZVSI25KjGxra4dlWYjfvI6BI32qd30Sc/MYvXwVPp8PP1aWVe9fXIHnCWhg5vmT/zZAOJdruJYaJfAkbJNTD63dRo/1LpG053qDa6lBLa3LtuYuuml/JIzp+xNi3CvRM+ew8CnldhuNvHr9RnbwLZ1Re/IONahFTX0SiUki+V7StFIW1QI1qEVNjRjJ501JwUZBLdaQppk/2dwSBvoPS4eTG7fiyGaX1NtqERJdlMQwOnDlUky9rcJx1o6m6t1lu7lqq4ZkV09vL0KhYN2ZpWGGMQRfFxflXU5CA0631AuvJGpqxAjjkTdNuYvqhRoMujPGa8W4dXsbDh6I4NHUXRnwCl31ceEzfn5fUT2OwPO6nrNzm5edV7iWWUUtJ65bmAmQt4/68tnjmguTbjp24hRCdiHqgGtcKcxBpiQn13IizuUarv3XACmpE/qSuxkcvoDTZ8+vmwwc4xzO5RpnHJyUfLQ0I7GL8vktFou2QFAq2/X5zeQkI/1+v8RgfOy2jJWjopFGUuKuxgP8ATlXoGLsydy5AAAAAElFTkSuQmCC'),
                  ]]
    d0Tab = [[Sg.Multiline("", key="d0ML", horizontal_scroll=True, size=(140, 15))]]
    d1Tab = [[Sg.Multiline("", key="d1ML", horizontal_scroll=True, size=(140, 15))]]
    d2Tab = [[Sg.Multiline("", key="d2ML", horizontal_scroll=True, size=(140, 15))]]
    d3Tab = [[Sg.Multiline("", key="d3ML", horizontal_scroll=True, size=(140, 15))]]

    solutionTab = [[Sg.Column([[Sg.Multiline("", key="solutionML", horizontal_scroll=True, size=(140, 11))],

                               ############## LEFT SIDE BUTTONS ARE FOR TOP ML, default solutions:
                               [Sg.Button("", border_width=0, tooltip="Recommend Solutions for Content Above",
                                          key="recommendSolutions",
                                          image_data=b'iVBORw0KGgoAAAANSUhEUgAAABkAAAAZCAYAAADE6YVjAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAEpSURBVEhLY5SVU/7PQGPABKVpCuA+Wb16OcOp02fBgpQCM1NjhtDQSCgPagnIgpiEVKgQdcCSBbPhFoGD6+SpM2DOz69fqIJBAGYmCNAlTkaQJY8e3oGyMAE+OWQwOHwiJ68CZWECfHLIYPBEPHrYExsXMECUJaBgARkMw8QGEwwQHVwgg2GYVDB44oRSALZEU0MdzGHn5oHjuXNngcVAYMeOLQwiEpIo8vgwCJibmYBpEECpT2Al5+RpMxlys9IZerp7wRaAqoH///8zJMZFg+UJAZAFGPUJlA0HINeALHFxdoRbsHThHAYPDx+oCtIAzji5duMmVSwAAayWSElJMuzdd4AqFoAA1uA6duwQw7r1GxmCAv0ZrKzsoKLkA6yWUBvQIZ8wMAAAvnyc22rzv28AAAAASUVORK5CYII='),
                                Sg.Button("", key="emailSolutionsTop", border_width=0,
                                          image_data=b'iVBORw0KGgoAAAANSUhEUgAAABoAAAAWCAYAAADeiIy1AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsIAAA7CARUoSoAAAALYSURBVEhLvZVbSJNhGMf/driIdEUXUdPqIvBAXXWyrtLcgoJZKkg0sxVEttRA8mxBpWtpWLiaRWFD5mVaCl20mbsrqe4CD3ddOKOLCDW6iKj3//ht9bl9Ou3wk4+98zl973NaUtrmrT/wH1imfSbE1OePsOTslYfnxZDwjQrzD8Jx4jhSUlLk+/T0NDru3kMw9Eq+L8SCN8pK3wJ/lwcVzrMYGRtHrvWwPDw31lWLjDoLYXgj0+qVaKi7iOzduxAOT6Km4TImPnzSpLOkbliHVtdVmM0bMfz6DVzum5j68k2T6okJxNzzTQuP5mNmZgbN19sw/PadJo2PNWcfKsvLkJycjN4n/Whxt8G0dr0mnUUX6Pc6eLz34ev2xxgYwRd0lJZIilm/R9096BsIaFItENPk9bQj1WzG4IuQukUrsHyVprJIvn9FU30N8g7kYCIchrOiStIpzdDpuSVBgoNDqhaXlh6EKFv6oC/65AWIBGIxWXBLXi5CgWfYs2ObCJdC9s7t4oO+6JPBSLS9H6siHik6Jm17Q3WS97ZLuipRqEsbd8sV8UFf9BlBN0fMZW2TC87KKqwxmeD3PUBjdbnkPQKLrtsKSkYd6tKGtvQxt81XaJ86Rsbfw366XLrwVKkdQyoVPtVFVktuNBUsdCA4pDrNLmPALu3tfy6yeMy7GWi433JIck2HSeqPQ8mHZ/6PAakzXxAyb6DI8LJZ+p4OwFZYjEDopTw8cxR4Q+ro0hkHw0CcLb/voWwI3qCj06cbXp6bWz0iow51aWNE3ECySFVxN6WlosRxRm5gBGXUoS5tjBZsTCCHvQjejnaV+0nJ/dxFGg/q2AqKxYa2BTarJvlFNJBJ7Tf3tXqcVLuO9Th3oT7hPSeojUAb2laeLxNf9BlBdl1P1x0pOBkZHUNArY8/waq2QlZmhpxH1fDyBaJLldsgMyNdhH8LBqlVv2Mc3pjfo38D8BP4+EBAHaJTGQAAAABJRU5ErkJggg=='),
                                Sg.Button("", key="wordCloudSolutionsTop", border_width=0,
                                          image_data=b'iVBORw0KGgoAAAANSUhEUgAAABoAAAAUCAYAAACTQC2+AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsIAAA7CARUoSoAAAAJxSURBVEhLvZVdSJNRGMf/KlLhtkKa1DYqCmxCF4FzC4K+nIWEi1k0LEwHUSmsD5AwISgoii66GH2YBGmx6qIhVnQzN6WI2igoirY36K69RRdh20Caqb3P45lQcx/N0e9ivOd5z/Y7zznPeVZiWLFmGv+B/EST4zDXmaDX6xCPx/EhLCEiSdAsqRITcpNVpKkoR093FyyK5G9IeOu2BwN3PHkJM4ostetw8fxZJBIJuK/0wucPAGWLEBv7hhqjEbvtNth3NSEckdDpOsHvsjGnqKZ6Ja65L8MfGMXJntMZV0wZewZu4kcsBluzI2tmaSJa8ajvCaLyF3QcOyWimSHZkPe+soV30e/ximg6ZZrFlWfEM7NpowU7G3fgeFc34olxEc3Mz4kpxGNjOHTQCYtpPVavMiAUfAmUlosZM6SJnK0OJJNJ3HvwWERyEwy+UL4zAa12KTaY61iKqV94+y4sZswhatlrRzQq4+nzkIjkZsHCCoSlTxgOPMONvj5UabVocexByfQk3ghZKX8KaL+Na6sRU0q3UKgg3Nf7MTj0CG2t+6BfVsnxWRGVMx0qlXMw9EpEC+fchUv8W3QNCBaRle4MrWKztRHB1+/55XygzHz+EVi3beExi5wH9kNWyplSzueW58tn5azVajU/s8hiNrG92BiU3kjbR7BIpVLxoNhQj0wlwKKI9BHW+pm9LBbNtu3Q6ZbDO/iQxyxyX+2FXqeD60gbB+cDtTB7UwNcnYe5uKJfv3N8ttcd7WjnbhyVZfiGRwq6S3QmDfVbuQBIQsWV4o+mSl27XalAs6lWRP4NOng6E9quVCYpMv4fFRfgN6av5EusNbJyAAAAAElFTkSuQmCC'),
                                Sg.Button("", tooltip="Clear Top Output", border_width=0, key="clearTopSolItems",
                                          image_data=b'iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsIAAA7CARUoSoAAAAKISURBVEhLY5SRU/7PQEPABKWJAkF+bgzTJrQx8HGzQkUIA6Is+PThFdjg3Kx0Bk0NdTAmFhC0AGT4kgVzGGRlpBmy8ooYvnz5wiAtLQWVJQwIWpAQFwN2cXR8CsP1Ww8ZTp46w+Di5ACVJQwIWgAKlvUbNzN8+vobzN+9dz/YQmkJITCfEMBrAcwQkKEwcPLsFYZnz54zVFeUgIOPECAukj99hrIgIDO3EOyL6opSqAhugNeC6zdugGlzMxMwDQOg4KqormcICvBjyM2Ih4piB8x8/EINUDYYgLz988dXBnYObjCWlRJnsLWxYli3cTtUBQQ8ff6KgfH/X4bI8BAwfeHydagMKkDxASgDbVq3kmHa5H6oCCT8paWksGauBUvXghNAfGwUg6aaPFQUFaBY0NnWBDbM3NQEruHTZ0j48/Lygml0MGn6AoYbN28xdLY2QkVQAdwCkIEa6mrgsAVpmDapj6GjuRKsEcR/+uIdVCUmaGnvBjvA3FgHKoIAcAtArgYBUDKMjk9mWLh4GQMjIyPDqdNnGTJzCsByuADIclAOx1aEsEBpBk1NdYZTZ86C2XwCYuDwhQNmTigDN7h24ybYDHSAN5lSA8AtAJUxZibGROVObACkF2QGOoBbsAdaHLg6O4FpUgAscq8DgwkdwC0A5U5QHBBbxsAASG1udjq4fAKVtugAJQ5agckNlHJA5T8xloDUgMojUN4pq6qDiqICFAtAvgApBFUuB3ZvYzAz0obKYAJQSQtyCKg8AuUdXPkEa6UPKhaqK0vBEfcZmJNBkQdKhiAgA6zNQIUfyNWgYAE5CF8mxNuqALnS1dkRbCAol4MAOKyBloHKKFCmJARo3GxhYAAAASz0wYbe/AkAAAAASUVORK5CYII='),
                                Sg.Button("", border_width=0,
                                          image_data=b'iVBORw0KGgoAAAANSUhEUgAAABkAAAAZCAYAAADE6YVjAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAACeSURBVEhLY5SRU/7PQGPABKVpCkYtIQmMWkISINmS9Iw0MCYFkGRJZFQkw8LFy8AYxCYWEG0JyND1GzczBPr7MgQF+IHZxFpElCXIFixftpxh2dJlJFlE0BJ0C2CAFIvwWoLLAhgg1iKclhCyAAaIsQhnUS8qIcng4uSA1wJkEBUdxbBrzz6GNy9fQEUQYLQ+IQmMWkISGLWEBMDAAAAMFk2162LZMQAAAABJRU5ErkJggg=='),
                                #############
                                Sg.Combo(solQueries, key="solutionDropDown", enable_events=True, readonly=True,
                                         size=(25, 1), default_value=solQueries[0]),

                                Sg.Button("", border_width=0,
                                          image_data=b'iVBORw0KGgoAAAANSUhEUgAAABkAAAAZCAYAAADE6YVjAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAACrSURBVEhLY5SRU/7PQGPABKVpCkYtIQmMWkISGDhLRMQlGKKio6A8wiAyKpJBVEISysMEWC1xdXZkWLdhE1EWgSxYv3Ezg4uTA1QEE2C1ZPmy5QyB/r4ELYJZAFIL0oML4IwTQhYRawEI4I14XBaRYgEIEFUKwwwNCvBj+P//P0kWgADRRT3MIhAgxQIQIKk+Sc9IA9MzZ8wC08SC0UqLJDBqCUlguFjCwAAAvlFKawnhSs0AAAAASUVORK5CYII='),
                                ############## RIGHT SIDE BUTTONS ARE FOR BOTTOM ML, FILTERED SOLUTIONS
                                Sg.Button("", key="filterSolutions", border_width=0,
                                          image_data=b'iVBORw0KGgoAAAANSUhEUgAAABcAAAAXCAIAAABvSEP3AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAI5SURBVDhPY5SRU2agGGCY8vd7YICfq7OjpoY6kHf9xs2nT58tWLzs6Yt3EHmsAMWUID+3hNgoXl7eU2fOnjx1BigiIy1lbmoiJSV58vSZrNxCPgExiEo0gDAlLzMh0N93774DLe1dDMycEEEIMDfWqaks/f//f0xC6qevv6GiSABqCtAVuVnpk6fNXLdpF0QCHfz9vnTh3P8M//2CwjFdxAQi/n4HegToCpxGAAEzZ2ZuobSUVF52JlQECYBMCQr0B4YFyCN4AdAv6zduDgrwhfKRAMgUYIwAgxMtLLCC3Xv3A+2TlhCC8mEAZIqGuhokRgiC67ceAklzMxMIFw7A4UIxAJly4+YtYLqA8AmAv9+BxOdPnyE8OACZAkygZqbGED5+4OrsBCR3790H4cIByBRgmAGjEJi0IEJ4QEJcNNZ4ALvl1kOgXHVFCcTBuEBCdDAwKyxYtBTKRwLQ0C2vrGVkZFyycA4fNytEBA0AjYiPjQL6HRJNaICZjx8c+UysW7du9fHySEtJ5OPh/PTx/Zt3H0Hif7+7ONk21ZXb2lgBIwGY0YGyp85cBEkhAZQ8/enDq4S4mMS4aB4eHqgQGAD1T5o6A+gKSI5dt2HT5BkLoXJggFG+gM3S1NAAxr20tBQwUkExghScWA2C+QgJsHNwf/7y/enzV9dv3r334AnQs1AJMDh55gI/L1dQgB+y17CYQhBgGkSOKUAAN+jZk8dA95JpChAADQIaASxJf/7+hyV0SQYMDACvTuLhjlzNKAAAAABJRU5ErkJggg=='),
                                Sg.Button("", tooltip="Clear Bottom Output", border_width=0, key="clearBottomSolItems",
                                          image_data=b'iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsIAAA7CARUoSoAAAAKISURBVEhLY5SRU/7PQEPABKWJAkF+bgzTJrQx8HGzQkUIA6Is+PThFdjg3Kx0Bk0NdTAmFhC0AGT4kgVzGGRlpBmy8ooYvnz5wiAtLQWVJQwIWpAQFwN2cXR8CsP1Ww8ZTp46w+Di5ACVJQwIWgAKlvUbNzN8+vobzN+9dz/YQmkJITCfEMBrAcwQkKEwcPLsFYZnz54zVFeUgIOPECAukj99hrIgIDO3EOyL6opSqAhugNeC6zdugGlzMxMwDQOg4KqormcICvBjyM2Ih4piB8x8/EINUDYYgLz988dXBnYObjCWlRJnsLWxYli3cTtUBQQ8ff6KgfH/X4bI8BAwfeHydagMKkDxASgDbVq3kmHa5H6oCCT8paWksGauBUvXghNAfGwUg6aaPFQUFaBY0NnWBDbM3NQEruHTZ0j48/Lygml0MGn6AoYbN28xdLY2QkVQAdwCkIEa6mrgsAVpmDapj6GjuRKsEcR/+uIdVCUmaGnvBjvA3FgHKoIAcAtArgYBUDKMjk9mWLh4GQMjIyPDqdNnGTJzCsByuADIclAOx1aEsEBpBk1NdYZTZ86C2XwCYuDwhQNmTigDN7h24ybYDHSAN5lSA8AtAJUxZibGROVObACkF2QGOoBbsAdaHLg6O4FpUgAscq8DgwkdwC0A5U5QHBBbxsAASG1udjq4fAKVtugAJQ5agckNlHJA5T8xloDUgMojUN4pq6qDiqICFAtAvgApBFUuB3ZvYzAz0obKYAJQSQtyCKg8AuUdXPkEa6UPKhaqK0vBEfcZmJNBkQdKhiAgA6zNQIUfyNWgYAE5CF8mxNuqALnS1dkRbCAol4MAOKyBloHKKFCmJARo3GxhYAAAASz0wYbe/AkAAAAASUVORK5CYII='),
                                Sg.Button("", key="wordCloudSolutionsBottom", border_width=0,
                                          image_data=b'iVBORw0KGgoAAAANSUhEUgAAABoAAAAUCAYAAACTQC2+AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsIAAA7CARUoSoAAAAJxSURBVEhLvZVdSJNRGMf/KlLhtkKa1DYqCmxCF4FzC4K+nIWEi1k0LEwHUSmsD5AwISgoii66GH2YBGmx6qIhVnQzN6WI2igoirY36K69RRdh20Caqb3P45lQcx/N0e9ivOd5z/Y7zznPeVZiWLFmGv+B/EST4zDXmaDX6xCPx/EhLCEiSdAsqRITcpNVpKkoR093FyyK5G9IeOu2BwN3PHkJM4ostetw8fxZJBIJuK/0wucPAGWLEBv7hhqjEbvtNth3NSEckdDpOsHvsjGnqKZ6Ja65L8MfGMXJntMZV0wZewZu4kcsBluzI2tmaSJa8ajvCaLyF3QcOyWimSHZkPe+soV30e/ximg6ZZrFlWfEM7NpowU7G3fgeFc34olxEc3Mz4kpxGNjOHTQCYtpPVavMiAUfAmUlosZM6SJnK0OJJNJ3HvwWERyEwy+UL4zAa12KTaY61iKqV94+y4sZswhatlrRzQq4+nzkIjkZsHCCoSlTxgOPMONvj5UabVocexByfQk3ghZKX8KaL+Na6sRU0q3UKgg3Nf7MTj0CG2t+6BfVsnxWRGVMx0qlXMw9EpEC+fchUv8W3QNCBaRle4MrWKztRHB1+/55XygzHz+EVi3beExi5wH9kNWyplSzueW58tn5azVajU/s8hiNrG92BiU3kjbR7BIpVLxoNhQj0wlwKKI9BHW+pm9LBbNtu3Q6ZbDO/iQxyxyX+2FXqeD60gbB+cDtTB7UwNcnYe5uKJfv3N8ttcd7WjnbhyVZfiGRwq6S3QmDfVbuQBIQsWV4o+mSl27XalAs6lWRP4NOng6E9quVCYpMv4fFRfgN6av5EusNbJyAAAAAElFTkSuQmCC'),
                                Sg.Button("", key="emailSolutionsBottom", border_width=0,
                                          image_data=b'iVBORw0KGgoAAAANSUhEUgAAABoAAAAWCAYAAADeiIy1AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsIAAA7CARUoSoAAAALYSURBVEhLvZVbSJNhGMf/driIdEUXUdPqIvBAXXWyrtLcgoJZKkg0sxVEttRA8mxBpWtpWLiaRWFD5mVaCl20mbsrqe4CD3ddOKOLCDW6iKj3//ht9bl9Ou3wk4+98zl973NaUtrmrT/wH1imfSbE1OePsOTslYfnxZDwjQrzD8Jx4jhSUlLk+/T0NDru3kMw9Eq+L8SCN8pK3wJ/lwcVzrMYGRtHrvWwPDw31lWLjDoLYXgj0+qVaKi7iOzduxAOT6Km4TImPnzSpLOkbliHVtdVmM0bMfz6DVzum5j68k2T6okJxNzzTQuP5mNmZgbN19sw/PadJo2PNWcfKsvLkJycjN4n/Whxt8G0dr0mnUUX6Pc6eLz34ev2xxgYwRd0lJZIilm/R9096BsIaFItENPk9bQj1WzG4IuQukUrsHyVprJIvn9FU30N8g7kYCIchrOiStIpzdDpuSVBgoNDqhaXlh6EKFv6oC/65AWIBGIxWXBLXi5CgWfYs2ObCJdC9s7t4oO+6JPBSLS9H6siHik6Jm17Q3WS97ZLuipRqEsbd8sV8UFf9BlBN0fMZW2TC87KKqwxmeD3PUBjdbnkPQKLrtsKSkYd6tKGtvQxt81XaJ86Rsbfw366XLrwVKkdQyoVPtVFVktuNBUsdCA4pDrNLmPALu3tfy6yeMy7GWi433JIck2HSeqPQ8mHZ/6PAakzXxAyb6DI8LJZ+p4OwFZYjEDopTw8cxR4Q+ro0hkHw0CcLb/voWwI3qCj06cbXp6bWz0iow51aWNE3ECySFVxN6WlosRxRm5gBGXUoS5tjBZsTCCHvQjejnaV+0nJ/dxFGg/q2AqKxYa2BTarJvlFNJBJ7Tf3tXqcVLuO9Th3oT7hPSeojUAb2laeLxNf9BlBdl1P1x0pOBkZHUNArY8/waq2QlZmhpxH1fDyBaJLldsgMyNdhH8LBqlVv2Mc3pjfo38D8BP4+EBAHaJTGQAAAABJRU5ErkJggg=='),
                                Sg.Button("", border_width=0, tooltip="Recommend Solutions for Content Below",
                                          key="recommendSolutionsBelow",
                                          image_data=b'iVBORw0KGgoAAAANSUhEUgAAABkAAAAZCAYAAADE6YVjAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAEpSURBVEhLY5SVU/7PQGPABKVpCuA+Wb16OcOp02fBgpQCM1NjhtDQSCgPagnIgpiEVKgQdcCSBbPhFoGD6+SpM2DOz69fqIJBAGYmCNAlTkaQJY8e3oGyMAE+OWQwOHwiJ68CZWECfHLIYPBEPHrYExsXMECUJaBgARkMw8QGEwwQHVwgg2GYVDB44oRSALZEU0MdzGHn5oHjuXNngcVAYMeOLQwiEpIo8vgwCJibmYBpEECpT2Al5+RpMxlys9IZerp7wRaAqoH///8zJMZFg+UJAZAFGPUJlA0HINeALHFxdoRbsHThHAYPDx+oCtIAzji5duMmVSwAAayWSElJMuzdd4AqFoAA1uA6duwQw7r1GxmCAv0ZrKzsoKLkA6yWUBvQIZ8wMAAAvnyc22rzv28AAAAASUVORK5CYII='),
                                Sg.Text("", size=(12, 1)),
                                #############
                                ########### THIS IS FOR ADDING OR REMOVING ITEMS FROM THE DROP DOWN TO CUSTOM FILTER:
                                Sg.Input("", key="solutionFilter", size=(20, 1)),
                                Sg.Button("", border_width=0, enable_events=True, key="addSolFilter",
                                          image_data=b'iVBORw0KGgoAAAANSUhEUgAAABkAAAAZCAYAAADE6YVjAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAJzSURBVEhLvZXBTxNBFMa/CuFiGxLjQdroRRNYEsRQ8awgfwUENWpSQQkIbUSNMcZoUlCLKMGoUYn9H9Ba9Kwp0QtduHfBRGNie1/ne+5Cl+5uQYq/ZDrdnZnv7bz35k3g4KHDJnaZPVa/q9Q1Nu67bf13JTX1EHUNDdgbDOHX7yLq1f+2o22Idh7H4EAM8/PvrJneeLornhjDq7k0isUiwuEmaC3NaFWNLOnLyKtmGKsIhUI419+LieSkjLnhauRYNCoi3V0nMTQYQ6vWYo04WcrrePx0FtmFT/IRX3M5a8RJhZH9B5pgmiaS9+6g53SX9dafzIcFJK7fQiAQwI+1VevtBo7Acwc0kH7zYssGCOdyDddSowLuhG1qesY8orWb7zNZNfff4FpqUMvWZVt3F910ojOK2ScpMe7G3ftJ6W+OJ6R3I3Z5GJ+/5BxuE3c9Sj2QLGKQ/cjnVVap5gc1qEVNGzGSyX6UNPXKou1ADWpR00aMFAqGpGCtoBbPkE09f/TlFfR0n5IX5TAGur5iPSl3qXmk78wF6YmmNePGtbj19BceWp4dm6q1SyVN1VYNya72jg5EImHfzCK9/eelT8+9lN4LZhhD8G1xUZ5lJzRQ7padwpJETRsxwngUDENq0U6hBoNeHmMxMjI8imAwiOmZZ/LSCwaZzQ8WTGpRcx376P+XskKYAAW11bevn2/7YNJNfWcvIqIOoh1wG0cKc1B9kExm+d4qnMs1XLvZAKk4Jz+/r8nXDAxdxaUrI77JwDHO4Vyu4Vo3XG9GMhYfleu3VCopgbAE3HH9qkLJjGSQef1OTmwUxM14GqklFe6qPcAfpNSjHYHAlh4AAAAASUVORK5CYII='),
                                Sg.Button("", border_width=0, key="removeSolFilter",
                                          image_data=b'iVBORw0KGgoAAAANSUhEUgAAABkAAAAZCAYAAADE6YVjAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAJrSURBVEhLtZXLaxNRFMa/2NKNCQUVbBN0o9BOoVYaoy61tX+FIroQYqvFR1NEQUREIa3aWh8FBR/YnYjLaprq1mqKLsyj+0wrKILJfpzv9N46Y5LGTNIf3GTmPr5z73nc8e3YucvCBrNJ/W8oTa2tW66p57JMTN5BU0sLNvsD+PW7gGb7uXtPN8KRfRgajGJ29q2aWZmK7oqNjuDpixkUCgUEg+0wOjvQZTeSzuaQsZtpLiMQCODk8aMYi4/LWDnKGtkbDotIf98hDA9F0WV0qhE36UwW9x5MIzn/QTbxJZVSI25KjGxra4dlWYjfvI6BI32qd30Sc/MYvXwVPp8PP1aWVe9fXIHnCWhg5vmT/zZAOJdruJYaJfAkbJNTD63dRo/1LpG053qDa6lBLa3LtuYuuml/JIzp+xNi3CvRM+ew8CnldhuNvHr9RnbwLZ1Re/IONahFTX0SiUki+V7StFIW1QI1qEVNjRjJ501JwUZBLdaQppk/2dwSBvoPS4eTG7fiyGaX1NtqERJdlMQwOnDlUky9rcJx1o6m6t1lu7lqq4ZkV09vL0KhYN2ZpWGGMQRfFxflXU5CA0631AuvJGpqxAjjkTdNuYvqhRoMujPGa8W4dXsbDh6I4NHUXRnwCl31ceEzfn5fUT2OwPO6nrNzm5edV7iWWUUtJ65bmAmQt4/68tnjmguTbjp24hRCdiHqgGtcKcxBpiQn13IizuUarv3XACmpE/qSuxkcvoDTZ8+vmwwc4xzO5RpnHJyUfLQ0I7GL8vktFou2QFAq2/X5zeQkI/1+v8RgfOy2jJWjopFGUuKuxgP8ATlXoGLsydy5AAAAAElFTkSuQmCC'),
                                Sg.Button("", tooltip="Save outputs to CSV", border_width=0, key="saveCSV",
                                          image_data=b'iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAAEnQAABJ0Ad5mH3gAAAJaSURBVEhL1ZbNaxNBGMafJLsmaUhSemlD0iJYbFERCXrwJoig/4BQKQGlFBSlNhhpUfy4SaUEKigexEPx66QQL6IitFWQYtooYlqih6SKSmObpLvZbD7Wmcm0sjUaEtJDf4fdYd7hfeb9mNk1eDq2adggFuKfYeTjDWPzC7AalEolKDkVRw7ux+jINUiyDDpHEQUBOVXFyGgQd+6Oo33rdmilIrNVg9bA5HC2XCkUClCUHCZfhPBrObXmnELHZrMZu3ftRCojYybyEVarhVv/Tzq1VE6RRvuIPKxOp875KiqJwO1x4/ChA2hptkHN57mlOixFqpqHTNKSWY4jFp3nptoxGo2wNVkxfPEyQs8msPhjobFFptFLchY3gtdhNBjYXMO7iIrYmp1kVKeAKApIpzO49+ARPkXnSMGt3FKZmgVoRyWTSdayR3t8iETew263c+vf1CywsiJh314vAv4BcnZy6D81gOjcPGy2Jr5Cj8DfOgRyuCRJwuMnISS+foPFYuaWPzjIrr3ePQiHZ+E/N4TbN8fgamtFVlH4ijJ6AYOJHAcN4/cfIpFIEIGnWCTpqEZ4NsLS1tHuqSJAMkZ3PzH1GlOTb5CVlxAj4a9HFEXQ03/y9Fk8f/kKVy9dQHd3F4t6PfoaaHkUi0XcGgviw8zbfzgXmPPBwBBzPnzeD19vD2vPYoVboK4uisW+YHr6HfpO+NDfd5yllW6sEg29Klbp7OpEq3sHfn6P1x5BrTRcgF54cipNRuVPPRMQBBO2kNz2HvPB4bCzRfXicrXhzGBg7drf7H8VwG/tdwNXxgNjRAAAAABJRU5ErkJggg=='),
                                Sg.Button("", tooltip="Email Saved CSVs", key="emailCSVs", border_width=0,
                                          image_data=b'iVBORw0KGgoAAAANSUhEUgAAABoAAAAWCAYAAADeiIy1AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsIAAA7CARUoSoAAAALYSURBVEhLvZVbSJNhGMf/driIdEUXUdPqIvBAXXWyrtLcgoJZKkg0sxVEttRA8mxBpWtpWLiaRWFD5mVaCl20mbsrqe4CD3ddOKOLCDW6iKj3//ht9bl9Ou3wk4+98zl973NaUtrmrT/wH1imfSbE1OePsOTslYfnxZDwjQrzD8Jx4jhSUlLk+/T0NDru3kMw9Eq+L8SCN8pK3wJ/lwcVzrMYGRtHrvWwPDw31lWLjDoLYXgj0+qVaKi7iOzduxAOT6Km4TImPnzSpLOkbliHVtdVmM0bMfz6DVzum5j68k2T6okJxNzzTQuP5mNmZgbN19sw/PadJo2PNWcfKsvLkJycjN4n/Whxt8G0dr0mnUUX6Pc6eLz34ev2xxgYwRd0lJZIilm/R9096BsIaFItENPk9bQj1WzG4IuQukUrsHyVprJIvn9FU30N8g7kYCIchrOiStIpzdDpuSVBgoNDqhaXlh6EKFv6oC/65AWIBGIxWXBLXi5CgWfYs2ObCJdC9s7t4oO+6JPBSLS9H6siHik6Jm17Q3WS97ZLuipRqEsbd8sV8UFf9BlBN0fMZW2TC87KKqwxmeD3PUBjdbnkPQKLrtsKSkYd6tKGtvQxt81XaJ86Rsbfw366XLrwVKkdQyoVPtVFVktuNBUsdCA4pDrNLmPALu3tfy6yeMy7GWi433JIck2HSeqPQ8mHZ/6PAakzXxAyb6DI8LJZ+p4OwFZYjEDopTw8cxR4Q+ro0hkHw0CcLb/voWwI3qCj06cbXp6bWz0iow51aWNE3ECySFVxN6WlosRxRm5gBGXUoS5tjBZsTCCHvQjejnaV+0nJ/dxFGg/q2AqKxYa2BTarJvlFNJBJ7Tf3tXqcVLuO9Th3oT7hPSeojUAb2laeLxNf9BlBdl1P1x0pOBkZHUNArY8/waq2QlZmhpxH1fDyBaJLldsgMyNdhH8LBqlVv2Mc3pjfo38D8BP4+EBAHaJTGQAAAABJRU5ErkJggg=='),

                                ],
                               ###############

                               # [Sg.TabGroup([[Sg.Tab("Filter", solFilterTab), Sg.Tab("Recommended Solutions", recSolTab)]])],]]

                               [Sg.TabGroup([[Sg.Tab("Main", solFilterTab, pad=(0, 0), border_width=0),
                                              Sg.Tab("Recommended Solutions", recSolTab, pad=(0, 0), border_width=0),
                                              Sg.Tab("D0", d0Tab, pad=(0, 0), border_width=0),
                                              Sg.Tab("D1", d1Tab, pad=(0, 0), border_width=0),
                                              Sg.Tab("D2", d2Tab, pad=(0, 0), border_width=0),
                                              Sg.Tab("D3", d3Tab, pad=(0, 0), border_width=0),
                                              ]], pad=(0, 0), border_width=0, tab_location="bottomright")]],
                              element_justification="c")]]

    sessionsTab = [[Sg.Multiline("", key="sessionsTab", size=(140, 25))]]

    verifierTab = [[Sg.Multiline("", key="verifierTab", size=(140, 25))]]

    authTab = [[Sg.Text("Tool Key:  "), Sg.Input("", key="toolKey")], [
        Sg.Text("")], [
                   Sg.Text("ACAS:")], [Sg.Text("API Key    "), Sg.Input("", key="APIkey", password_char=">>")], [
                   Sg.Text("API Secret"), Sg.Input("", key="APIsec", password_char="^>>")], [
                   Sg.Text("")], [
                   Sg.Text("VSphere:")], [
                   Sg.Text("UN:          "),
                   Sg.Input("", key="vSphereUN")], [
                   Sg.Text("PW:         "),
                   Sg.Input("", key="vSpherePW", password_char="<<")]]

    opacityDD = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.75, 0.8, 0.85, 0.9, 0.95, 1]

    themeTab = [[Sg.Text("Use at your own Aesthetic Risk")], [Sg.Radio('Dark', key="darkTheme", group_id="themeGroup")],
                [
                    Sg.Radio('Light', key="lightTheme", group_id="themeGroup", enable_events=True)], [
                    Sg.Radio('Blue', key="blueTheme", group_id="themeGroup")],
                [Sg.Text("Opacity: "), Sg.Combo(opacityDD, key="opacityDD", default_value=0.95, readonly=True)],
                [Sg.Button('Change Theme', key="changeTheme"), Sg.Button("Original Classic", key="classicTheme")]]

    helpTab = [[Sg.Column([[Sg.Image(subsample=1, data=doc64List[k]) for k in range(0, len(doc64List))]],
                          scrollable=True, size=(1000, 500))]]

    configTabGroup = [[Sg.TabGroup([[Sg.Tab('General', genConfigTab),
                                     # Sg.Tab("Scanning", scanConfigTab),
                                     Sg.Tab("Email", emailConfigTab),
                                     Sg.Tab("Exempt Plugins", pluginConfigTab),
                                     Sg.Tab("WordCloud", wordcloudConfigTab),
                                     Sg.Tab("Authentication", authTab),
                                     Sg.Tab("Themes", themeTab, key="themeTab"),
                                     Sg.Tab("Help & Documentation", helpTab, key="helpTab")]], pad=(0, 0))]]

    blankTab = [[Sg.Column([[Sg.Text("This is not the tab you are looking for, move along now...")]])]]

    githubTab = [[Sg.Column([[Sg.Text("")]])]]  # TODO: update with github info, pip info, and other repository info

    if theme:
        Sg.theme(theme)
    # -----  Layout & Window Create  -----
    mainLayout = [[Sg.TabGroup([[Sg.Tab('', mainTab, expand_x=True, tooltip="", key="mainTab",
                                        image_source=b'iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAFOSURBVDhPY5SRU/7PQAFggtIY4NOHVwy5GfFgDGLjAlhdwMfNyrBkwWwGRkZGMP////8MMQmpDJ++/gbzkQGGC8yNdRg2rl3B8PTZc4bo+BQwBrFBYiA5dMDMxy/UAGUz5GUmMORmpTPs3XeAITO3ACjLyfDz9z+G5SuWM6goKTGkpSQy8PFwMpw6cxGqA+oFkB+XLJjDoKmhzjB52kyGdZt2QaVRQZCfG9iC6zduAr2UwsAnIAbxwvQpExhkZaQZsvKKcGoGAZAcSA1I7bTJ/WAxsAFmJsYM8xctZbh+6yFYEB8AqQGpNTc1AfOxRiPIS4G+rigYV1SyQGkUkBAXA/YrMgBFKTbv4UxIIODoEQzG+ABeA4gBA28APBDNTI3BaR7GRgfo8l++fAGzwQZUVNcz1FSWwuMWBG7cvAVlQdggOZg8SHNLezeQxcAAAJeRfrq+/kYqAAAAAElFTkSuQmCC'),
                                 Sg.Tab('', parserTab, key="parserTab", expand_x=True, tooltip="",
                                        image_source=b'iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAEUSURBVDhPY5SRU/7PQAFggtJkA6IN4ONmZVgybzLD/h1rGeKjgqCiDAzMfPxCDVA2TgDWvGA2AwcHB8PhI8cYggL8GBj//2W4cPk6AwtUDU4A08zLy8vgHxzB8Onrb7B4fGwUw4Kla/F7AVkzCIA0gcTMTI0Znj17DhbDGQswzYyMjAzR8SkMCXHRDIH+vmC5L1++gMVArsHqAnTN167fYFiwaClYDlkzCGAYgE2zlqYGWAxdMwigGICuGaQQphlZDBnADcBmMzYD0QHcgOmT+7E6G59mEAAbIC0hxCAlJclQVlVHkmYQABvg6uwI5lwHanYBsonVDALgdDB9YjuDNNAFsAQDSiSZuYUENYMAhdmZgQEAPdKPscBf+Q8AAAAASUVORK5CYII='),
                                 Sg.Tab("", scannerTab, key="scannerTab", tooltip="", expand_x=True,
                                        image_source=b'iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAFtSURBVDhPlZM7TwJBFIUPm9UKLYw20AtaKmLtj9DOR+cbKxNUSlQSK8FnaSz9JbxKA9hDo7FQKk3EPZe5m3FdjX7JwL1ndmbvayNT6bkeAsRio8hsriF7kBe/cJhD6eIa7faj+DaO+f9Cs/WARrNlPIht+zb+BfvZHfTwjpfXZ/H5RtpctAltPsNnFT+Fj94bJpMJzKZTsvET5UoNDS/CCAbEd+XXo9vtyuGb2zujhLO8OI9KrY7hoRHxHRZMw1ZUs1c8PmZ2+6jmstoskOZJWMR0atpPh2HbbyXbG6uY8FJ2tVVBeDiztS528exSLrDRVEPb+B9cDglDLp5fGalPpVpHyWi0g6wsLSCZGIfLg7zAhhvlak2WQq3TeTKel5Z3jppD0S4OUc1e9mGimj9IbMvsTOpPg3TfaMKJDIrvX8DxzB+fyED9RjQaRW5vF0eFU/FDv0ZGwz5rqzh9nBOGHSS0jSwOh0ShTe07wCeb3bQnHaPhJQAAAABJRU5ErkJggg=='),
                                 # Sg.Tab("Remediator", remTab),
                                 Sg.Tab("", solutionTab, key="solutionizerTab", tooltip="", expand_x=True,
                                        image_source=b'iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAFFSURBVDhPYzQyc/zPQAFggtJYQWCABxjjA3gNuH79JhjjAxgGTJvcyaCpocTw6fM7hlNnzoIxiA0SA8mhA3gYSEmJMNy4eQssKCUlyRAc4MewdsMmMB/GfvbsOZivqaHO8PTpazAb7oK87Aww3dHayPDl80+GhYtXM8hISYExiA0SA8mBQG5WOpgGAbgBfHy8YFpGWgpMYwMwOZhaEGCWlFZsADHu3rvLAPLLjRu3GN68eQ8SYhAREQTTb95+ANPY1IBd4OxkzXDtxk2wM69evwHmowNcasAGrN+4mYGRkZEhIS4MTJ88fQYsiQxgaoICPVHUgA3g4xViMDM1Zpg0dQaYBtmCDmBqFixaiqIGb1LWUFcE0zdu3gfT2AA8FsgFGC5ATlDoADkBwQCGAR2tNQzXgaGNDYAMqKhugfIggMLszMAAAG+xjhaqruXxAAAAAElFTkSuQmCC'),
                                 # Sg.Tab("Verifier", verifierTab), Sg.Tab('Sessions', sessionsTab),
                                 Sg.Tab("", graphTab, key="graphTab", tooltip="",
                                        image_source=b'iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAADRSURBVDhPYzQ0c/zPQAEAG6AkzcdQXVHCwMvLCxXGDz5//szQ2tHDcO/pJ4gB86Y0M1y7cZPh5KkzUCX4gbmZCYOmuhpDcm4dAwtIgIeHB6z58KkbYAXEADMTYzDNBCaRwKoF/VAWA0NJTgwYwwCyHAxgGEAqoK0B16/fBGN8AK8BW/eeBmN8AMOAGzdvQVnEAQwD6tqnQ1nEAZICEZvrSDIAm+vAKREEzEyNGf7/Jy5fgdR++fIFzIZnpprKUnCSJgaANLe0dyMyE1ScDMDAAACFskf9w47C1QAAAABJRU5ErkJggg=='),
                                 Sg.Tab("", vSphereTab, key="vSphereTab", tooltip="",
                                        image_source=b'iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAIrSURBVDhPbVNLTBNRFD0Fg5vOuHLRmRqCbqobQ5DCxkQoLBW1iTGWTzckbVobFeMHjSH81GjU8AkkiiKiARKKQOJGIS50IZbAqhSNrpx232lMcDO+e5mB0ulJJn3v3nfPO/f0Pkelt85AEZQhB291FXRdR/z9Ao54TpiZvbAR/Eol8LCvGw2+OjMCJglfvoZ/cJqRXZSYvzsItjZzcf+Dx6iqPYkm/0Vo6QxGBp8weSFsBP6zZzA3v4hXE5Ni3cSxm533IEkSGn31vM+HjUBRXPijpXkdi4bQees6khsppDZ/ICtaKUSpS63oMteMcvdB1AjzyDhNyyDYEkBatBD/8BV/t8xDebAp6Lv/CAdkGZPjL/Bby2IlsYo7QkWx/gk2gv2SC9msziQEIqT+Y5Ew7wvBBFt6Bsc9CgcOqzL7MDA8ynsifP3mHdpaLmFssBsz40/REQnwnBBKqHh+dgr+c9uOxyIhlk3yLQwMj7APn5Y/M9khVRUtPueLHW8nxgy3ouD0+Qv8t5HrzcH2okNjgfxYjM9gI7UJ/EyuG3dv36BpNNZWvhhEaK0pV/gtxKc5H4uGeb8vl8tBliUiRq8wjFjdqgKn04klITlJt+SBbxWgM9SWGJZtpmBrgJlFgm8hBYLYoLdCX423mnMUo7NUQ7UOKhodegZf/SlmJpCqUPTqHh9eDvWwKgukLhS9AiagwLGjHn5Emhjjj0vLtudLxllv49v3BI83APwHCZwNJ3VfCz8AAAAASUVORK5CYII='),
                                 Sg.Tab("", exportTab, key="exportTab", tooltip="",
                                        image_source=b'iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAF4SURBVDhPpVM9SwNBEB3F9tJ78QeonaCx1CRnYSViqUgKhQRj/oSgIqKiooJKNCSNjYUQCwMq2iSCWokftbHPXb/OG26Pu42k8cG7nXuzM+w8druGEklF/4HfIMLRxIg63NsWIjbzmqjt5iACLqLy2TENDvQLEUPri9v+DgP6BLGYpZaXsuql8agK+VygIYb2XH+QPHRNqcXnvnatvt5e5cjhDSaP9nfUXa0a/Acj2HYveZ5HTjpJE04KUgTQuJDSqXGK29FRAg+KpQrNZRbpYHeLyucnMrN4wDE01/Ukb6LHXwX1xhOtrm9SIZ+l25uqaDgZtGKpLP/vH5+yBsAcmF8bB8K8q8sLIWKtmww8MNFqudRyfXIcBsYK488GnaDviIY0aDZ/yGGH+daJ2AnfvDfcRBqMOZPs8AI3GCa+MMQXRpIa7AMbmxMClmVRZn5W4ra3gMsCU8FK6TSSA6FvrK1ILLVmAxAPCI1mpqfacroYRO0/nzPRLyv88isWv0p2AAAAAElFTkSuQmCC'),
                                 Sg.Tab("", configTabGroup, key="configTab", tooltip="", expand_x=True,
                                        image_source=b'iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAFySURBVDhPpZIxSwNBEIVH0Uo8xEKERC2E5K5WBLtEL7VCOoNE8D9YWAgWCjYiFmlUiBDLJCaVGGLSiWI60SSdhQpWcvkBem/c2bvzUukHy07em5ns7N5AdHr2i/7BoNr/TKCB8/lBuaN9alwVaSOTVipxDA0ecvwEGlycn9FUNEL1myZl19eUShxDg1fInyr1B90glVgkMx6jre0demp3lOoBDZ5lxjlX0A1sO0ntTpeeuy9KCQMPOcgVdIOF+Tmq1Rsc95we75HJcV5ANOQgVwjcgVC8rPA/FfInvBBD68eQ2un+oUX2UoJK1WsyxiYok92k9OoKeyiGBlLLSc4V9AlK5SpfkBWb4d8oqDVveUkxPFw0cgXd4K71yEc92NvVc/tBMTwep+yNE7gDHPv17Z3nNkaGleqexo1zx4fsIcdPoIHMDmx3VkFieI56DSH0CjJvP34Xg1AD+dbl3YHEhjHKu59QA8s0efd/zhKL50H0DTR5k+nZ4faXAAAAAElFTkSuQmCC'),
                                 Sg.Tab("", logTab, key="logTab", tooltip="",
                                        image_source=b'iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAHdSURBVDhPYzQ0c/zv7WzKEBTgy8DLy8tADPj8+TPD2vWbGLbtO8PAAtIcHxvFsH7jZoYnT59BlWCC4AA/BikpSbA6EEiIi2b4/OULA+P5U0f+7967n2H5+n1gCVxg3pRmBmR1kYFODC5ODgxMIA4vDw9YkBBAVvfp02cGRkZGBsa8nMz/uVnpUGHCoK2jh+HCjacME9rKGK7fuMkADkQRPkYGTQ11BnMzEwYzE2O84bFu/UYGTU0NhmmT+hgqqushBoAk7t44w7Bp3UpgCH9hqGufDlaMDaCrY4GKM+RlZzJIS0kxxCSkMojw8TJoqKtBZSBg4eKlDMoaJijqGBh4IAawMXwBR+XCxcsYfgEF87IzMAy4cfMWOOCQ1YEA2AtNlZkMfMBE5BsUBrYFF8CmjklJmg9s26SpMxhkpKUZbEzVUfDPz8/BCmHqWjq6wer0NaTA4iyuzo4Mz549Z7j39BMwOfuBnYgM+Pn4GLbuPc0AU/fm038GaWkphuqKUrBXGG9fu/B/8rSZDIdP3YBqwQ5AKRGU/kGGgQA8JX4BpmcZoInEAD5g7CADUEpkmb9oKQMoJf7//x9vZvr46RNDoL8vWB0IgNggl4NjwdZMA57biAEgV4MsPnzqBgMAQCHIC8i8eFwAAAAASUVORK5CYII='),
                                 Sg.Tab("", githubTab, key="githubTab", tooltip="",
                                        image_source=b'iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAGOSURBVDhPhZM7TAJBEIaH68HOQmyVk8ooHI0NDwtNjLE1MZYGo1YWGAq1szOCiqVIMHbEmGBhxAILOTCxUtBWsEd6vX9uFw7k8Ev2dmZ3ZnZudtYxpQV/qIe5kI8Cmo8mVA/rb9UalfQKpTNZGnaba5KuAPNhP62uLAutP+cXWbotVIRmCbC/EyXVM86L/4GM9g7OWFbwwclwrtbeKRbf5Rm0Wi0eoNH44j298sy/Bh8GGXy8vvDY2ogim4EDNtIevko7ksGoe0RI9ricTiGZmSuotiRxnBKSPYmTjo3mnybFWrjPeoNnIz0ekmKx2NabzW+eAWrhwL8Inca8k0IajDW4gupKZiMhIdkT0Do1w20ppXKnKTbX1wYWEnvx2LbQzH5QrnIFVnLXNxzx4S5PqeQheSdUXgeQsYY92d4AvtxI6cwlLS0u8C1Adg25jILW2QhAjoSDQjOBHeAA+fsyn35qnPKkl+komeqqtlUGsIUPsH1MvTciK4+TpTPo+5xnNPVPUxktTI96VWgSol/susGFdt8lyAAAAABJRU5ErkJggg=='),
                                 Sg.Tab(":|", blankTab)]],
                               key="tabGroup", enable_events=True, pad=(0, 0), border_width=1, expand_x=True, )],
                  [Sg.Column([[Sg.Text("", key="analyzeText")],
                              [Sg.Text("Status:"), Sg.Text("None Currently", key="info", text_color="grey")]])]]

    if oldLoc is None:
        return Sg.Window("AQT", layout=mainLayout, right_click_menu=right_click_menu, no_titlebar=False,
                         use_custom_titlebar=True, finalize=True, alpha_channel=opacity)

    else:
        return Sg.Window("AQT", layout=mainLayout, right_click_menu=right_click_menu, no_titlebar=False,
                         use_custom_titlebar=True, finalize=True, alpha_channel=opacity,
                         location=(oldLoc[0], oldLoc[1]))


newTabML = [[Sg.Multiline("", size=(140, 25))]]

theme = "DarkGrey11"

mainWindow = make_window(theme="DarkGrey11", opacity=0.95, oldLoc=None)
mainWindow['connect'].set_focus()  # so it stops selecting the text from drop down by default

# HOTKEYS FOR TABS:
mainWindow.bind("<F1>", "<F1>")
mainWindow.bind("<F2>", "<F2>")
mainWindow.bind("<F3>", "<F3>")
mainWindow.bind("<F4>", "<F4>")
mainWindow.bind("<F5>", "<F5>")
mainWindow.bind("<F6>", "<F6>")
mainWindow.bind("<F7>", "<F7>")
mainWindow.bind("<F8>", "<F8>")

# expand columns to fit window size:
mainWindow['genCol'].expand()

while True:
    b, v, = mainWindow.Read(timeout=0)

    # print(v) # USE THIS TO CHECK GUI VALUES DURING RUNTIME

    if b in ("logTab", "<F8>"):  # this is working, just need to add other tabs / things to hotkey to
        # print("Switched to Parser Tab")
        mainWindow.Element('logTab').Select()

    if b in ("configTab", "<F7>"):  # this is working, just need to add other tabs / things to hotkey to
        # print("Switched to Parser Tab")
        mainWindow.Element('configTab').Select()

    if b in ("vSphereTab", "<F6>"):  # this is working, just need to add other tabs / things to hotkey to
        # print("Switched to Parser Tab")
        mainWindow.Element('vSphereTab').Select()

    if b in ("graphTab", "<F5>"):  # this is working, just need to add other tabs / things to hotkey to
        # print("Switched to Parser Tab")
        mainWindow.Element('graphTab').Select()

    if b in ("solutionizerTab", "<F4>"):  # this is working, just need to add other tabs / things to hotkey to
        # print("Switched to Parser Tab")
        mainWindow.Element('solutionizerTab').Select()

    if b in ("scannerTab", "<F3>"):  # this is working, just need to add other tabs / things to hotkey to
        # print("Switched to Parser Tab")
        mainWindow.Element('scannerTab').Select()

    if b in ("parserTab", "<F2>"):  # this is working, just need to add other tabs / things to hotkey to
        # print("Switched to Parser Tab")
        mainWindow.Element('parserTab').Select()

    if b in ("mainTab", "<F1>"):  # this is working, just need to add other tabs / things to hotkey to
        # print("Switched to Main Tab")
        mainWindow.Element('mainTab').Select()

    if b == "changeTheme":

        if generatedTabs == True:
            Sg.Popup("Unable to Change Theme with Generated Tabs...")
            continue

        if v['darkTheme'] == True:
            oldLoc = mainWindow.CurrentLocation()  # get window loc so we can rerender it back in same place
            oldV = v
            theme = "DarkGrey{}".format(randrange(1, 15))
            # print("Changing Theme")
            mainWindow.close()
            mainWindow = make_window(oldLoc, v['opacityDD'], theme=theme)
            # mainWindow['connect'].set_focus() # so it stops selecting the text from drop down by default

            mainWindow.move(oldLoc[0], oldLoc[1])  # x,y
            mainWindow.Element('configTab').Select()  # select the config/theme tab since that's where we were
            mainWindow.Element('themeTab').Select()

            for val in oldV:  # refill all elements from old window to the new window
                if val == "graphCanvas":
                    continue
                # print(oldV.get(val))
                mainWindow[val].update(oldV.get(val))
            # print("Updated")

        if v['blueTheme'] == True:
            oldLoc = mainWindow.CurrentLocation()  # get window loc so we can rerender it back in same place
            oldV = v
            theme = "DarkBlue{}".format(randrange(1, 15))
            # print("Changing Theme")
            mainWindow.close()
            mainWindow = make_window(oldLoc, v['opacityDD'], theme=theme)
            # mainWindow['connect'].set_focus() # so it stops selecting the text from drop down by default

            mainWindow.move(oldLoc[0], oldLoc[1])
            mainWindow.Element('configTab').Select()  # select the config/theme tab since that's where we were
            mainWindow.Element('themeTab').Select()

            for val in oldV:  # refill all elements from old window to the new window
                if val == "graphCanvas":
                    continue
                # print(oldV.get(val))
                mainWindow[val].update(oldV.get(val))
            # print("Updated")

        if v['lightTheme'] == True:
            oldLoc = mainWindow.CurrentLocation()  # get window loc so we can rerender it back in same place
            oldV = v
            theme = "LightGrey{}".format(randrange(1, 6))
            # print("Changing Theme")
            mainWindow.close()
            mainWindow = make_window(oldLoc, v['opacityDD'], theme=theme)
            # mainWindow['connect'].set_focus() # so it stops selecting the text from drop down by default

            mainWindow.move(oldLoc[0], oldLoc[1])
            mainWindow.Element('configTab').Select()  # select the config/theme tab since that's where we were
            mainWindow.Element('themeTab').Select()

            for val in oldV:  # refill all elements from old window to the new window
                if val == "graphCanvas":
                    continue
                # print(oldV.get(val))
                mainWindow[val].update(oldV.get(val))
            # print("Updated")

        if v['darkTheme'] == False and v['lightTheme'] == False and v['blueTheme'] == False:
            oldLoc = mainWindow.CurrentLocation()  # get window loc so we can rerender it back in same place
            oldV = v
            # theme = "DarkGrey11"
            # print("Changing Theme")
            mainWindow.close()
            mainWindow = make_window(oldLoc, v['opacityDD'], theme=theme)
            # mainWindow['connect'].set_focus() # so it stops selecting the text from drop down by default

            mainWindow.move(oldLoc[0], oldLoc[1])
            mainWindow.Element('configTab').Select()  # select the config/theme tab since that's where we were
            mainWindow.Element('themeTab').Select()

            for val in oldV:  # refill all elements from old window to the new window
                if val == "graphCanvas":
                    continue
                # print(oldV.get(val))
                mainWindow[val].update(oldV.get(val))
            # print("Updated")

    if b == "classicTheme":
        oldLoc = mainWindow.CurrentLocation()  # get window loc so we can rerender it back in same place
        oldV = v
        theme = "DarkGrey11"
        # print("Changing Theme")
        mainWindow.close()
        mainWindow = make_window(oldLoc, v['opacityDD'], theme=theme)
        # mainWindow['connect'].set_focus() # so it stops selecting the text from drop down by default

        mainWindow.move(oldLoc[0], oldLoc[1])
        mainWindow.Element('configTab').Select()  # select the config/theme tab since that's where we were
        mainWindow.Element('themeTab').Select()

        for val in oldV:  # refill all elements from old window to the new window
            if val == "graphCanvas":
                continue
            # print(oldV.get(val))
            mainWindow[val].update(oldV.get(val))
        # print("Updated")

    if b == "vConnect":  # vSphere connection
        if v['vSphereAPIEnabled'] == True and v['vSphereUN'] is not "" and v['vSpherePW'] is not "":
            vConn = vSphere()
            vConn.enableVSphere()
            vConn.vConnect(v['vSphereUN'], v['vSpherePW'], "192.168.0.14")
            vSphereTuple = vConn.listAllVMs()
            outputVsphere = vSphereTuple[0]
            dictVersionvSphere = vSphereTuple[1]
            vSphereVMsPoweredOff = vSphereTuple[2]
            if v["getIDs"] == True:
                outputVsphere = addVulnUUID(outputVsphere)
            # for item in outputVsphere:
            # 	print(item.get("vulnUUID"))

            numVMsPoweredOn = 0

            for item in outputVsphere:
                numVMsPoweredOn += 1
            numVMs = numVMsPoweredOn + vSphereVMsPoweredOff

            mainWindow['vSphereCounters'].update(
                "VM's: {}, Online: {}, Offline: {}".format(numVMs, numVMsPoweredOn, vSphereVMsPoweredOff))
        # [Sg.Text("VM's: 0, Online: 0, Offline: 0", key="vSphereCounters")

        else:
            Sg.PopupOK("Enable the VSphere Plugin and\nComplete Auth Info Within the Config Tab")
        vSphereList = []

    # VSPHERE IP QUERY (There is a space in > "IP Address "):
    if b == "IP Address ":
        pass

    if b == "findIPs":
        if vConn.connected:
            vConn.findIPs()

    if b == "v Clear Window":
        mainWindow['vSphereML'].update("")

    if b == "connect":  # ACAS connection
        try:
            if len(str(v['APIkey'])) > 0 and len(str(v['APIsec'])) > 0:
                sc = TenableSC('192.168.17.240',
                               access_key=v['APIkey'],
                               secret_key=v['APIsec'])
                # print(sc.credentials.list())
                loggy("Connected to ACAS", "INFO")
                mainWindow['info'].update("Successfully Connected to ACAS", text_color="lightgreen")
            else:
                mainWindow['info'].update("Provide ACAS Creds within Config Tab", text_color="#ffb399")
        except:
            loggy("Error connecting to ACAS", "ERROR")

            mainWindow['info'].update("Error Connecting to ACAS", text_color="#ffb399")

    if b == 'Email Parsed Output' or b == 'emailMainWindow' or b == 'Email Rem Output' or b == 'emailSolutionsTop' or b == 'emailSolutionsBottom' or b == 'emailCSVs':
        try:
            if len(str(v['emailSender'])) < 1 and len(str(v['emailRecipient'])) < 1:
                mainWindow['info'].update("Error Emailing, Provide email info within config tab", text_color="#ffb399")
                continue
            else:
                print('all good')
                pass
        except:
            loggy("Erroring Emailing Output", "ERROR")
            mainWindow['info'].update("Erroring Emailing Output", text_color="#ffb399")
            pass

    if b == 'Clear Window':
        print(clearWindow())

    if b == "IP Address":
        allGood = functionalityCheck("IP Address")
        if allGood == 1:
            try:
                ip = v['query']
                print(str(ip))

                if v['anyV']:
                    sev = "1,2,3,4"
                if v['lowV']:  # Severity from check boxes:
                    sev = 1
                if v['medV']:
                    sev = 2
                if v['highV']:
                    sev = 3
                if v['critV']:
                    sev = 4

                if v['csvForm']:
                    vulns = getVulnsList(sc, ip, sev)
                    print(vulns)
                    autoClear()
                    csvList = []
                    for entry in vulns:
                        csvList.append(
                            '\"{ip}\" \"{pluginID}\" \"{pluginName}\" \"{severity}\" \"{notes}\" \"{reason}\" \"{customUUID}\"'.format(
                                **entry) + "\n")

                    print(csvList)
                    mainWindow['csvTable'].update(values=csvList)
                    mainWindow.Element('csvTab').Select()
                    continue

                vulns = getVulnsList(sc, ip, sev)
                mainWindowList = vulns
                print("Obtained Vulns")
                autoClear()
                for entry in mainWindowList:
                    sev = entry.get('severity').get('name')
                    # mainWindow['resultML'].update('{ip}:{pluginID}:{pluginName}'.format(**entry) + ":", append=True)
                    if sev == "Critical":
                        mainWindow['resultML'].update('{ip}'.format(**entry) + ":", append=True)
                        mainWindow['resultML'].update('{pluginID}:'.format(**entry) + ":",
                                                      text_color_for_value="#cc4668", append=True)
                        mainWindow['resultML'].update('{pluginName}'.format(**entry) + ":", append=True)
                        mainWindow['resultML'].update("{}".format(sev), append=True)
                    if sev == "High":
                        mainWindow['resultML'].update('{ip}'.format(**entry) + ":", append=True)
                        mainWindow['resultML'].update('{pluginID}:'.format(**entry) + ":",
                                                      text_color_for_value="#ffb399", append=True)
                        mainWindow['resultML'].update('{pluginName}'.format(**entry) + ":", append=True)
                        mainWindow['resultML'].update("{}".format(sev), append=True)
                    elif sev == "Medium":
                        mainWindow['resultML'].update('{ip}'.format(**entry) + ":", append=True)
                        mainWindow['resultML'].update('{pluginID}:'.format(**entry) + ":",
                                                      text_color_for_value="#f9eca5", append=True)
                        mainWindow['resultML'].update('{pluginName}'.format(**entry) + ":", append=True)
                        mainWindow['resultML'].update("{}".format(sev), append=True)
                    elif sev == "Low":
                        mainWindow['resultML'].update('{ip}'.format(**entry) + ":", append=True)
                        mainWindow['resultML'].update('{pluginID}:'.format(**entry) + ":",
                                                      text_color_for_value="#eef0f0", append=True)
                        mainWindow['resultML'].update('{pluginName}'.format(**entry) + ":", append=True)
                        mainWindow['resultML'].update("{}".format(sev), append=True)
                    elif sev == "Info":
                        mainWindow['resultML'].update('{ip}'.format(**entry) + ":", append=True)
                        mainWindow['resultML'].update('{pluginID}:'.format(**entry) + ":",
                                                      text_color_for_value="#95a5a6", append=True)
                        mainWindow['resultML'].update('{pluginName}'.format(**entry) + ":", append=True)
                        mainWindow['resultML'].update("{}".format(sev), append=True)

                    # #778484
                    mainWindow['resultML'].update(':notes: |' + entry.get('notes') + "|", append=True)
                    mainWindow['resultML'].update(':reason: |' + entry.get('reason') + "|", append=True)
                    mainWindow['resultML'].update(':{exempt}:'.format(**entry), append=True)
                    mainWindow['resultML'].update('{customUUID}'.format(**entry) + '\n', text_color_for_value="#778484",
                                                  append=True)
                # returns: <PySimpleGUI.PySimpleGUI.Multiline object at 0x000001FE2CB093F0>

                quicML = mainWindow['resultML'].get()
                ipPattern = re.compile(
                    r'^(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
                ipList = []
                for line in quicML.splitlines():
                    ipList.append(ipPattern.search(quicML))

                lows = quicML.count("Low")
                meds = quicML.count("Medium")
                highs = quicML.count("High")
                crits = quicML.count("Critical")
                exempts = quicML.count("True")
                # print(lows)
                # crits = v['resultML'].count("Critical")

                # print(ipList)
                strippedDupes = list(set(ipList))
                noIPDupes = len(strippedDupes)
                # print(strippedDupes)

                # PLUGINS:

                pluginList = []
                for line in quicML.splitlines():
                    y = line.split(":")
                    z = y[1].split(" ")
                    # pluginList.append(z)
                    # print(z[0])
                    pluginList.append(z[0])
                totalPlugins = len(pluginList)
                noDupes = list(set(pluginList))
                totalUniquePlugins = len(noDupes)

                mainWindow['analyzeText'].update(
                    "IP's: {}, Unique IP's: {}, Plugins: {}, Unique Plugins: {}, Lows: {}, Meds: {}, Highs: {}, Crits: {}, Exempts: {}".format(
                        len(ipList), noIPDupes, totalPlugins, totalUniquePlugins, lows, meds, highs, crits, exempts))


            except UnboundLocalError:
                loggy("Bad Query to ACAS", "ERROR")
                mainWindow['info'].update("Bad ACAS Query", text_color="#ffb399")
        elif allGood != 1:
            Sg.PopupOK(allGood)
        else:
            loggy("ACAS Error", "ERROR")
            mainWindow['info'].update("Error with ACAS query", text_color="#ffb399")

    # analyze(v, mainWindow) # populate data counts

    if b == "wut":
        mainWindow['info'].update("Created By Preston And eagleEggs", text_color="lightblue")

    if b == "saveSearch":
        saveSearch = not saveSearch
        if saveSearch is True:
            mainWindow['saveSearch'].update(
                image_data=b'iVBORw0KGgoAAAANSUhEUgAAABcAAAAXCAYAAADgKtSgAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAJUSURBVEhLtZXLTxNRFMa/ipKoZYhEkc60amzqQokhPujONrpQF76FhFbQnQSjWxMT1Oh/oAsRxbQqZQcIiQvbMmLcqLgqSivBldQdJj6CUcw45/ZOnbG9M8XgL5lM5pw73z3z3XPvuLwb/Br+E8v4XUgoHIY/sIU/LQ5b8XUNHryZyqKmxv1PEwjFSVjTNPTH7+JMRxSz+Tzu9fXybGUIxQ1hafUKBHc2QpY9iD9I8GxllIhTxWvXNxSFDS6c68SLVxO4dv0qjzhTJdXWFUebrTALE165Hp+/zONOXwytrSeRyWR4RkxR3E7YILi7CZK0htmzvLoaBw7uR/upKFT1KR9hhfX5nlAIb7M5W2ELVSsRu/8QybSKfP4jCymyzBa+u/sKeyaY+OZAALWSxJLNO7bxVIXoEyXTY0ilVLyceI3v377yBLfl09wcVrndGBoeRWrsOby+jVA89XyIA9oC/Jt8mMrNIJt7h4WfP3jC1C3vp6fZrIrechcvXcbNnjjPOHPjVgxDj0Zx7MghHilQ0orPxsdxvussBodHMDjyhEfFmIUHEgM8WkB4cLVF2thLavIx8GueR63YCROWPjczmZlk7aabiqbtWwtBE07ChHD7E/v2hpFKl/awIUy4XC52L4eteLB5FzuwqN0MzBXTRWsTiUZ41orQFoJ2HlmjKB7Wbn9bQda1tJxgsXJHguOfiDaYT1H0CWRWZTmPjcU/fvQwEv1/Tk5bWwjatXQaioQJipWzaEn/ocYXnG6P4HZPr3Pli4G+gIQ/zOpNoLOklVsBfgMoUPQDp6t41QAAAABJRU5ErkJggg==')
        else:
            mainWindow['saveSearch'].update(
                image_data=b'iVBORw0KGgoAAAANSUhEUgAAABcAAAAXCAYAAADgKtSgAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsIAAA7CARUoSoAAAAJiSURBVEhLtZVLaBNRFIb/aalSbSbQithJUDRgje60VtxI2yTutL7AR1oTpfiCuBTsQkRF7DZWKgglauPOShVcaC2h4mOGWCoopUiLi2YKomgSpUipcc71pk7SeSH4wXCHcy7/PXPOPWcE72pfAf+JCr4aIi6vwrXL59Hfdx2eVbXc6hzTyEm4P3ELgiBgOqPC5apB+/EY9zrDMHK9cDjSicSdJDySBP/6NXyHMxaJlwvnfsxBfvMOqjqDSMcRvssZJeJGwkXiN25i29ZGhJq3c4s9laK79iK9WAkTmZlPcLuW4UTnMYg11VDk11poVdxrDBO3Ey4ip8eQz31DtCOM6NEwvPUrsXRJBaYmPxgexG5L95UubNzQYClcwvysJt6OUKAFklTPTBlVZYUfSmlfxGHiyb4eZHM55lRG33OXQ7SDQoFWBIMtaGrcgrb9hxYCZAU913UBblFE99VLrGGaNm9iTkdUVuNp6hUyWi+Uw3Ke/z6LgcHHUBQZvnVrWU5Z0dJv+TZrzp6OYm/bLjwYfISRl6PcqrstxOcvWQwNP18oGq3jE5Pca4xeON6b4NY/GHbowMMnbHPszEmWUzOshAlDcSLe08tWuhVG2AkTpuJUqGfDKQQDzdzwl6IwUSiYT2xzcQ1ZSbOBpU+NPmJ69u3ZjdipCPeWUlLQcqjzqBNpaE19nF6UCupYGgl0gNHtshSnlt7ZugN1K+rgb/AxkfIcWx1gLa6Rz37F4YMH4NfGg1nxzA5w9A+lwUbYzZ1i2m7fvYdE8r595MTPuV/ssYO+QCjMw+uRMPJCcRb5vwH8BkJuE0gT8P8VAAAAAElFTkSuQmCC')

    if b == "saveSearch2":
        saveSearch2 = not saveSearch2
        if saveSearch2 is True:
            mainWindow['saveSearch2'].update(
                image_data=b'iVBORw0KGgoAAAANSUhEUgAAABcAAAAXCAYAAADgKtSgAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAJUSURBVEhLtZXLTxNRFMa/ipKoZYhEkc60amzqQokhPujONrpQF76FhFbQnQSjWxMT1Oh/oAsRxbQqZQcIiQvbMmLcqLgqSivBldQdJj6CUcw45/ZOnbG9M8XgL5lM5pw73z3z3XPvuLwb/Br+E8v4XUgoHIY/sIU/LQ5b8XUNHryZyqKmxv1PEwjFSVjTNPTH7+JMRxSz+Tzu9fXybGUIxQ1hafUKBHc2QpY9iD9I8GxllIhTxWvXNxSFDS6c68SLVxO4dv0qjzhTJdXWFUebrTALE165Hp+/zONOXwytrSeRyWR4RkxR3E7YILi7CZK0htmzvLoaBw7uR/upKFT1KR9hhfX5nlAIb7M5W2ELVSsRu/8QybSKfP4jCymyzBa+u/sKeyaY+OZAALWSxJLNO7bxVIXoEyXTY0ilVLyceI3v377yBLfl09wcVrndGBoeRWrsOby+jVA89XyIA9oC/Jt8mMrNIJt7h4WfP3jC1C3vp6fZrIrechcvXcbNnjjPOHPjVgxDj0Zx7MghHilQ0orPxsdxvussBodHMDjyhEfFmIUHEgM8WkB4cLVF2thLavIx8GueR63YCROWPjczmZlk7aabiqbtWwtBE07ChHD7E/v2hpFKl/awIUy4XC52L4eteLB5FzuwqN0MzBXTRWsTiUZ41orQFoJ2HlmjKB7Wbn9bQda1tJxgsXJHguOfiDaYT1H0CWRWZTmPjcU/fvQwEv1/Tk5bWwjatXQaioQJipWzaEn/ocYXnG6P4HZPr3Pli4G+gIQ/zOpNoLOklVsBfgMoUPQDp6t41QAAAABJRU5ErkJggg==')
        else:
            mainWindow['saveSearch2'].update(
                image_data=b'iVBORw0KGgoAAAANSUhEUgAAABcAAAAXCAYAAADgKtSgAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsIAAA7CARUoSoAAAAJiSURBVEhLtZVLaBNRFIb/aalSbSbQithJUDRgje60VtxI2yTutL7AR1oTpfiCuBTsQkRF7DZWKgglauPOShVcaC2h4mOGWCoopUiLi2YKomgSpUipcc71pk7SeSH4wXCHcy7/PXPOPWcE72pfAf+JCr4aIi6vwrXL59Hfdx2eVbXc6hzTyEm4P3ELgiBgOqPC5apB+/EY9zrDMHK9cDjSicSdJDySBP/6NXyHMxaJlwvnfsxBfvMOqjqDSMcRvssZJeJGwkXiN25i29ZGhJq3c4s9laK79iK9WAkTmZlPcLuW4UTnMYg11VDk11poVdxrDBO3Ey4ip8eQz31DtCOM6NEwvPUrsXRJBaYmPxgexG5L95UubNzQYClcwvysJt6OUKAFklTPTBlVZYUfSmlfxGHiyb4eZHM55lRG33OXQ7SDQoFWBIMtaGrcgrb9hxYCZAU913UBblFE99VLrGGaNm9iTkdUVuNp6hUyWi+Uw3Ke/z6LgcHHUBQZvnVrWU5Z0dJv+TZrzp6OYm/bLjwYfISRl6PcqrstxOcvWQwNP18oGq3jE5Pca4xeON6b4NY/GHbowMMnbHPszEmWUzOshAlDcSLe08tWuhVG2AkTpuJUqGfDKQQDzdzwl6IwUSiYT2xzcQ1ZSbOBpU+NPmJ69u3ZjdipCPeWUlLQcqjzqBNpaE19nF6UCupYGgl0gNHtshSnlt7ZugN1K+rgb/AxkfIcWx1gLa6Rz37F4YMH4NfGg1nxzA5w9A+lwUbYzZ1i2m7fvYdE8r595MTPuV/ssYO+QCjMw+uRMPJCcRb5vwH8BkJuE0gT8P8VAAAAAElFTkSuQmCC')

    if b == "sendParser":
        sendParser = not sendParser
        if sendParser is True:
            mainWindow['sendParser'].update(
                image_data=b'iVBORw0KGgoAAAANSUhEUgAAABkAAAAZCAYAAADE6YVjAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAItSURBVEhLY5SRU/7PQGMAtmT/jrVQLio4cvoKw569+xmu3bjJ8PnzZwZeXl4GLQ11BhdnRwYbUx2oKvzA0SMYuyXb9h5jmDxtJpitoa7GYG5mwsAHtOAT0KKTp84w3Lh5CyyXl53B4OlkCWbjAlgtKapuY7gOdHmgvy9DWlwIVBQTzFq0hmH9xs0MmkCf9bVWQUUxAcgSJigbDAqrWhkeP3nKMG1SH14LQAAkD1IHUg9yGD4AtwQURKBg6GprYlCUFoaK4gcgdSD1IJ+D9OMCcEtAcQAKImItgAGQepA+WBxiA2BLDp++DOYQCiJcAKYPZg46AFuyZ89+cCqiBID0g8zBBsCWgPIBKJlSAkD6r0OTNjoAW/LlyxdwPqAESEtLMfz/j73wAFvCw8MDzmiUAFtTXYbVC6dCeagAbAmoqDh1+ixYgBYAbImLiyM4rdMKgC0BeRUEQEUFJQBUoGIDYEtAIDcrHVwW3X/6FipCGgDlkdaObobZizFLdLglXs5W4LReXl1PlkWg0ADl/HUbNmFYxMzHL9SQEBMO5ng42zEcO3WeYeGSZQzff/1jMNbXAosTC0Dqv/38Cw4RmP6FS1YRrk9ARTmsPiEWzF+0FFzJxcdGMcycMQt/zQgKZ1BRASoRQBmWVGBmYsxw6OBB/JaQC8IScsC5f+nCOQzuHj6IiKcWQLaAjeEnWIxqlvxiYIdbACpeYBaAANUsOXn6DNwCdACOEyibRoCBAQAiIe704Ih05wAAAABJRU5ErkJggg==')
        else:
            mainWindow['sendParser'].update(
                image_data=b'iVBORw0KGgoAAAANSUhEUgAAABkAAAAZCAYAAADE6YVjAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAIeSURBVEhLY1TR1P/PQGOA1xIbUx0GF2dHBi0NdQZeXl6Gz58/M1y7cZNhz979DEdOX4GqIgywWuLlbMWQm5UOZt+4eYvh5KkzDJ+AFvABLTI3M2HQUFcDy02aOoNh+77jYDY+gGFJX2sVgybQ5es3bmaYtWgNVBQTpMWFMAT6+zJcB/qsqLoNKoodoFjS31bNICMtxVBWVcdw/+lbqChuoCgtzNDV1sTw+MlTvBYxQWlwEIGCgVgLQACkDqQe5HOQflwAbgkoDkBBRKwFMABSD9IHi0NsAGyJrakumIMvDvABmD6YOegAbImLiyM4FVECQPpB5mADYEtA+QCUTCkBIP2a0KSNDsCW8PDwgPMBJeDp02cMjIyMUB4qAFvy5csXcEajBBw+fZkhND4bykMFYEtARYWZqTFYgBYAbMmePfvBaZ1WAGwJyKsgACoqKAGgAhUbYBYSlWgAMd6/fcUQHxvFcOzoYYYPn7+DJUkBoDxSXVHKwMXOzHDu0nWoKATALbl9/zGDiYE2Q1CAL8OZ0ydJtujRs1cM3BwsQP1+GBbBLQGBnXsPM1iZGYJ9hM1FhMDZi9ewWkSwPgEV5bD6hFiQGBcNruQWLl7GsGLDTvw1IyicQUUFqEQAZVhSwakzZxnq2yfht4RcsGrBFHDuj45PYfjFwA5JwtQE6BaAANUsYWP4CbcAVLzALAABqllibmoCtwAd0CROUAEDAwDjas5sJxYwuwAAAABJRU5ErkJggg==')

    if b == "sendParser2":
        sendParser2 = not sendParser2
        if sendParser2 is True:
            mainWindow['sendParser2'].update(
                image_data=b'iVBORw0KGgoAAAANSUhEUgAAABkAAAAZCAYAAADE6YVjAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAItSURBVEhLY5SRU/7PQGMAtmT/jrVQLio4cvoKw569+xmu3bjJ8PnzZwZeXl4GLQ11BhdnRwYbUx2oKvzA0SMYuyXb9h5jmDxtJpitoa7GYG5mwsAHtOAT0KKTp84w3Lh5CyyXl53B4OlkCWbjAlgtKapuY7gOdHmgvy9DWlwIVBQTzFq0hmH9xs0MmkCf9bVWQUUxAcgSJigbDAqrWhkeP3nKMG1SH14LQAAkD1IHUg9yGD4AtwQURKBg6GprYlCUFoaK4gcgdSD1IJ+D9OMCcEtAcQAKImItgAGQepA+WBxiA2BLDp++DOYQCiJcAKYPZg46AFuyZ89+cCqiBID0g8zBBsCWgPIBKJlSAkD6r0OTNjoAW/LlyxdwPqAESEtLMfz/j73wAFvCw8MDzmiUAFtTXYbVC6dCeagAbAmoqDh1+ixYgBYAbImLiyM4rdMKgC0BeRUEQEUFJQBUoGIDYEtAIDcrHVwW3X/6FipCGgDlkdaObobZizFLdLglXs5W4LReXl1PlkWg0ADl/HUbNmFYxMzHL9SQEBMO5ng42zEcO3WeYeGSZQzff/1jMNbXAosTC0Dqv/38Cw4RmP6FS1YRrk9ARTmsPiEWzF+0FFzJxcdGMcycMQt/zQgKZ1BRASoRQBmWVGBmYsxw6OBB/JaQC8IScsC5f+nCOQzuHj6IiKcWQLaAjeEnWIxqlvxiYIdbACpeYBaAANUsOXn6DNwCdACOEyibRoCBAQAiIe704Ih05wAAAABJRU5ErkJggg==')
        else:
            mainWindow['sendParser2'].update(
                image_data=b'iVBORw0KGgoAAAANSUhEUgAAABkAAAAZCAYAAADE6YVjAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsQAAA7EAZUrDhsAAAIeSURBVEhLY1TR1P/PQGOA1xIbUx0GF2dHBi0NdQZeXl6Gz58/M1y7cZNhz979DEdOX4GqIgywWuLlbMWQm5UOZt+4eYvh5KkzDJ+AFvABLTI3M2HQUFcDy02aOoNh+77jYDY+gGFJX2sVgybQ5es3bmaYtWgNVBQTpMWFMAT6+zJcB/qsqLoNKoodoFjS31bNICMtxVBWVcdw/+lbqChuoCgtzNDV1sTw+MlTvBYxQWlwEIGCgVgLQACkDqQe5HOQflwAbgkoDkBBRKwFMABSD9IHi0NsAGyJrakumIMvDvABmD6YOegAbImLiyM4FVECQPpB5mADYEtA+QCUTCkBIP2a0KSNDsCW8PDwgPMBJeDp02cMjIyMUB4qAFvy5csXcEajBBw+fZkhND4bykMFYEtARYWZqTFYgBYAbMmePfvBaZ1WAGwJyKsgACoqKAGgAhUbYBYSlWgAMd6/fcUQHxvFcOzoYYYPn7+DJUkBoDxSXVHKwMXOzHDu0nWoKATALbl9/zGDiYE2Q1CAL8OZ0ydJtujRs1cM3BwsQP1+GBbBLQGBnXsPM1iZGYJ9hM1FhMDZi9ewWkSwPgEV5bD6hFiQGBcNruQWLl7GsGLDTvw1IyicQUUFqEQAZVhSwakzZxnq2yfht4RcsGrBFHDuj45PYfjFwA5JwtQE6BaAANUsYWP4CbcAVLzALAABqllibmoCtwAd0CROUAEDAwDjas5sJxYwuwAAAABJRU5ErkJggg==')
    if b == "Plugin ID":
        allGood = functionalityCheck("Plugin ID")
        if allGood == 1:
            try:
                plugin = v['query']
                print(str(plugin))

                plugins = getPlugin(plugin)
                # print(vulns)
                autoClear()
                for entry in plugins.values():
                    mainWindow['resultML'].update(("{}\n".format(entry)), append=True)
            except UnboundLocalError:
                mainWindow['info'].update("Bad Query to ACAS", text_color="#ffb399")
        elif allGood != 1:
            Sg.PopupOK(allGood)
        else:
            mainWindow['info'].update("Bad Query to ACAS", text_color="#ffb399")

    if b == "List Scans":
        scanList = sc.scans.list()
        autoClear()
        for scanEntry in scanList.values():
            mainWindow['resultML'].update(("{}\n".format(scanEntry)), append=True)

    if b == "Email Parsed Output":
        email(v['parserML'], v['emailSender'], v['emailRecipient'])

    if b == "advQuery":
        try:
            query = v['advQueries']
            y = query.split("&")
            tupleList = []
            i = 0  # tracking how many parameters are being used
            for x in y:  # building the query tuples for ACAS API
                w = x.split("==")
                if w[0] == "severity":
                    tupleList.append(('severity', '=', '{}'.format(w[1])))
                    i = i + 1
                if w[0] == "ip":
                    tupleList.append(('ip', '=', '{}'.format(w[1])))
                    i = i + 1
                if w[0] == "plugin":
                    tupleList.append(('pluginID', '=', '{}'.format(w[1])))
                    i = i + 1

            list2Tuple = tuple(tupleList)

            if i == 3:  # checking parameter totals before passing to call
                advVulns = sc.analysis.vulns(list2Tuple[0], list2Tuple[1], list2Tuple[2])
            if i == 2:
                advVulns = sc.analysis.vulns(list2Tuple[0], list2Tuple[1])
            if i == 1:
                advVulns = sc.analysis.vulns(list2Tuple[0])
            mainWindowList = []

            for vuln in advVulns:
                mainWindowList.append(vuln)

            f = open('configs/vulnIdentity.json')
            data = json.load(f)
            f.close()

            for item in mainWindowList:
                found = False
                while not found:
                    for value in data:
                        if item.get('ip') == data[value][0].get("ip") and item.get('pluginID') == data[value][0].get(
                                'pluginID'):
                            item['customUUID'] = str(value)
                            item['notes'] = data[value][0].get('notes')
                            item['exempt'] = data[value][0].get('exempt')
                            item['reason'] = data[value][0].get('reason')
                            found = True
                            break
                    if not found:
                        newID = str(uuid4())
                        data[newID] = [
                            {"ip": item.get('ip'), "pluginID": item.get('pluginID'), "notes": "", "exempt": False,
                             "reason": ""}]
                        item['customUUID'] = newID
                        item['notes'] = data[value][0].get('notes')
                        item['exempt'] = data[value][0].get('exempt')
                        item['reason'] = data[value][0].get('reason')
                        found = True

            toDump = data
            json_object = json.dumps(toDump, indent=4)
            with open("configs/vulnIdentity.json", "w") as outFile:
                outFile.write(json_object)

            for entry in mainWindowList:
                sev = entry.get('severity').get('name')
                # mainWindow['resultML'].update('{ip}:{pluginID}:{pluginName}'.format(**entry) + ":", append=True)
                mainWindow['resultML'].update('{ip}'.format(**entry) + ":", append=True)
                mainWindow['resultML'].update('{pluginID}'.format(**entry) + ":", text_color_for_value="#cc4668",
                                              append=True)
                mainWindow['resultML'].update('{pluginName}'.format(**entry) + ":", append=True)
                mainWindow['resultML'].update("{}".format(sev), append=True)
                mainWindow['resultML'].update(':notes: |' + entry.get('notes') + "|", append=True)
                mainWindow['resultML'].update(':reason: |' + entry.get('reason') + "|", append=True)
                mainWindow['resultML'].update(':{exempt}:'.format(**entry), append=True)
                mainWindow['resultML'].update('{customUUID}'.format(**entry) + '\n', text_color_for_value="#778484",
                                              append=True)
            with open("configs/advQuery.cache", "r+") as advQueryCache:
                advQueryCache.write("\n{}".format(v['advQueries']))
                newAdvList = []
                for advQ in advQueryCache:
                    newAdvList.append("{}".format(advQ.strip()))  # TODO: Doesn't update DD to latest search

                newAdvList.reverse()
                mainWindow['advQueries'].update(value=newAdvList[0], values=newAdvList)

            # analyze()
            print("Updated Adv Queries")

        except:
            pass

    if b == "saveSession":
        saveCheck = Sg.PopupOKCancel("Override All Saved Configurations?")
        if saveCheck == "OK":  # useful if the button is accidentally pressed :)
            saveConfig()
        else:
            pass

    if b == "loadSession":
        loadConfig()

    if b == "loadScan":
        loadScanConfig()
    if b == "saveScan":
        saveScanConfig()
        print("saved scan")

    if b == "launchScan":
        # first, create a scan definition:
        mainWindow['info'].update("Launching Scan", text_color="lightgreen")
        print("{}".format(str(v['name'])), "{}".format(v['scanRepoID']), "{}".format(int(v['policy_id'])),
              "{}".format(v['targets']))
        mainWindow['scanOutput'].update("Scan Setup Info:/n {}/n, {}/n, {}/n, {}".format(str(v['name']),
                                                                                         v['scanRepoID'],
                                                                                         int(v['policy_id']),
                                                                                         v['targets']), append=True)
        scanning = sc.scans.create(name=str(v['name']), repo=v['scanRepoID'], creds=[v["scanCreds"]],
                                   policy_id="{}".format(int(v['policy_id'])), targets=[v["targets"]])
        print(scanning['id'])  # this is the ID needed to launch a scan
        mainWindow['scanOutput'].update("Scan Definition ID: {}".format(scanning['id']), append=True)
        mainWindow['scanIDDD'].update(value=scanning['id'])

        scanLaunching = sc.scans.launch(id=scanning['id'])
        print("Scan Result will be at {}".format(scanLaunching['scanResult']['id']))
        # mainWindow['scanOutput'].update("Launch Details: {}".format(scanLaunching), append = True)
        mainWindow['scanOutput'].update("Scan Result ID: {}".format(scanLaunching['scanResult']['id']), append=True)
        mainWindow['resultIDDD'].update(value=scanLaunching['scanResult']['id'])

        with open("configs/scanHistory.cache", "r+") as scanHistory:
            scanHistory.write("\n{},{}".format(scanLaunching['scanResult']['id'], scanLaunching['scanResult']['id']))

            scanHistList = []
            resultScanHistList = []
            scanz = scanHistory.read()
            for data in scanz.splitlines():
                spli = data.split(",")
                scanHistList.append(spli[0])
                resultScanHistList.append(spli[1])

            scanHistList.reverse()
            resultScanHistList.reverse()
            # mainWindow['solutionDropDown'].update(value=newList[0], values=newList)
            mainWindow['scanIDDD'].update(value=scanning['id'])
            mainWindow['resultIDDD'].update(value=scanLaunching['scanResult']['id'])

    if b == "clearScanOutput":
        mainWindow['scanOutput'].update("")

    if b == "queryResult":

        try:
            scanRes = sc.scan_instances.details(int(v['resultIDDD']))
            mainWindow['scanOutput'].update("Completed IP's: {} \
								Completed Checks: {} \
						Total Checks: {} \
		Scanned IP's: {}\
										".format(scanRes.get('completedIPs'),
                                                 scanRes.get('completedChecks'),
                                                 scanRes.get('totalChecks'),
                                                 scanRes.get('scannedIPs'), append=True))
            completedChecks = int(scanRes['progress'].get("completedChecks"))
            totalChecks = int(scanRes['progress'].get("totalChecks"))
            mainWindow['progress'].update(current_count=int(completedChecks),
                                          max=int(totalChecks))
            mainWindow['progress'].update(int(completedChecks))
        except:
            loggy("Error Querying Scan Result Details", "ERROR")
            mainWindow['info'].update("Error Connecting to ACAS", text_color="#ffb399")

    if b == "queryScan":
        try:
            scanDefRes = sc.scans.details(int(v['scanIDDD']))
            mainWindow['scanOutput'].update("Scan ID: {} \
										Scan Name: {} \
										IP List: {} \
										Total Checks: {} \
										Scanned IP's: {}\
										".format(scanDefRes.get('id'), scanDefRes.get('name'),
                                                 scanDefRes.get('ipList'), append=True))
        except:
            loggy("Error Querying Scan Details", "ERROR")
            mainWindow['info'].update("Error Querying Scan Details", text_color="#ffb399")

    if b == "updateProgress":
        # currentValue = int(v['progress'])
        x = 0
        mainWindow['progress'].update(current_count=x + 3)

    if b == "Quickest Solutions":
        # i.e. get vuln count down...
        # get wordcloud results, drill down to easiest resolutions, i.e. updates and reg values based on easiest resolutions
        mainWindow['info'].update("Not Implemented Yet\n get wordcloud results, drill down to easiest resolutions",
                                  text_color="#ffb399")
    # Sg.PopupOK("Not Implemented Yet\n get wordcloud results, drill down to easiest resolutions, i.e. updates and reg values based on easiest resolutions")

    if b == "Ideal Solutions":
        # i.e. get severities down...
        # get wordcloud results, drill down to most critical resolutions based on severity
        mainWindow['info'].update("Not Implemented Yet\n get wordcloud results, drill down to easiest resolutions",
                                  text_color="#ffb399")

    if b == "Flip to CSV":
        mainWindow.Element('csvTab').Select()

    if b == "showSolution":
        try:
            # vulns = getVulnsList(sc, ip, sev)
            for entry in vulns:
                mainWindow['resultML'].update('{ip}:{pluginID}:{pluginName}:{solution}'.format(**entry) + "\n",
                                              append=True)
        except:
            loggy("Error Displaying Vuln Data", "ERROR")
            mainWindow['info'].update("Error Displaying Vuln Data", text_color="#ffb399")

    if b == "wordcloud":

        try:
            stop_words = STOPWORDS.update(list(defaultStopWords))
            # stopwords = ["Medium", "critical", "low", "high", "the", "name", "Severity", "id"]
            text = v['resultML']
            text.replace("'", "")
            wordcloud = WordCloud(stopwords=stop_words, colormap="Greys", max_words=100).generate(text)
            # print(wordcloud.words_.keys())
            import matplotlib.pyplot as plt

            plt.imshow(wordcloud, interpolation='bilinear')
            plt.axis("off")

            # lower max_font_size
            # wordcloud = WordCloud(max_font_size=40).generate(text)
            # plt.figure()
            # plt.imshow(wordcloud, interpolation="bilinear")
            # plt.axis("off")
            plt.show()
        except:
            loggy("Error with Wordcloud", "ERROR")

    if b == "wordCloudSolutionsTop":
        try:
            stop_words = STOPWORDS.update(list(defaultStopWords))
            # stopwords = ["Medium", "critical", "low", "high", "the", "name", "Severity", "id"]
            text = v['solutionML']
            text.replace("'", "")
            wordcloud = WordCloud(stopwords=stop_words, colormap="Greys", max_words=100).generate(text)
            # print(wordcloud.words_.keys())
            import matplotlib.pyplot as plt

            plt.imshow(wordcloud, interpolation='bilinear')
            plt.axis("off")

            # lower max_font_size
            # wordcloud = WordCloud(max_font_size=40).generate(text)
            # plt.figure()
            # plt.imshow(wordcloud, interpolation="bilinear")
            # plt.axis("off")
            plt.show()
        except:
            loggy("Error with Wordcloud", "ERROR")
            mainWindow['info'].update("Error With Wordcloud", text_color="#ffb399")

    if b == "wordCloudSolutionsBottom":
        try:
            stop_words = STOPWORDS.update(list(defaultStopWords))
            # stopwords = ["Medium", "critical", "low", "high", "the", "name", "Severity", "id"]
            text = v['filteredSolutionML']
            text.replace("'", "")
            wordcloud = WordCloud(stopwords=stop_words, colormap="Greys", max_words=100).generate(text)
            # print(wordcloud.words_.keys())
            import matplotlib.pyplot as plt

            plt.imshow(wordcloud, interpolation='bilinear')
            plt.axis("off")

            # lower max_font_size
            # wordcloud = WordCloud(max_font_size=40).generate(text)
            # plt.figure()
            # plt.imshow(wordcloud, interpolation="bilinear")
            # plt.axis("off")
            plt.show()
        except:
            loggy("Error with Wordcloud", "ERROR")
            mainWindow['info'].update("Error With Wordcloud", text_color="#ffb399")

    if b == "recommendSolutions":
        try:
            if solutionizerList is None:
                continue
        except:
            mainWindow['info'].update("Must Query ACAS Data First", text_color="#ffb399")
            continue

        easyDropDown = mainWindow['easy']
        interDropDown = mainWindow['intermediate']
        hardDropDown = mainWindow['hard']
        insaneDropDown = mainWindow['insane']
        mainWindow.Element('Recommended Solutions').Select()
        results = getSuggestions(solutionizerList, easyList, interList, hardList, insaneList)

        mainWindow["recSolutionML"].update('Easy Solutions: \n \n')
        for entry in results.get('simple'):
            mainWindow["recSolutionML"].update(
                '{ip}:{pluginID}:{solution}:'.format(**entry) + entry.get('severity').get('name') + '\n', append=True)
            mainWindow["d0ML"].update(
                '{ip}:{pluginID}:{solution}:'.format(**entry) + entry.get('severity').get('name') + '\n', append=True)

        mainWindow["recSolutionML"].update('Intermediate Solutions: \n \n', append=True)
        for entry in results.get('intermediate'):
            mainWindow["recSolutionML"].update(
                '{ip}:{pluginID}:{solution}:'.format(**entry) + entry.get('severity').get('name') + '\n', append=True)
            mainWindow["d1ML"].update(
                '{ip}:{pluginID}:{solution}:'.format(**entry) + entry.get('severity').get('name') + '\n', append=True)

        mainWindow["recSolutionML"].update('Hard solutions: \n \n', append=True)
        for entry in results.get('hard'):
            mainWindow["recSolutionML"].update(
                '{ip}:{pluginID}:{solution}:'.format(**entry) + entry.get('severity').get('name') + '\n', append=True)
            mainWindow["d2ML"].update(
                '{ip}:{pluginID}:{solution}:'.format(**entry) + entry.get('severity').get('name') + '\n', append=True)

        mainWindow["recSolutionML"].update('------------ \n \n Insane Solutions: \n \n', append=True)
        for entry in results.get('insane'):
            mainWindow["recSolutionML"].update(
                '{ip}:{pluginID}:{solution}:'.format(**entry) + entry.get('severity').get('name') + '\n', append=True)
            mainWindow["d3ML"].update(
                '{ip}:{pluginID}:{solution}:'.format(**entry) + entry.get('severity').get('name') + '\n', append=True)

        mainWindow["recSolutionML"].update('------------ \n \n Unknown Difficulty: \n \n', append=True)
        for entry in results.get('unknown'):
            mainWindow["recSolutionML"].update(
                '{ip}:{pluginID}:{solution}:'.format(**entry) + entry.get('severity').get('name') + '\n', append=True)

    if b == "recommendSolutionsBelow":
        mainWindow.Element('Recommended Solutions').Select()
        results = getSuggestions(filteredList, easyList, interList, hardList, insaneList)

        mainWindow["recSolutionML"].update('Easy solutions: \n \n')
        for entry in results.get('simple'):
            mainWindow["recSolutionML"].update('{ip}:{pluginID}:{solution}:{severity}'.format(**entry) + '\n',
                                               append=True)

        mainWindow["recSolutionML"].update('intermediate: \n \n', append=True)
        for entry in results.get('intermediate'):
            mainWindow["recSolutionML"].update('{ip}:{pluginID}:{solution}:{severity}'.format(**entry) + '\n',
                                               append=True)

        mainWindow["recSolutionML"].update('Hard solutions: \n \n', append=True)
        for entry in results.get('hard'):
            mainWindow["recSolutionML"].update('{ip}:{pluginID}:{solution}:{severity}'.format(**entry) + '\n',
                                               append=True)

        mainWindow["recSolutionML"].update('------------ \n \n insane solutions: \n \n', append=True)
        for entry in results.get('insane'):
            mainWindow["recSolutionML"].update('{ip}:{pluginID}:{solution}:{severity}'.format(**entry) + '\n',
                                               append=True)

        mainWindow["recSolutionML"].update('------------ \n \n Unknown Difficulty \n \n', append=True)
        for entry in results.get('unknown'):
            mainWindow["recSolutionML"].update('{ip}:{pluginID}:{solution}:{severity}'.format(**entry) + '\n',
                                               append=True)

    if b == "addDiffFilterD0":
        easyDropDown = mainWindow['easy']
        print(updateKeys(easyDropDown, 'configs/easy.config', str(v['easy']), 1))
    if b == "removeDiffFilterD0":
        easyDropDown = mainWindow['easy']
        print(updateKeys(easyDropDown, 'configs/easy.config', str(v['easy']), 0))

    if b == "addDiffFilterD1":
        interDropDown = mainWindow['intermediate']
        print(updateKeys(interDropDown, 'configs/intermediate.config', str(v['intermediate']), 1))
    if b == "removeDiffFilterD1":
        interDropDown = mainWindow['intermediate']
        print(updateKeys(interDropDown, 'configs/intermediate.config', str(v['intermediate']), 0))

    if b == "addDiffFilterD2":
        hardDropDown = mainWindow['hard']
        print(updateKeys(hardDropDown, 'configs/hard.config', str(v['hard']), 1))
    if b == "removeDiffFilterD2":
        hardDropDown = mainWindow['hard']
        print(updateKeys(hardDropDown, 'configs/hard.config', str(v['hard']), 0))

    if b == "addDiffFilterD3":
        insaneDropDown = mainWindow['insane']
        print(updateKeys(insaneDropDown, 'configs/insane.config', str(v['insane']), 1))
    if b == "removeDiffFilterD3":
        insaneDropDown = mainWindow['insane']
        print(updateKeys(insaneDropDown, 'configs/insane.config', str(v['insane']), 0))

    if b == "graphIt":
        try:  # this can be done better
            fig_canvas_agg.get_tk_widget().forget()
            plt.close('all')
        except:
            pass
        try:
            mainWindow['graphCanvas'].TKCanvas.delete("all")
            lows = v['resultML'].count("Low")
            meds = v['resultML'].count("Medium")
            highs = v['resultML'].count("High")
            crits = v['resultML'].count("Critical")

            if lows + meds + highs + crits == 0:
                Sg.PopupOK("Pull Data First")
                continue

            data = {'Low': int(lows), 'Med': int(meds), 'High': int(highs), 'Crit': int(crits)}
            sev = list(data.keys())
            values = list(data.values())
            plt.style.use('dark_background')
            fig = plt.gcf()
            fig.set_figwidth(4)
            fig.set_figheight(4)

            plt.bar(sev, values, color='blue', width=0.5)

            fig_canvas_agg = draw_figure(mainWindow['graphCanvas'].TKCanvas, fig)
        except:
            loggy("Error Graphing", "ERROR")
            mainWindow['info'].update("Error Graphing", text_color="#ffb399")

    if b == "analyze":  # TODO: moving this into a function to always display and update auto
        # IP's:
        ipPattern = re.compile(
            r'^(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
        ipList = []
        for line in v['resultML'].splitlines():
            ipList.append(ipPattern.search(v['resultML']))

        lows = v['resultML'].count("Low")
        meds = v['resultML'].count("Medium")
        highs = v['resultML'].count("High")
        crits = v['resultML'].count("Critical")
        # crits = v['resultML'].count("Critical")

        # print(ipList)
        strippedDupes = list(set(ipList))
        noIPDupes = len(strippedDupes)
        # print(strippedDupes)

        # PLUGINS:

        pluginList = []
        for line in v['resultML'].splitlines():
            y = line.split(":")
            z = y[1].split(" ")
            # pluginList.append(z)
            # print(z[0])
            pluginList.append(z[0])
        totalPlugins = len(pluginList)
        noDupes = list(set(pluginList))
        totalUniquePlugins = len(noDupes)

        mainWindow['analyzeText'].update(
            "IP's: {}, Unique IP's: {}, Plugins: {}, Unique Plugins: {}, Lows: {}, Meds: {}, Highs: {}, Crits: {}".format(
                len(ipList), noIPDupes, totalPlugins, totalUniquePlugins, lows, meds, highs, crits))

    if b == "clearItems":
        try:
            toClear = mainWindowList
            mainWindowListSearched = clearSearchItems(str(v['searchWords']), toClear)
            if len(mainWindowListSearched) > 0:
                mainWindow['resultML'].update('')
                for entry in mainWindowListSearched:
                    sev = entry.get('severity').get('name')
                    mainWindow['resultML'].update('{ip}:{pluginID}:{pluginName}'.format(**entry) + ":" + sev,
                                                  append=True)
                    mainWindow['resultML'].update(':notes: |' + entry.get('notes') + "|", append=True)
                    mainWindow['resultML'].update(':reason: |' + entry.get('reason') + "|", append=True)
                    mainWindow['resultML'].update(':{exempt}:{customUUID}'.format(**entry) + '\n', append=True)
            else:
                mainWindow['resultML'].update('')
        except:
            mainWindow['info'].update("Nothing to Search", text_color="#ffb399")

    if b == "revert":
        try:
            if len(mainWindowList) > 0:
                mainWindow['resultML'].update('')
                for entry in mainWindowList:
                    sev = entry.get('severity').get('name')
                    mainWindow['resultML'].update('{ip}:{pluginID}:{pluginName}'.format(**entry) + ":" + sev,
                                                  append=True)
                    mainWindow['resultML'].update(':notes: |' + entry.get('notes') + "|", append=True)
                    mainWindow['resultML'].update(':reason: |' + entry.get('reason') + "|", append=True)
                    mainWindow['resultML'].update(':{exempt}:{customUUID}'.format(**entry) + '\n', append=True)
        except NameError:
            mainWindow['info'].update("Nothing to Revert To Bro", text_color="#ffb399")

    if b == "clearTopSolItems":
        mainWindow['solutionML'].update("")

    if b == "clearBottomSolItems":
        mainWindow['filteredSolutionML'].update("")

    if b == "emailSolutionsTop":
        email(v['solutionML'], v['emailSender'], v['emailRecipient'])

    if b == "emailSolutionsBottom":
        email(v['filteredSolutionML'], v['emailSender'], v['emailRecipient'])
    if b == "emailMainWindow":
        email(str(v['resultML']), v['emailSender'], v['emailRecipient'])

    # mainWindow['resultML'].update(entry, append=True)

    if b == "addSolFilter":
        with open("configs/solutionFilter.cache", 'r+') as solCache:
            solCache.write("\n{}".format(v['solutionFilter']))
            # x = searchCache.read()
            newList = []
            # solSearches = []
            for line in solCache:
                newList.append(line)
            # solSearches.append("{}".format(line.strip()))
            newList.append(v['solutionFilter'])
            # print(solSearches)
            newList.reverse()
            mainWindow['solutionDropDown'].update(value=newList[0], values=newList)

    if b == "removeSolFilter":

        with open("configs/solutionFilter.cache", 'r') as solCache:
            lines = solCache.readlines()
        with open('configs/solutionFilter.cache', "w") as solCache:
            for line in lines:
                if line.strip() != str(v['solutionFilter']):
                    solCache.write(line)
        with open("configs/solutionFilter.cache", 'r') as solutionFilterCache:
            solQueries = []
            for line in solutionFilterCache:
                solQueries.append(line.strip())
            mainWindow['solutionDropDown'].update(value=solQueries[0], values=solQueries)

            solQueries.reverse()
            mainWindow['solutionDropDown'].update(value=solQueries[0], values=solQueries)

    if b == "Send to Parser":
        pass

    if b == "search":

        thisSearch = v['searchWords']
        if v['searchWords'] == "":
            continue
        if saveSearch:
            with open("configs/search.cache", 'r+') as searchCache:
                searchCache.write("\n{}".format(v['searchWords']))
                # x = searchCache.read()
                searches = []
                for line in searchCache:
                    searches.append("{}".format(line.strip()))
                # mainWindow['searchWords'].Update(values=searches)
        searchCount = 0
        if sendParser:
            parser = mainWindow['parserML']
            parsedData = []
        searching = True
        mlContent = v['resultML']
        mlSearch = v['searchWords']

        if not sendParser:
            # mainWindow['searchWords'].Update(values=searches)
            for fullLine in mlContent.splitlines():
                for line in fullLine.split():
                    if str(mlSearch.lower()) in str(line.lower()) and searching:
                        searchCount = searchCount + 1
                        # mainWindow['searchCount'].update("#:{}".format(searchCount))
                        searching = False
                        if sendParser:
                            # parsedData.append(fullLine)
                            searchAgain = Sg.PopupYesNo(fullLine)
                            if searchAgain == "Yes":
                                # parser.update("{}\n".format(parsedData), append=True)
                                searching = True
                            else:
                                continue
                        else:
                            searchAgain = Sg.PopupYesNo(fullLine)
                            if searchAgain == "Yes":
                                searching = True
                            else:
                                continue
        else:
            # mainWindow['searchWords'].Update(values=searches)
            queri = v['query']
            sw = v['searchWords']
            # mainWindow['tabGroup'].add_tab(Sg.Tab(f'{sw} {index}', tab(index), key=f'{queri} {index}'))
            generatedTabs = True
            for fullLine in mlContent.splitlines():
                # for line in fullLine.split():
                if str(mlSearch.lower()) in str(fullLine.lower()) and searching:
                    searchCount = searchCount + 1
                    # mainWindow['searchCount'].update("#:{}".format(searchCount))

                    parsedData.append(fullLine)
                    pDataSet = [*set(parsedData)]
                    # searchAgain = Sg.PopupYesNo(fullLine)
                    # for result in pDataSet:
                    # print(v['autoParserTab'])
                    if v['autoParserTab']:
                        print("auto parser is on... maybe not tho")

                        if index is 99 and f'{queri} {index}' in v:
                            print("Existing New Tab Found...")
                            newIndex = 0
                            while newIndex is not 99 and newIndex not in v:
                                queri = v['query']
                                mainWindow['tabGroup'].add_tab(
                                    Sg.Tab(f'{sw} {newIndex}', tab(newIndex), key=f'{queri} {newIndex}'))
                                print(v['tabGroup'])
                                # mainWindow[f'{queri} {index}'].update("{}".format(v[f'{queri} {index}']))
                                mainWindow[f'parserML{newIndex}'].update("{}\n".format(result), append=True)
                                mainWindow.Element(f'{queri} {newIndex}').Select()
                                indexList.append(newIndex)
                                # index+=1
                                generatedTabs = True
                                newIndex = newIndex + 1

                        if index is not 99:
                            # queri = v['query']
                            if index not in indexList:
                                # indexList.append(index)
                                # mainWindow['tabGroup'].add_tab(Sg.Tab(f'{queri} {index}', tab(index), key=f'{queri} {index}'))
                                print(v['tabGroup'])
                                generatedTabs = True
                                # mainWindow[f'{queri} {index}'].update("{}".format(v[f'{queri} {index}']))
                                mainWindow[f'parserML{index}'].update("{}\n".format(result), append=True)
                                mainWindow.Element(f'{queri} {index}').Select()
                                Tabs = True

                        else:
                            loggy(
                                "Tab Index Exceeded beyond 99... Remove Check for Generating New Tabs\n or Remove Tabs",
                                "WARNING")
                            Sg.Popup("Tab Index Exceeded...\nRemove Check for Generating New Tabs")
                            continue

                    else:
                        # print("adding value to ML")
                        parser.update("{}\n".format(fullLine), append=True)
                        mainWindow.Element('parserTab').Select()
                continue
            indexList.append(index)
            index += 1

        mainWindow['searchWords'].Update(values=searches)
        mainWindow['searchWords'].Update(thisSearch)

    # print(v['tabGroup']) # for debugging main tab group
    try:
        if b.__contains__('removeTab'):
            # print('removeTab{}'.format(randrange(0, 6)))
            # print("Removing Tab...")
            # print(v['tabGroup'])
            currentTab = v['tabGroup']
            # print(currentTab)
            mainWindow[currentTab].update(visible=False, disabled=True)
        # index = index - 1
        # indexList.remove()
    except:
        # this gets around the error caused when closing tool (__contains__ error parsed in loop while closing)
        pass

    if b == "Send to Scanner":
        allGood = functionalityCheck("Send to")
        if allGood == 1:
            # pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
            temp = []
            # turn query into list by each line
            query = str(v['resultML']).splitlines()

            # break each line by ":" to get jsut ip's
            for line in query:
                temp.append(line.split(":", maxsplit=1))

            withDuplicates = []

            print("begin looop")

            # place IP's into list
            for item in temp:
                withDuplicates.append("{},".format(item[0]))  # add commas

            sorted = []
            # remove duplicate items
            for item in withDuplicates:
                if item not in sorted:
                    sorted.append(item)

            print("---done loop-------")
            print(sorted)
            if len(sorted) > 0 and len(sorted) != 1:
                sorted[-1] = sorted[-1].rstrip(",")  # remove last comma
                mainWindow['targets'].update(list(sorted))
                mainWindow.Element('scannerTab').Select()
            if len(sorted) == 0:
                pass
            if len(sorted) == 1:
                sorted[0] = sorted[0].rstrip(",")
                mainWindow['targets'].update(list(sorted))
                # mainWindow['targets'].update("{}".format(v['targets'].strip(",")))
                mainWindow.Element('scannerTab').Select()
        elif allGood != 1:
            Sg.PopupOK(allGood)
        else:
            loggy("Error Sending to Scanner", "ERROR")
            mainWindow['info'].update("Error with Scanner", text_color="#ffb399")
    # ipList = []
    # for line in v['resultML'].splitlines():
    # 	ipList.append(pattern.search(v['resultML']))

    # print(ipList)
    # # print(ipList)
    # finalList = []
    # for item in ipList:
    # 	finalList.append(item[0])
    # print(set(finalList))
    # mainWindow['targets'].update(list(finalList))
    # mainWindow.Element('scannerTab').Select()

    if b == "IP Subnet":
        ip = v['query']
        print(str(ip))

        if v['lowV']:  # Severity from check boxes:
            sev = 1
        if v['medV']:
            sev = 2
        if v['highV']:
            sev = 3
        if v['critV']:
            sev = 4

        try:
            vulns = getVulnsSubnet(sc, ip, sev)
            mainWindowList = vulns
            # print(vulns)
            autoClear()
            for entry in vulns:
                mainWindow['resultML'].update(entry, append=True)
        except:
            loggy("Error with ACAS Query (Subnet)", "ERROR")
            mainWindow['info'].update("Error With Query to ACAS", text_color="#ffb399")

    if b == "Severity":
        allGood = functionalityCheck("IP Address")
        if allGood == 1:
            if v['lowV']:  # Severity from check boxes:
                sev = 1
            if v['medV']:
                sev = 2
            if v['highV']:
                sev = 3
            if v['critV']:
                sev = 4

            vulns = getSeverity(sc, sev)
            autoClear()
            # print(vulns)
            for entry in vulns:
                mainWindow['resultML'].update(entry, append=True)
        elif allGood != 1:
            Sg.PopupOK(allGood)
        else:
            loggy("Error with ACAS Query (Sev)", "ERROR")
            mainWindow['info'].update("Error With ACAS Query (Severity Query)", text_color="#ffb399")

    if b == "Send to Solutionizer":  # or v == "CRTL_s":
        print("input received ")
        allGood = functionalityCheck("Send to")
        if allGood == 1:
            mainWindow.Element('solutionizerTab').Select()
            solutionizerList = mainWindowList
            for entry in solutionizerList:
                mainWindow['solutionML'].update(
                    '{ip}:{pluginID}:{solution}:'.format(**entry) + entry.get('severity').get('name') + "\n",
                    append=True)
        elif allGood != 1:
            Sg.PopupOK(allGood)
        else:
            loggy("Error Sending Data to Solutionizer", "ERROR")
            mainWindow['info'].update("Error With Sending Data to Solutionizer", text_color="#ffb399")

    if b == "filterSolutions":
        search = v['solutionDropDown']
        filteredList = filterSolution(solutionizerList, str(search))

        for entry in filteredList:
            mainWindow['filteredSolutionML'].update('{ip}:{pluginID}:{solution}:{severity}'.format(**entry) + "\n",
                                                    append=True)

    if b == "finalExport":
        if v['VM'] == True:
            if v["enableCustomExport"] == True:
                if v['exportAllVM'] == True:
                    convertAllvAnchor(outputVsphere, mainWindowList,
                                      'output/csv/fullExport/bothExported_{}'.format(str(uuid4())) + '.csv', v)
                else:
                    convertAllvAnchor(vSphereList, mainWindowList,
                                      'output/csv/fullExport/bothExported_{}'.format(str(uuid4())) + '.csv', v)
            else:
                defaultConvertAllvAnchor(outputVsphere, mainWindowList,
                                         'output/csv/fullExport/bothExported_{}'.format(str(uuid4())) + '.csv')

            print("exported!")
        if v['Vulnerability'] == True:
            if v["enableCustomExport"] == True:
                alternateConvertAll(dictVersionvSphere, mainWindowList,
                                    'output/csv/fullExport/bothExported_{}'.format(str(uuid4())) + '.csv', v)
            else:
                defaultConvertAll(dictVersionvSphere, mainWindowList,
                                  'output/csv/fullExport/bothExported_{}'.format(str(uuid4())) + '.csv')
            print("exported!")
    if b == "finalExportAndEmail":
        outFilePath = 'output/csv/fullExport/bothExported_{}'.format(str(uuid4())) + '.csv'
        # [Sg.Text("Primary Pivot Key:"), Sg.Radio("Vulnerability", group_id="exportKey"), Sg.Radio("VM", group_id="exportKey")]
        if v['VM'] == True:
            if v["enableCustomExport"] == True:
                if v['exportAllVM'] == True:
                    convertAllvAnchor(outputVsphere, mainWindowList, outFilePath, v)
                else:
                    convertAllvAnchor(vSphereList, mainWindowList, outFilePath, v)
            else:
                defaultConvertAllvAnchor(outputVsphere, mainWindowList, outFilePath)
            print("exported!")
        if v['Vulnerability'] == True:
            if v["enableCustomExport"] == True:
                alternateConvertAll(dictVersionvSphere, mainWindowList, outFilePath, v)
            else:
                defaultConvertAll(dictVersionvSphere, mainWindowList, outFilePath)
            print("exported!")
        emailList = [outFilePath]
        emailDoc(emailList, v['emailSender'], v['emailRecipient'], 'See Final CSV')

    if b == "saveCSV":
        try:
            if len(str(solutionizerList)) > 0:
                solFilePath = 'output/csv/solutions/solutionizerList_{}'.format(str(uuid4())) + '.csv'
                convertCSV(solutionizerList, solFilePath)
        except:
            print("Didn't write solutionizer")
        try:
            if len(str(filteredList)) > 0:
                filFilePath = 'output/csv/solutions/filteredList_{}'.format(str(uuid4())) + '.csv'
                convertCSV(filteredList, filFilePath)
        except:
            print("Didn't write filtered tab")
        try:
            if len(str(results)) > 0:
                resFilePath = 'output/csv/solutions/suggestionsList_{}'.format(str(uuid4())) + '.csv'
                convertDifCSV(results, resFilePath)
        except:
            print("Didn't write results")

        loggy("Wrote Solutions to CSV", "INFO")
        mainWindow['info'].update("Generated CSV's", text_color="lightgreen")
    # print('wrote CSVs')

    if b == "emailCSVs":
        print("Pressed Email CSV's from Solutionizer")
        try:
            if len(str(solFilePath)) > 0:
                print('all good')
        except NameError:
            try:
                if len(str(solutionizerList)) > 0:
                    solFilePath = 'output/csv/solutions/solutionizerList_{}'.format(str(uuid4())) + '.csv'
                    convertCSV(solutionizerList, solFilePath)
            except:
                print("Didn't write solutionizer")
            try:
                if len(str(filteredList)) > 0:
                    filFilePath = 'output/csv/solutions/filteredList_{}'.format(str(uuid4())) + '.csv'
                    convertCSV(filteredList, filFilePath)
            except:
                print("Didn't write filtered tab")
            try:
                if len(str(results)) > 0:
                    resFilePath = 'output/csv/solutions/suggestionsList_{}'.format(str(uuid4())) + '.csv'
                    convertDifCSV(results, resFilePath)
            except:
                print("Didn't write results")
        # try:
        files = []

        try:
            files.append(filFilePath)
        except:
            print("Didn't email filtered tab")
        try:
            files.append(solFilePath)
        except:
            print("Didn't email solutionizer")
        try:
            files.append(resFilePath)
        except:
            print("Didn't email suggestions")

        if len(files) > 0:
            emailDoc(files, v['emailSender'], v['emailRecipient'], 'See Solutionizer Window CSV(s)')
            mainWindow['info'].update("Emailed CSV's", text_color="lightgreen")
        else:
            mainWindow['info'].update("There is Nothing to Email", text_color="#ffb399")
    # solutionFilterList = ["Registry setting","Registry key","Policy setting","Reconfigure","Update","Upgrade","Patch","Patches","KB","Recommended Settings","Enable","Disable"]
    if b == "Send to VSphere":
        print("input received")
        adList = getIPList(mainWindowList)
        mainWindow['vSphereML'].update('')
        mainWindow.Element('vSphereTab').Select()
        for ip in adList:
            try:
                for item in outputVsphere:
                    if item.get('IP Address') == str(ip):
                        mainWindow['vSphereML'].update(
                            '{IP Address}:{name}:{host_name}:{guest_os}:{power_state}'.format(**item), append=True)
                        mainWindow['vSphereML'].update(':notes: |' + item.get('notes') + "|", append=True)
                        mainWindow['vSphereML'].update(':reason: |' + item.get('reason') + "|", append=True)
                        mainWindow['vSphereML'].update(":" + str(item.get("quarantine_impact")), append=True)
                        mainWindow['vSphereML'].update(":" + str(item.get("customUUID")) + "\n", append=True)
                    else:
                        print("couldnt locate: " + str(item))
            except KeyError:
                print("couldnt locate: " + str(ip))
    if b == "IP Address ":
        vSphereList.clear()
        for item in outputVsphere:
            if item.get('IP Address') == str(v['vQuery']):
                mainWindow['vSphereML'].update(
                    '{IP Address}:{name}:{host_name}:{guest_os}:{power_state}'.format(**item), append=True)
                mainWindow['vSphereML'].update(':notes: |' + item.get('notes') + "|", append=True)
                mainWindow['vSphereML'].update(':reason: |' + item.get('reason') + "|", append=True)
                mainWindow['vSphereML'].update(':quarantine_impact: |' + item.get('quarantine_impact') + "|",
                                               append=True)
                mainWindow['vSphereML'].update(":" + str(item.get("customUUID")) + "\n", append=True)
                vSphereList.append(item)
        uuids = getUUID(v['vSphereML'])
        for entry in uuids:
            for item in outputVsphere:
                if item.get('customUUID') == str(entry):
                    vSphereList.append(item)
                    break

        # vSphereList.append(item)
    # [Sg.Text("VM's: 0, Online: 0, Offline: 0", key="vSphereCounters")
    # numVMsPoweredOn = 0

    # for item in outputVsphere:
    # 	numPoweredOn += 1
    # numVMs = numVMsPoweredOn + vSphereVMsPoweredOff
    # print("total" + str(numVMs))
    # print("off" + str(vSphereVMsPoweredOff))
    # print("on" + str(numVMsPoweredOn))

    if b == "Save Data for Export":
        mainWindow['info'].update("Saved/Merged Data for Export", text_color="lightgreen")
        saveFields(v['resultML'])
    if b == "Save Data for Export ":
        mainWindow['info'].update("Saved/Merged Data for Export", text_color="lightgreen")
        saveFieldsvSphere(v['vSphereML'])

    if b == "parserApplyBulkACAS":
        if v["ACASExempt"] != "Do Not Change":
            if v["ACASExempt"] == "Blank":
                saveExemptAll(str(v['parserML']), str(" "), "configs/vulnIdentity.json")
            saveExemptAll(str(v['parserML']), str(v['ACASExempt']), "configs/vulnIdentity.json")
        if v['ACASReason'] != "":
            saveReasonsAll(str(v['parserML']), str(v['ACASReason']), "configs/vulnIdentity.json")
        if v['ACASNotes'] != "":
            saveNotesAll(str(v['parserML']), str(v['ACASNotes']), "configs/vulnIdentity.json")
        print("input received")
        mainWindowList = updateList(mainWindowList)
        ids = getUUID(v['parserML'])
        mainWindow['parserML'].update('', append=False)
        for uid in ids:
            for entry in mainWindowList:
                if uid == entry.get('customUUID'):
                    sev = entry.get('severity').get('name')
                    mainWindow['parserML'].update('{ip}:{pluginID}:{pluginName}'.format(**entry) + ":" + sev,
                                                  append=True)
                    mainWindow['parserML'].update(':notes: |' + entry.get('notes') + "|", append=True)
                    mainWindow['parserML'].update(':reason: |' + entry.get('reason') + "|", append=True)
                    mainWindow['parserML'].update(':{exempt}:{customUUID}'.format(**entry) + '\n', append=True)

    if b == "parserApplyBulkVM":
        if v["VMImpact"] != "Do Not Change":
            if v["VMImpact"] == "Blank":
                saveImpactAll(str(v['parserML2']), str(" "), "configs/vmIdentity.json")
            saveImpactAll(str(v['parserML2']), str(v['VMImpact']), "configs/vmIdentity.json")
        if v['VMReason'] != "":
            saveReasonsAll(str(v['parserML2']), str(v['VMReason']), "configs/vmIdentity.json")
        if v['VMNotes'] != "":
            saveNotesAll(str(v['parserML2']), str(v['VMNotes']), "configs/vmIdentity.json")
        outputVsphere = updateVMList(outputVsphere)
        dictVersionvSphere = updateVMDict(dictVersionvSphere)
        ids = getUUID(v['parserML2'])
        mainWindow['parserML2'].update('', append=False)
        for uid in ids:
            for item in outputVsphere:
                if uid == item.get('customUUID'):
                    mainWindow['parserML2'].update(
                        '{IP Address}:{name}:{host_name}:{guest_os}:{power_state}'.format(**item), append=True)
                    mainWindow['parserML2'].update(':notes: |' + item.get('notes') + "|", append=True)
                    mainWindow['parserML2'].update(':reason: |' + item.get('reason') + "|", append=True)
                    mainWindow['parserML2'].update(':quarantine_impact: |' + item.get('quarantine_impact') + "|",
                                                   append=True)
                    mainWindow['parserML2'].update(":" + str(item.get("customUUID")) + "\n", append=True)
        # 			mainWindow['vSphereML'].update('{IP Address}:{name}:{host_name}:{guest_os}:{power_state}'.format(**item), append=True)
        # mainWindow['vSphereML'].update(':notes: |' + item.get('notes') + "|", append=True)
        # mainWindow['vSphereML'].update(':reason: |' + item.get('reason') + "|", append=True)
        # mainWindow['vSphereML'].update(':quarantine_impact: |' + item.get('quarantine_impact') + "|", append=True)
        # mainWindow['vSphereML'].update(":" + str(item.get("customUUID")) + "\n", append=True)
    if b == "Apply ACAS Manual Changes":
        print('input recieved')
        saveFields(v['parserML'])
    if b == "Apply vSphere Manual Changes":
        print("input recieved")
        saveFieldsvSphere(v['parserML2'])

    if b == "clearItems2":
        searchedList = clearvSphereSearchItems(str(v['searchWords2']), vSphereList)
        mainWindow['vSphereML'].update("", append=False)
        for item in searchedList:
            mainWindow['vSphereML'].update('{IP Address}:{name}:{host_name}:{guest_os}:{power_state}'.format(**item),
                                           append=True)
            mainWindow['vSphereML'].update(':notes: |' + item.get('notes') + "|", append=True)
            mainWindow['vSphereML'].update(':reason: |' + item.get('reason') + "|", append=True)
            mainWindow['vSphereML'].update(':quarantine_impact: |' + item.get('quarantine_impact') + "|", append=True)
            mainWindow['vSphereML'].update(":" + str(item.get("customUUID")) + "\n", append=True)

    if b == "revert2":
        try:
            if len(vSphereList) > 0:
                mainWindow['vSphereML'].update('')
                for item in vSphereList:
                    mainWindow['vSphereML'].update(
                        '{IP Address}:{name}:{host_name}:{guest_os}:{power_state}'.format(**item), append=True)
                    mainWindow['vSphereML'].update(':notes: |' + item.get('notes') + "|", append=True)
                    mainWindow['vSphereML'].update(':reason: |' + item.get('reason') + "|", append=True)
                    mainWindow['vSphereML'].update(':quarantine_impact: |' + item.get('quarantine_impact') + "|",
                                                   append=True)
                    mainWindow['vSphereML'].update(":" + str(item.get("customUUID")) + "\n", append=True)
        except NameError:
            Sg.PopupOK('Nothing to revert to')

    if b == "search2":

        thisSearch = v['searchWords2']
        if v['searchWords2'] == "":
            continue
        if saveSearch2:
            with open("configs/search.cache", 'r+') as searchCache:
                searchCache.write("\n{}".format(v['searchWords2']))
                # x = searchCache.read()
                searches = []
                for line in searchCache:
                    searches.append("{}".format(line.strip()))
                # mainWindow['searchWords'].Update(values=searches)
        searchCount = 0
        if sendParser2:
            parser = mainWindow['parserML2']
            parsedData = []
        searching = True
        mlContent = v['vSphereML']
        mlSearch = v['searchWords2']

        if not sendParser2:
            # mainWindow['searchWords'].Update(values=searches)
            for fullLine in mlContent.splitlines():
                for line in fullLine.split():
                    if str(mlSearch.lower()) in str(line.lower()) and searching:
                        searchCount = searchCount + 1
                        # mainWindow['searchCount'].update("#:{}".format(searchCount))
                        searching = False
                        if sendParser:
                            # parsedData.append(fullLine)
                            searchAgain = Sg.PopupYesNo(fullLine)
                            if searchAgain == "Yes":
                                # parser.update("{}\n".format(parsedData), append=True)
                                searching = True
                            else:
                                continue
                        else:
                            searchAgain = Sg.PopupYesNo(fullLine)
                            if searchAgain == "Yes":
                                searching = True
                            else:
                                continue
        else:
            # mainWindow['searchWords'].Update(values=searches)
            queri = v['vQuery']
            sw = v['searchWords2']
            # mainWindow['tabGroup'].add_tab(Sg.Tab(f'{sw} {index}', tab(index), key=f'{queri} {index}'))
            generatedTabs = True
            for fullLine in mlContent.splitlines():
                # for line in fullLine.split():
                if str(mlSearch.lower()) in str(fullLine.lower()) and searching:
                    searchCount = searchCount + 1
                    # mainWindow['searchCount'].update("#:{}".format(searchCount))

                    parsedData.append(fullLine)
                    pDataSet = [*set(parsedData)]
                    # searchAgain = Sg.PopupYesNo(fullLine)
                    # for result in pDataSet:
                    # print(v['autoParserTab'])
                    if v['autoParserTab2']:
                        print("auto parser is on... maybe not tho")

                        if index is 99 and f'{queri} {index}' in v:
                            print("Existing New Tab Found...")
                            newIndex = 0
                            while newIndex is not 99 and newIndex not in v:
                                queri = v['vQuery']
                                mainWindow['tabGroup'].add_tab(
                                    Sg.Tab(f'{sw} {newIndex}', tab(newIndex), key=f'{queri} {newIndex}'))
                                print(v['tabGroup'])
                                # mainWindow[f'{queri} {index}'].update("{}".format(v[f'{queri} {index}']))
                                mainWindow[f'parserML2{newIndex}'].update("{}\n".format(result), append=True)
                                mainWindow.Element(f'{queri} {newIndex}').Select()
                                indexList.append(newIndex)
                                # index+=1
                                generatedTabs = True
                                newIndex = newIndex + 1

                        if index is not 99:
                            # queri = v['query']
                            if index not in indexList:
                                # indexList.append(index)
                                # mainWindow['tabGroup'].add_tab(Sg.Tab(f'{queri} {index}', tab(index), key=f'{queri} {index}'))
                                print(v['tabGroup'])
                                generatedTabs = True
                                # mainWindow[f'{queri} {index}'].update("{}".format(v[f'{queri} {index}']))
                                mainWindow[f'parserML2{index}'].update("{}\n".format(result), append=True)
                                mainWindow.Element(f'{queri} {index}').Select()
                                Tabs = True

                        else:
                            loggy(
                                "Tab Index Exceeded beyond 99... Remove Check for Generating New Tabs\n or Remove Tabs",
                                "WARNING")
                            Sg.Popup("Tab Index Exceeded...\nRemove Check for Generating New Tabs")
                            continue

                    else:
                        # print("adding value to ML")
                        parser.update("{}\n".format(fullLine), append=True)
                        mainWindow.Element('parserTab').Select()
                continue
            indexList.append(index)
            index += 1

        mainWindow['searchWords2'].Update(values=searches)
        mainWindow['searchWords2'].Update(thisSearch)

    # print(v['tabGroup']) # for debugging main tab group
    try:
        if b.__contains__('removeTab'):
            # print('removeTab{}'.format(randrange(0, 6)))
            print("Removing Tab...")
            # print(v['tabGroup'])
            currentTab = v['tabGroup']
            # print(currentTab)
            mainWindow[currentTab].update(visible=False, disabled=True)
        # index = index - 1
        # indexList.remove()
    except:
        # this gets around the error caused when closing tool (__contains__ error parsed in loop while closing)
        pass

    if b == "savevSphere":
        outFilePath = 'output/csv/solutions/vSphere_{}'.format(str(uuid4())) + '.csv'
        convertvSphereCSV(vSphereList, outFilePath)

    if b == 'emailMainWindow2':
        emailList = [outFilePath]
        emailDoc(emailList, v['emailSender'], v['emailRecipient'], 'See vSphere Window CSV')
        loggy("Emailed CSV vSphere", "INFO")

    if b == "Send to ACAS":
        mainWindow.Element('mainTab').Select()
        allGood = functionalityCheck("IP Address")
        if allGood == 1:
            try:
                Vips = []
                for item in vSphereList:
                    Vips.append(item.get("IP Address"))

                print(str(Vips))

                if v['anyV']:
                    sev = "1,2,3,4"
                if v['lowV']:  # Severity from check boxes:
                    sev = 1
                if v['medV']:
                    sev = 2
                if v['highV']:
                    sev = 3
                if v['critV']:
                    sev = 4

                if v['csvForm']:
                    vulns = getVulnsList(sc, ip, sev)
                    print(vulns)
                    autoClear()
                    csvList = []
                    for entry in vulns:
                        csvList.append(
                            '\"{ip}\" \"{pluginID}\" \"{pluginName}\" \"{severity}\" \"{notes}\" \"{reason}\" \"{customUUID}\"'.format(
                                **entry) + "\n")

                    print(csvList)
                    mainWindow['csvTable'].update(values=csvList)
                    mainWindow.Element('csvTab').Select()
                    continue

                mainWindowList = []
                for ip in Vips:
                    vulns = getVulnsList(sc, ip, sev)
                    for item in vulns:
                        mainWindowList.append(item)
                print("Obtained Vulns")
                autoClear()
                for entry in mainWindowList:

                    sev = entry.get('severity').get('name')
                    # mainWindow['resultML'].update('{ip}:{pluginID}:{pluginName}'.format(**entry) + ":", append=True)
                    if sev == "Critical":
                        mainWindow['resultML'].update('{ip}'.format(**entry) + ":", append=True)
                        mainWindow['resultML'].update('{pluginID}:'.format(**entry) + ":",
                                                      text_color_for_value="#cc4668", append=True)
                        mainWindow['resultML'].update('{pluginName}'.format(**entry) + ":", append=True)
                        mainWindow['resultML'].update("{}".format(sev), append=True)
                    if sev == "High":
                        mainWindow['resultML'].update('{ip}'.format(**entry) + ":", append=True)
                        mainWindow['resultML'].update('{pluginID}:'.format(**entry) + ":",
                                                      text_color_for_value="#ffb399", append=True)
                        mainWindow['resultML'].update('{pluginName}'.format(**entry) + ":", append=True)
                        mainWindow['resultML'].update("{}".format(sev), append=True)
                    elif sev == "Medium":
                        mainWindow['resultML'].update('{ip}'.format(**entry) + ":", append=True)
                        mainWindow['resultML'].update('{pluginID}:'.format(**entry) + ":",
                                                      text_color_for_value="#f9eca5", append=True)
                        mainWindow['resultML'].update('{pluginName}'.format(**entry) + ":", append=True)
                        mainWindow['resultML'].update("{}".format(sev), append=True)
                    elif sev == "Low":
                        mainWindow['resultML'].update('{ip}'.format(**entry) + ":", append=True)
                        mainWindow['resultML'].update('{pluginID}:'.format(**entry) + ":",
                                                      text_color_for_value="#eef0f0", append=True)
                        mainWindow['resultML'].update('{pluginName}'.format(**entry) + ":", append=True)
                        mainWindow['resultML'].update("{}".format(sev), append=True)
                    elif sev == "Info":
                        mainWindow['resultML'].update('{ip}'.format(**entry) + ":", append=True)
                        mainWindow['resultML'].update('{pluginID}:'.format(**entry) + ":",
                                                      text_color_for_value="#95a5a6", append=True)
                        mainWindow['resultML'].update('{pluginName}'.format(**entry) + ":", append=True)
                        mainWindow['resultML'].update("{}".format(sev), append=True)

                    # #778484
                    mainWindow['resultML'].update(':notes: |' + entry.get('notes') + "|", append=True)
                    mainWindow['resultML'].update(':reason: |' + entry.get('reason') + "|", append=True)
                    mainWindow['resultML'].update(':{exempt}:'.format(**entry), append=True)
                    mainWindow['resultML'].update('{customUUID}'.format(**entry) + '\n', text_color_for_value="#778484",
                                                  append=True)
                # returns: <PySimpleGUI.PySimpleGUI.Multiline object at 0x000001FE2CB093F0>

                quicML = mainWindow['resultML'].get()
                ipPattern = re.compile(
                    r'^(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
                ipList = []
                for line in quicML.splitlines():
                    ipList.append(ipPattern.search(quicML))

                lows = quicML.count("Low")
                meds = quicML.count("Medium")
                highs = quicML.count("High")
                crits = quicML.count("Critical")
                exempts = quicML.count("True")
                # print(lows)
                # crits = v['resultML'].count("Critical")

                # print(ipList)
                strippedDupes = list(set(ipList))
                noIPDupes = len(strippedDupes)
                # print(strippedDupes)

                # PLUGINS:

                pluginList = []
                for line in quicML.splitlines():
                    y = line.split(":")
                    z = y[1].split(" ")
                    # pluginList.append(z)
                    # print(z[0])
                    pluginList.append(z[0])
                totalPlugins = len(pluginList)
                noDupes = list(set(pluginList))
                totalUniquePlugins = len(noDupes)

                mainWindow['analyzeText'].update(
                    "IP's: {}, Unique IP's: {}, Plugins: {}, Unique Plugins: {}, Lows: {}, Meds: {}, Highs: {}, Crits: {}, Exempts: {}".format(
                        len(ipList), noIPDupes, totalPlugins, totalUniquePlugins, lows, meds, highs, crits, exempts))


            except UnboundLocalError:
                loggy("Bad Query to ACAS", "ERROR")
                mainWindow['info'].update("Bad Query to ACAS", text_color="#ffb399")
        elif allGood != 1:
            Sg.PopupOK(allGood)
        else:
            loggy("ACAS Error", "ERROR")
            mainWindow['info'].update("Error With ACAS", text_color="#ffb399")
    if v == Sg.WINDOW_CLOSED:
        break


