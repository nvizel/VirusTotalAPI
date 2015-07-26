#!/usr/bin/python
import sys						# To use some system function.
import re						# To use regex when i look for the API-KEY.
import csv						# To save the result as csv
import json as simplejson		# To parse the respond from Virus Total (using json format).
import urllib, urllib2			# To send http request to Virus Total.
from datetime import datetime	# To get date and time.
from subprocess import call		# To call bash command.
from os import listdir			# To get dir command as list.
from os.path import isfile,join	# To know if path is file or not.
from os.path import isdir		# To know if path is dir or not.
import hashlib					# To run hash algorithms.
import time						# To count time.
from optparse import OptionParser	# To parse args.

# Getting the current time.
t1 = datetime.now()

# This function used to get the user API-KEY from file API-KEY.
def getAPI_KEY(fileLocation="./API-KEY"):
    myFile = open(fileLocation, "r")
    for line in myFile.readlines():
        pattern = r'API-KEY:(\w+)'
        api_key = re.findall(pattern, line)
    myFile.close()
    try:
        return api_key[0]
    except:
        print '''
    Error:  its look like you give invalid API-KEY or that you edited the file API-KEY incorrect.
            Please re-edit the file.

            If you need any help, please contact me on E-mail: nir.vizel2312@gmail.com
        '''
        sys.exit(-1)

# This function used to send the http request to https://www.virustotal.com/vtapi/v2/file/report.
def send_To_VT(sha, apikey):
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    parameters = {"resource": sha, "apikey": apikey}
    data = urllib.urlencode(parameters)
    req = urllib2.Request(url, data)
    response = urllib2.urlopen(req)
    return response

# This function used to create list of the companies and they results.
def compeny_resulte(myDici):
    compenyNum = 1
    fullRportList = []
    for compony in myDici.get("scans", {}).keys():
        Name1 = myDici.get("scans", {}).get(compony, {}).get("result")
        fullRportList.append(str(compenyNum) + ") " + str(compony) + "  :  " + str(Name1))
        compenyNum = compenyNum + 1
    if len(fullRportList) < 2:
        return ""
    else:
        return fullRportList

# This function used to guessing the most common name of the malicious file form the names that all companies let him.
def guessing(myDici):
    wordList = []
    Myguess = []
    for compony in myDici.get("scans", {}).keys():
        NameList = (myDici.get("scans", {}).get(compony, {}).get("result"))
        if NameList != None:
            pattern = '\w+'
            words = re.findall(pattern, str(NameList))
            wordList.append(words)
    numerOfoccurrences = 2
    for i in wordList:
        occurrences = wordList.count(i)
        while i in wordList:
            wordList.remove(i)
        if occurrences >= numerOfoccurrences:
            numerOfoccurrences = occurrences
            Myguess.append(i)
    return Myguess
'''    location = "./RESULT/Scan_Resulte." + tt1 + ".txt"
    myFile = open(location, "w")
    for line in fullreport:
        myFile.write(str(line) + "\n")
    myFile.close()
    print '--- Saved to: ' + location + ' ---'
'''

# This function used to get YES or NO user answer on script change questions.
def YesOrNo(question):
    YesNo = '0'
    while YesNo != '1' and '2':
        YesNo = raw_input(question + "\n[1] Yes.\n[2] No.\n\n\tYour choice :")
        if YesNo == '1':
            print '\n'
            return True
            break
        elif YesNo == '2':
            print '\n'
            return False
            break
        else:
            raw_input("""
        Illegal choice ! Please chocs 1 or 2.
        Enter to continue.""")
            continue

# This function used to chocs the hash algorithm to use.
def ChoiceSHA():
    question = '\nWhitch type of SHA you like to use?'
    A = '[1] SHA 1.'
    B = '[2] SHA 224.'
    C = '[3] SHA 256.'
    D = '[4] SHA 512.'
    E = '[5] MD 5.'
    F = '[6] Use All.'
    option = None
    while option != '1' and '2' and '3' and '4' and '5' and '6':
        option = raw_input(
            question + '\n' + A + '\n' + B + '\n' + C + '\n' + D + '\n' + E + '\n' + F + "\n\n\tYour choice :")
        if option == '1':
            return [hashlib.sha1()]
            break
        elif option == '2':
            return [hashlib.sha224()]
            break
        elif option == '3':
            return [hashlib.sha256()]
            break
        elif option == '4':
            return [hashlib.sha512()]
            break
        elif option == '5':
            return [hashlib.md5()]
        elif option == '6':
            return [hashlib.sha1(), hashlib.sha224(), hashlib.sha256(), hashlib.sha512(), hashlib.md5()]
            break
        else:
            print """
        Illegal choice ! Please chocs 1, 2, 3, 4, 5 or 6."""
            raw_input("""
        Enter to continue.""")
            continue

# This function used to create hash(list) on the files(list), its will return a dic {file:{algorithm:hash}}.
def CreateSHA(UserChoice, fileForSha):
    hashDic = {}
    hashDic_A = {}
    BLOCKSIZE = 65536
    for myfile in fileForSha:
        hashDic[myfile] = {}
        for hasher in UserChoice:
            MyHash = str(hasher).split(' ')[0].split('<')[1]
            hashDic_A[MyHash] = []
            with open(myfile, 'rb') as afile:
                buf = afile.read(BLOCKSIZE)
                while len(buf) > 0:
                    hasher.update(buf)
                    buf = afile.read(BLOCKSIZE)
            hashDic_A[MyHash].append(hasher.hexdigest())
            hashDic[myfile].update(hashDic_A)
    return hashDic

# This function used to return list of all files that Foremost extracted form the pcap file.
def getFileToSha(tempPATH):
    onlydirs = [f for f in listdir(tempPATH) if isdir(join(tempPATH, f))]
    AllFile = []
    for tempDir in onlydirs:
        onlyfiles = [f for f in listdir(tempPATH + '/' + tempDir) if isfile(join(tempPATH + '/' + tempDir, f))]
        for myfile in onlyfiles:
            AllFile.append(tempPATH + '/' + tempDir + '/' + myfile)
    return AllFile

# This function used to create the final report, using the dic format {file:{hash algorithm:{line title:line}}}
def report(final_report,GUI_staus):
    global myFileresult
    Line_1 = 'HERE ARE THE RESULT FOR YOUR SCAN'
    printhing = {}
    for myfile, myFileresult in final_report.iteritems():
        printhing[myfile] = {}
        for myhash, JSON_Dic in myFileresult.iteritems():
            printhing[myfile][myhash] = {}
            printhing[myfile][myhash]['Line_2_0'] = '\n############## SCAN SUMMERY ##################\n'
            printhing[myfile][myhash]['Line_2_1'] = 'Scan summery for file: ' + str(myfile)
            printhing[myfile][myhash]['Line_2_2'] = 'You use HASH types:    ' + str(myFileresult.keys()).replace('[','').replace(']','').replace("'",'')
            printhing[myfile][myhash]['line_2_3'] = "Verbose messages:      " + str(JSON_Dic.get("verbose_msg"))
            printhing[myfile][myhash]['line_2_4'] = "Scan ID:               " + str(JSON_Dic.get("scan_id"))
            printhing[myfile][myhash]['line_2_5'] = "Response code:         " + str(JSON_Dic.get("response_code"))
            printhing[myfile][myhash]['line_2_6'] = "Anti Virus detection:  " + str(JSON_Dic.get("positives")) + "/" + str(JSON_Dic.get("total"))
            printhing[myfile][myhash]['line_2_7'] = "Script think its:      " + str(guessing(JSON_Dic))
            printhing[myfile][myhash]['line_2_8'] = "You use HASH:          " + str(myhash) + ":" + str(JSON_Dic.get('resource'))
            printhing[myfile][myhash]['all_company'] = compeny_resulte(JSON_Dic)

# This part used to knowing if the user would want to see the report.
# If YES, its will print out.
    if GUI_staus == 0:
        YN = YesOrNo("\nDo you like to print full report?\n")
    else :
        YN = True
    if YN == True:
        print "\n#############################################\n"
        print Line_1
        print "\n#############################################\n"
        for scand_file in printhing.keys():
            for hashName in printhing[scand_file].keys():
                for lines in printhing[scand_file][hashName].keys():
                    if lines == 'all_company':
                        print "\n### Company Result ### \n"
                        for commpeny in printhing[scand_file][hashName][lines]:
                            print commpeny
                    else:
                        print printhing[scand_file][hashName][lines]

# This part used to knowing if the user would want to save the report.
    if GUI_staus == 0:
        YN = YesOrNo("\nDo you like to save your report?\n")
    else :
        YN = True
    if YN == True:
        LineToSave = []
        LineToSave.append("\n#############################################\n")
        LineToSave.append(Line_1)
        LineToSave.append("\n#############################################\n")
        for scand_file in printhing.keys():
            for hashName in printhing[scand_file].keys():
                for lines in printhing[scand_file][hashName].keys():
                    if lines == 'all_company':
                        LineToSave.append('\n### Company Result ###\n')
                        for commpeny in printhing[scand_file][hashName][lines]:
                            LineToSave.append(commpeny)
                    else:
                        LineToSave.append(printhing[scand_file][hashName][lines])
        resulteSave(LineToSave)

# This part used to knowing if the user would want to save the report as csv file.
    if GUI_staus == 0:
        YN = YesOrNo("\nDo you like to save your report as CSV file?\n")
    else :
        YN = True
    if YN == True:
        SaveToCSV(printhing)

# This function used to save the result report.
def resulteSave(fullreport):
    call(['mkdir', './RESULT'])
    tt1 = str(t1).split('.')[0].replace(' ', '_')
    location = "./RESULT/Scan_Resulte." + tt1 + ".txt"
    myFile = open(location, "w")
    for line in fullreport:
        myFile.write(str(line) + "\n")
    myFile.close()
    print '\n--- Saved to: ' + location + ' ---'

# This function used to save the result report as csv.
def SaveToCSV(fullResulteDic):
    call(['mkdir', './RESULT'])
    tt1 = str(t1).split('.')[0].replace(' ', '_')
    location = "./RESULT/Scan_Resulte_CSV." + tt1 + ".csv"
    with open(location, 'w') as csvfile:
        fieldnames = ['File_Name','Hash_Type','Value']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for FileName in fullResulteDic.keys():
            for hashType in fullResulteDic[FileName].keys():
                for LineTitel in fullResulteDic[FileName][hashType].keys():
                    writer.writerow({'File_Name':FileName,'Hash_Type':hashType,'Value':str(fullResulteDic[FileName][hashType][LineTitel])})

        csvfile.close()
        print '\n--- Saved to: ' + location + ' ---'

# This function used to check if the pcap file uar given is exist.
def CheckIfFileExist(location):
    """

    :rtype :
    """
    try:
        f = open(location)
    except IOError as e:
        print "\nI/O error({0}): {1}".format(e.errno, e.strerror) + '. File:\t' + location + "\n"
        sys.exit(e.errno)
    except:
        print "\nUnexpected error:", sys.exc_info()[0] + '\n'
        sys.exit(e.errno)
        raise

# This function used to count for 't' sec down and print it out.
# I am using it when script send more request then the API-KEY allow to.
def timer(t):
    t0 = time.time()
    now = t0
    while now - t0 < t:
        now = time.time()
        timestr = '\r%i' % (t - (now - t0))
        sys.stdout.write(timestr + ' sec to continue.')
        sys.stdout.flush()
        time.sleep(1)

# # This function used to print script banner.
def Banner():
    print"""
         ____   ____  _________
        |_  _| |_  _||  _   _  |
          \ \   / /  |_/ | | \_|
           \ \ / /       | |
            \ ' /       _| |_
             \_/       |_____|

              Version 1.0
  For improvements, bugs or just to chat:
         nir.vizel2312@gmail.com
          Created by Nir Vizel."""

# This is the MAIN function.
def main():
# This part used to set the args that can be used.
    parser = OptionParser("-f <full path> -a <algorithm type>")
    parser.add_option("-f", "--file", dest="FileToHash",
                      help="Use this full path FILE to hash", metavar="FILE")
    parser.add_option("-a", "--algorithm", dest="HashToUse",
                      help="Use sha1,sha224,sha256,sha512 or md5 ", metavar="ALGORITHM")
    (options, args) = parser.parse_args()
    Banner()
# This part used to know if user use args or not.
    if (options.FileToHash == None) and (options.HashToUse == None):
        print '''
You can use quick mode that get one File, one type of hash algorithm and send it to VitusTotal.
For example, please exit (Ctrl + c) and run script with "-h" or "--help" (VT.py -h).'''
        raw_input('''\n
        ##############################
        #                            #
        #    Welcome to GUI mode     #
        #  Please enter to continue  #
        #                            #
        ##############################\n''')
        GUI = 0
    elif (options.FileToHash == None) and (options.HashToUse != None):
        print '''
        You miss one argument.
        To Use Quick mode you most give tow

        '''+ str(parser.usage)
        sys.exit(-1)
    elif (options.FileToHash != None) and (options.HashToUse == None):
        print '''
        You miss one argument.
        To Use Quick mode you most give tow

        '''+ str(parser.usage)
        sys.exit(-1)
    else:
        CheckIfFileExist(str(options.FileToHash))
        if options.HashToUse not in ['sha1', 'sha224', 'sha256', 'sha512', 'md5']:
            print """
        Its look like you try to use unsupported hash algorithm.
        You can use only sha1, sha224, sha256, sha512 or md5 algorithm.
            """
            sys.exit(2)
        raw_input('''\n
        ##############################
        #                            #
        #    Welcome to quick mode   #
        #  Please enter to continue  #
        #                            #
        ##############################\n''')
        GUI = 1
# This part used decide if script continue to GUI mode or script mode.
    if GUI == 0:														# Start GUI mode.
        pcapFilePath = raw_input("""
    Enter your PCAP full path [/bla/bla/name.pcap]:""")					# Get pcap path from user input.
#        pcapFilePath = '/home/nvizel/Downloads/case.pcap'
        CheckIfFileExist(pcapFilePath)									# Checking if the pcap file exist.
        pcapName = str(pcapFilePath.split('/')[-1].split('.')[0])		# Get the pcap name.
        outputPath = 'OUTPUT_' + pcapName								# Create the output dir name for Foremost program.
        call(['foremost', 'all', pcapFilePath, '-o', outputPath, '-v'])	# Call subprocess that extract all file from the pcap to output dir.
        SHAtypeToUse = ChoiceSHA()										# Getting user hash algorithm he like to use.
        ListOfFileToSha = getFileToSha(outputPath)						# Get list of all file that foremost extract from the pcap.
    elif GUI == 1:														# Start quick mode.
        hashDic = {'md5': hashlib.md5(),								# Hash algorithm dic.
                   'sha1': hashlib.sha1(),
                   'sha224': hashlib.sha224(),
                   'sha256': hashlib.sha256(),
                   'sha512': hashlib.sha512()}
        SHAtypeToUse = [hashDic[options.HashToUse]]						# Get the hash type from args -a.
        CheckIfFileExist(options.FileToHash)							# Checking if file exist.
        ListOfFileToSha = [options.FileToHash]							# Get the file to hash from args -f.
    SHA_DIC = CreateSHA(SHAtypeToUse, ListOfFileToSha)					# Create hash dic {file:{algorithm:hash}}
    API_KEY = getAPI_KEY()												# Get the API-KEY from configuration file.
    DIC_A = {}															# Create the main empty dic, to update with result data.
    sendingCounter = 0													# Create parameter to count requests.
    for File, HASH_TYPE in SHA_DIC.iteritems():							# For every file in SHA_DIC.
        DIC_A.update({File: {}})										# Update DIC_A with key name as the file, and value is empty.
        for mytype, myShaLst in HASH_TYPE.iteritems():					# For every hash type in SHA_DIC[file_name]
            for hash in myShaLst:										# For every hash in SHA_DIC[file_name][hash_type]
                sendingCounter += 1										# Add 1 to request counter.
                                                                        # Print the sending progress.
                print '\n### Sending HASH to Virus Total: [%s/%d]' %(sendingCounter, len(SHA_DIC.keys()) * len(HASH_TYPE))
                print '### File: %s' % (File)							# Print the file that use for current scan.
                print '### Type: %s' % (mytype)							# Print the hash that use for cuttent scan.
                print '### Hash: %s\n' % (hash)							# Print the hash that use for current scan.
                respon = send_To_VT(hash, API_KEY)						# Send and save the respond to parameter 'respon'
                Jrespon = respon.read()									# Save the respond as readied data.
                try:													# Try to convert the readied respond data from json format to dic format.
                    response_dict = simplejson.loads(Jrespon)
                except:													# If the convert failed we assom that the respond is not valid.
                                                                        # We print error and start count for 60 second, after it we resend the last request.
                    print """##################################################################
                            \nOops!  That was  unvalid respond from Virus Total.
                            \nLook like you send more scans than your API-Key allow you (4/min).
                            \nScript will continue and resend it in 60 sec . . .
                            \n##################################################################"""
                    timer(60)
                    respon = send_To_VT(hash, API_KEY)
                    Jrespon = respon.read()
                    response_dict = simplejson.loads(Jrespon)
                DIC_A[File].update({mytype: response_dict})				# Add the respond to main dic DIC_A.
    report(DIC_A,GUI)														# Send the main dic to the report function.
    print '\n[*] Script finish to run'
    t2 = datetime.now()													# Get the current time after script done process data.
    t_total = t2 - t1													# Culcolet the time that tack to run the script.
    print '\n[*] Script run for:' + str(t_total)
    print '\n########## DONE ##########'

if __name__ == '__main__':
    main()
