# VirusTotalAPI
This is my Virus Total API tool that scan many files from pcap or specific file and send it to Virus Total DB.  

VT.py - is a simple tool, that send hash strings to Virus Total DB. 

# Information. 
This Script made to help you investigate malicious traffic or specific file that maybe contain malware. 
This script can work in 2 mods. 
One mode for quick scan (sending one hash to Virus Total DB), and second mode call GUI that getting pcap file and extract all files from him, hash them and send the result to Virus Total. 
After the result back, the script will show you report with all relevant information. 
You will be able to save the report as txt file or csv. 

# Dependencies. 
- Linux OS - This script work only on linux operation system. 
- FOREMOST need to be install - This script use FOREMOST the extarct the file from the pcap. 
- Python 2.7.X need to be install - This script base on python version 2.7.X 

# Script Fllow:  
## GUI Mode: ($ VT.py) 
- 1) Get pcap file path from user. 
- 2) Check if the file exist. 
- 3) For every pcap, the script take the first word on the last reposetory and named the pcap based on that word. 
    exampel: 
    the file '/tmp/pcaps/sespishes_pcap/pcap_name.pcap' will get the name 'pcap_name'.	  
- 4) Create output folder that contain all files that in the pcap.(OUTPUT_pcap_name). 
- 5) Using the program FOREMOST to extract all files from the pcap, and save them to the output folder that created. 
- 6) Asking the user with witch hash algorithm he like to hash the files. 
    The user can choce between all hash types that Virus Total support (sha1, sha224, sha256, sha512, md5 or use all). 
- 7) Greb all files that extract from the pcap to files list. 
- 8) Go one by one on the files list and hash them by the algorithm that user chosed. 
- 9) Greb the API-KEY that the user save in the 'API-KEY' file. 
-10) Send one by one all hashs to Virus Total DB. 
-11) Show progres. 
-12) Ask the user if he like to print out the result. 
-13) Ask the user if he like to save the result. 
-14) Ask the user if he like to save the reult as csv. 
-15) Close the script. 

## Quick Mode: ($ VT.py -f <full path> -a <algorithm type>) 
- 1) Get the algorithm type user like to use from args -a. 
- 2) Check if the file exist. 
- 3) Get the file path user like to use from args -f. 
- 4) Hash the file. 
- 5) Greb the API-KEY that the user save in the 'API-KEY' file. 
- 6) Send the hash to Virus Total DB. 
- 7) Show progres. 
- 8) Ask the user if he like to print out the result. 
- 9) Ask the user if he like to save the result. 
-10) Ask the user if he like to save the reult as csv. 
-11) Close the script. 

#License: #Do whatever you want with it ;)

#Some examples:

-This is example for using GUI mode with pcap that contain PoisonIvy malware.

<pre>

$ ./VT.py 

         ____   ____  _________ 
        |_  _| |_  _||  _   _  | 
          \ \   / /  |_/ | | \_| 
           \ \ / /       | | 
            \ ' /       _| |_ 
             \_/       |_____| 

              Version 1.0 
  For improvements, bugs or just to chat: 
         nir.vizel2312@gmail.com 
          Created by Nir Vizel. 

You can use quick mode that get one File, one type of hash algorithm and send it to VitusTotal. 
For example, please exit (Ctrl + c) and run script with "-h" or "--help" (VT.py -h). 


        ############################## 
        #                            # 
        #    Welcome to GUI mode     # 
        #  Please enter to continue  # 
        #                            # 
        ############################## 


    Enter your PCAP full path [/bla/bla/name.pcap]:/home/nvizel/Downloads/case.pcap 
Foremost version 1.5.7 by Jesse Kornblum, Kris Kendall, and Nick Mikus 
Audit File 

Foremost started at Sat Jul 25 22:34:26 2015 
Invocation: foremost all /home/nvizel/Downloads/case.pcap -o OUTPUT_case -v 
Output directory: /home/nvizel/Desktop/final_Project/OUTPUT_case 
Configuration file: /etc/foremost.conf 
Processing: /home/nvizel/Downloads/case.pcap 
|------------------------------------------------------------------ 
File: /home/nvizel/Downloads/case.pcap 
Start: Sat Jul 25 22:34:26 2015 
Length: 1 MB (1180238 bytes) 
 
Num	 Name (bs=512)	       Size	 File Offset	 Comment 

0:	00002134.rar 	      50 KB 	    1092733 	 Password Protected:Encrypted Headers! 
1:	00000002.exe 	       8 KB 	       1116 	 01/06/2008 14:51:31 
*| 
Finish: Sat Jul 25 22:34:26 2015 

2 FILES EXTRACTED 
	 
rar:= 1 
exe:= 1 
------------------------------------------------------------------ 

Foremost finished at Sat Jul 25 22:34:26 2015 

Whitch type of SHA you like to use? 
[1] SHA 1. 
[2] SHA 224. 
[3] SHA 256. 
[4] SHA 512. 
[5] MD 5. 
[6] Use All. 

	Your choice :1 

### Sending HASH to Virus Total: [1/2] 
### File: OUTPUT_case/rar/00002134.rar 
### Type: sha1 
### Hash: 01fa0254a6eb54c143b5c3752fec8c0e9d077ef9 


### Sending HASH to Virus Total: [2/2] 
### File: OUTPUT_case/exe/00000002.exe 
### Type: sha1 
### Hash: 57bf36be641ceeb5f841b73200094414e3fc1113 


Do you like to print full report? 

[1] Yes. 
[2] No. 

	Your choice :1 



############################################# 

HERE ARE THE RESULT FOR YOUR SCAN 

############################################# 


############## SCAN SUMMERY ################## 

Scan summery for file: OUTPUT_case/rar/00002134.rar 
You use HASH types:    sha1 
Verbose messages:      The requested resource is not among the finished, queued or pending scans 
Scan ID:               None 
Response code:         0 
Anti Virus detection:  None/None 
Script think its:      [] 
You use HASH:          sha1:01fa0254a6eb54c143b5c3752fec8c0e9d077ef9 

### Company Result ### 


############## SCAN SUMMERY ################## 

Scan summery for file: OUTPUT_case/exe/00000002.exe 
You use HASH types:    sha1 
Verbose messages:      Scan finished, information embedded 
Scan ID:               62910366caf05902fb4d127872e2d22b7fb56aa8687dba9f30111e6f54d27939-1437009465 
Response code:         1 
Anti Virus detection:  49/55 
Script think its:      [['Generic', 'PoisonIvy', '78ABA64D']] 
You use HASH:          sha1:57bf36be641ceeb5f841b73200094414e3fc1113 

### Company Result ### 

1) Bkav  :  None 
2) MicroWorld-eScan  :  Generic.PoisonIvy.78ABA64D 
3) nProtect  :  Generic.PoisonIvy.78ABA64D 
4) CAT-QuickHeal  :  TrojanAPT.Poisonivy.D3 
5) McAfee  :  BackDoor-DKI.gen.a 
6) Malwarebytes  :  None 
7) VIPRE  :  Trojan.Win32.Generic!BT 
8) AegisLab  :  None 
9) TheHacker  :  Backdoor/Poison.aec 
10) Alibaba  :  None 
11) K7GW  :  Backdoor ( 00199f611 ) 
12) K7AntiVirus  :  Backdoor ( 00199f611 ) 
13) Arcabit  :  Generic.PoisonIvy.78ABA64D 
14) NANO-Antivirus  :  Trojan.Win32.Poison.dfwiyv 
15) Cyren  :  W32/Agent.G.gen!Eldorado 
16) Symantec  :  Trojan!gm 
17) ESET-NOD32  :  a variant of Win32/Poison 
18) TrendMicro-HouseCall  :  BKDR_POISON.DD 
19) Avast  :  Win32:Tiny-ADY [Trj] 
20) ClamAV  :  Trojan.Downloader-24568 
21) Kaspersky  :  Backdoor.Win32.Poison.aec 
22) BitDefender  :  Generic.PoisonIvy.78ABA64D 
23) Agnitum  :  Trojan.DL.CKSPost.Gen 
24) ViRobot  :  Trojan.Win32.S.Agent.8192.LTJ[h] 
25) ByteHero  :  None 
26) Rising  :  PE:Trojan.Win32.Generic.15F7D435!368563253 
27) Ad-Aware  :  Generic.PoisonIvy.78ABA64D 
28) Emsisoft  :  Generic.PoisonIvy.78ABA64D (B) 
29) Comodo  :  Backdoor.Win32.Poison.AHF 
30) F-Secure  :  Backdoor:W32/PoisonIvy.gen!A 
31) DrWeb  :  BackDoor.Poison.812 
32) Zillya  :  Backdoor.Poison.Win32.58757 
33) TrendMicro  :  BKDR_POISON.DD 
34) McAfee-GW-Edition  :  BackDoor-DKI.gen.a 
35) Sophos  :  Troj/Poison-AE 
36) F-Prot  :  W32/Agent.G.gen!Eldorado 
37) Jiangmin  :  Backdoor/Poison.bp 
38) Avira  :  TR/Crypt.XPACK.Gen 
39) Antiy-AVL  :  Trojan[Backdoor]/Win32.Poison 
40) Kingsoft  :  Win32.Hack.Poison.(kcloud) 
41) Microsoft  :  Backdoor:Win32/Poison.E 
42) SUPERAntiSpyware  :  Trojan.Agent/Gen-Backdoor 
43) GData  :  Generic.PoisonIvy.78ABA64D 
44) AhnLab-V3  :  Win-Trojan/Agent.8192.EL 
45) ALYac  :  Generic.PoisonIvy.78ABA64D 
46) AVware  :  Trojan.Win32.Generic!BT 
47) VBA32  :  BackDoor.Poison 
48) Panda  :  Bck/PoisonIvy.gen 
49) Zoner  :  None 
50) Tencent  :  Backdoor.Win32.Poison.b 
51) Ikarus  :  Virus.Win32.Poison.DE 
52) Fortinet  :  W32/BDoor.DSE!tr.bdr 
53) AVG  :  BackDoor.PoisonIvy.AD 
54) Baidu-International  :  Trojan.Win32.Poison.NAE 
55) Qihoo-360  :  HEUR/Malware.QVM20.Gen 

Do you like to save your report? 

[1] Yes. 
[2] No. 

	Your choice :1 


mkdir: cannot create directory ‘./RESULT’: File exists 

--- Saved to: ./RESULT/Scan_Resulte.2015-07-25_22:34:23.txt --- 

Do you like to save your report as CSV file? 

[1] Yes. 
[2] No. 

	Your choice :1 


mkdir: cannot create directory ‘./RESULT’: File exists 

--- Saved to: ./RESULT/Scan_Resulte_CSV.2015-07-25_22:34:23.csv --- 

[*] Script finish to run 

[*] Script run for:0:00:58.206565 

########## DONE ##########

</pre>

- This exampel is for quick scan for one file and one hash type.
<pre> 

$ ./VT.py -f OUTPUT_case/exe/00000002.exe -a md5 

         ____   ____  _________ 
        |_  _| |_  _||  _   _  | 
          \ \   / /  |_/ | | \_| 
           \ \ / /       | | 
            \ ' /       _| |_ 
             \_/       |_____| 

              Version 1.0 
  For improvements, bugs or just to chat: 
         nir.vizel2312@gmail.com 
          Created by Nir Vizel. 
 

        ############################## 
        #                            # 
        #    Welcome to quick mode   # 
        #  Please enter to continue  # 
        #                            # 
        ############################## 


 ### Sending HASH to Virus Total: [1/1] 
 ### File: OUTPUT_case/exe/00000002.exe 
 ### Type: md5 
 ### Hash: f51144a3162c0a699743cd834a839ca0 



############################################# 

HERE ARE THE RESULT FOR YOUR SCAN 

############################################# 


############## SCAN SUMMERY ################## 

Scan summery for file: OUTPUT_case/exe/00000002.exe 
You use HASH types:    md5 
Verbose messages:      Scan finished, information embedded 
Scan ID:               62910366caf05902fb4d127872e2d22b7fb56aa8687dba9f30111e6f54d27939-1437009465 
Response code:         1 
Anti Virus detection:  49/55 
Script think its:      [['Generic', 'PoisonIvy', '78ABA64D']] 
You use HASH:          md5:f51144a3162c0a699743cd834a839ca0 

 ### Company Result ### 
1) Bkav  :  None 
2) MicroWorld-eScan  :  Generic.PoisonIvy.78ABA64D 
3) nProtect  :  Generic.PoisonIvy.78ABA64D 
4) CAT-QuickHeal  :  TrojanAPT.Poisonivy.D3 
5) McAfee  :  BackDoor-DKI.gen.a 
6) Malwarebytes  :  None 
7) VIPRE  :  Trojan.Win32.Generic!BT 
8) AegisLab  :  None 
9) TheHacker  :  Backdoor/Poison.aec 
10) Alibaba  :  None 
11) K7GW  :  Backdoor ( 00199f611 ) 
12) K7AntiVirus  :  Backdoor ( 00199f611 ) 
13) Arcabit  :  Generic.PoisonIvy.78ABA64D 
14) NANO-Antivirus  :  Trojan.Win32.Poison.dfwiyv 
15) Cyren  :  W32/Agent.G.gen!Eldorado 
16) Symantec  :  Trojan!gm 
17) ESET-NOD32  :  a variant of Win32/Poison 
18) TrendMicro-HouseCall  :  BKDR_POISON.DD 
19) Avast  :  Win32:Tiny-ADY [Trj] 
20) ClamAV  :  Trojan.Downloader-24568 
21) Kaspersky  :  Backdoor.Win32.Poison.aec 
22) BitDefender  :  Generic.PoisonIvy.78ABA64D 
23) Agnitum  :  Trojan.DL.CKSPost.Gen 
24) ViRobot  :  Trojan.Win32.S.Agent.8192.LTJ[h] 
25) ByteHero  :  None 
26) Rising  :  PE:Trojan.Win32.Generic.15F7D435!368563253 
27) Ad-Aware  :  Generic.PoisonIvy.78ABA64D 
28) Emsisoft  :  Generic.PoisonIvy.78ABA64D (B) 
29) Comodo  :  Backdoor.Win32.Poison.AHF 
30) F-Secure  :  Backdoor:W32/PoisonIvy.gen!A 
31) DrWeb  :  BackDoor.Poison.812 
32) Zillya  :  Backdoor.Poison.Win32.58757 
33) TrendMicro  :  BKDR_POISON.DD 
34) McAfee-GW-Edition  :  BackDoor-DKI.gen.a 
35) Sophos  :  Troj/Poison-AE 
36) F-Prot  :  W32/Agent.G.gen!Eldorado 
37) Jiangmin  :  Backdoor/Poison.bp 
38) Avira  :  TR/Crypt.XPACK.Gen 
39) Antiy-AVL  :  Trojan[Backdoor]/Win32.Poison 
40) Kingsoft  :  Win32.Hack.Poison.(kcloud) 
41) Microsoft  :  Backdoor:Win32/Poison.E 
42) SUPERAntiSpyware  :  Trojan.Agent/Gen-Backdoor 
43) GData  :  Generic.PoisonIvy.78ABA64D 
44) AhnLab-V3  :  Win-Trojan/Agent.8192.EL 
45) ALYac  :  Generic.PoisonIvy.78ABA64D 
46) AVware  :  Trojan.Win32.Generic!BT 
47) VBA32  :  BackDoor.Poison 
48) Panda  :  Bck/PoisonIvy.gen 
49) Zoner  :  None 
50) Tencent  :  Backdoor.Win32.Poison.b 
51) Ikarus  :  Virus.Win32.Poison.DE 
52) Fortinet  :  W32/BDoor.DSE!tr.bdr 
53) AVG  :  BackDoor.PoisonIvy.AD 
54) Baidu-International  :  Trojan.Win32.Poison.NAE 
55) Qihoo-360  :  HEUR/Malware.QVM20.Gen 
mkdir: cannot create directory ‘./RESULT’: File exists 

--- Saved to: ./RESULT/Scan_Resulte.2015-07-25_22:43:55.txt --- 
mkdir: cannot create directory ‘./RESULT’: File exists 

--- Saved to: ./RESULT/Scan_Resulte_CSV.2015-07-25_22:43:55.csv --- 

[*] Script finish to run 

[*] Script run for:0:00:02.673763 

########## DONE ##########

</pre>
