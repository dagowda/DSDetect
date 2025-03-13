import requests
import sys,json,re
import time

def detect(hash):
   print(f"Hash/IP/URL: {hash}")
   url=f"https://www.virustotal.com/api/v3/widget/url"

   #print(url)

   query_p = {
       "query": hash
   }

   header={
       "accept": "application/json",
       "x-apikey":"" #please add your own free VirusTotal API key from https://www.virustotal.com/gui/my-apikey 
       }

   response=requests.get(url,headers=header,params=query_p)
   a=response.text

   final=json.loads(a)
   if final["data"]["detection_ratio"]["detections"]==0:
      print("[*]No Detections")
      exit()
   else:
      print("[*]A total of %s vendors have made detections." % final["data"]["detection_ratio"]["detections"])
   
   token_url=final["data"]["url"]
   #print("\n")
   headers = {
    "Host": "www.virustotal.com",
    "Sec-Ch-Ua": "\"Not:A-Brand\";v=\"99\", \"Chromium\";v=\"112\"",
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": "\"Windows\"",
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.138 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-User": "?1",
    "Sec-Fetch-Dest": "document",
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "en-US,en;q=0.9"
   }

   response = requests.get(token_url, headers=headers)
   
   a=response.content.decode('utf-8')
   
   patterns = {
    "Possible malware name": r'<span class="vt-utils-ellipsis vt-utils-engine-verdict vt-utils-bold">Elastic:\s*<a[^>]*data-pivot-val=\'elastic:"([^"]+)"\'',
    "MD5": r'MD5</div>\s*<div class="vt-table__col vt-table__col--breakable">\s*<a[^>]*data-pivot-val="([^"]+)"',
    "SHA-1": r'SHA-1</div>\s*<div class="vt-table__col vt-table__col--breakable">\s*<a[^>]*data-pivot-val="([^"]+)"',
    "SHA-256": r'SHA-256</div>\s*<div class="vt-table__col vt-table__col--breakable">\s*<a[^>]*data-pivot-val="([^"]+)"',
    "First submission to VT": r'First submission to VT</div>\s*<div class="vt-table__col">\s*([^<]+)\s*</div>',
}


    # Extract values using regex
   extracted_data = {}
   for key, pattern in patterns.items():
       match = re.search(pattern, a)
       if match:
           extracted_data[key] = match.group(1)
       else:
            print(f"[!] Could not find {key}")

    # Print extracted values
   for key, value in extracted_data.items():
       print(f"[*]{key}: {value}")
   print("\n")
   time.sleep(4.5)
      

if __name__== "__main__":
   banner=r"""
   
                                                                                             
                                                                                          
    ,---,      .--.--.       ,---,                  ___                           ___     
  .'  .' `\   /  /    '.   .'  .' `\              ,--.'|_                       ,--.'|_   
,---.'     \ |  :  /`. / ,---.'     \             |  | :,'                      |  | :,'  
|   |  .`\  |;  |  |--`  |   |  .`\  |            :  : ' :                      :  : ' :  
:   : |  '  ||  :  ;_    :   : |  '  |   ,---.  .;__,'  /     ,---.     ,---. .;__,'  /   
|   ' '  ;  : \  \    `. |   ' '  ;  :  /     \ |  |   |     /     \   /     \|  |   |    
'   | ;  .  |  `----.   \'   | ;  .  | /    /  |:__,'| :    /    /  | /    / ':__,'| :    
|   | :  |  '  __ \  \  ||   | :  |  '.    ' / |  '  : |__ .    ' / |.    ' /   '  : |__  
'   : | /  ;  /  /`--'  /'   : | /  ; '   ;   /|  |  | '.'|'   ;   /|'   ; :__  |  | '.'| 
|   | '` ,/  '--'.     / |   | '` ,/  '   |  / |  ;  :    ;'   |  / |'   | '.'| ;  :    ; 
;   :  .'      `--'---'  ;   :  .'    |   :    |  |  ,   / |   :    ||   :    : |  ,   /  
|   ,.'                  |   ,.'       \   \  /    ---`-'   \   \  /  \   \  /   ---`-'   
'---'                    '---'          `----'               `----'    `----'             

VirusTotal Detection Viewer by dagowda

"""
   print(banner)

   if len(sys.argv)!=2:
      print("Usage: python3 DSDetect.py <hash file>")
   else:
       try:
          with open(sys.argv[1], "r") as f:
              content1=f.read().split()
       except Exception as e:
          print(f"error opening file: {e}")
       for hash in content1:
          detect(hash)
