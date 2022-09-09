import requests, argparse, json
import virustotal_python
from pprint import pprint
from base64 import urlsafe_b64encode
from pysafebrowsing import SafeBrowsing

def nslookup(url):
   main_url = "https://dns-lookup5.p.rapidapi.com/simple"
   querystring = {"domain":url,"recordType":"NS"}
   headers = {
      "X-RapidAPI-Key": "<Enter RapidAPI key>",
      "X-RapidAPI-Host": "dns-lookup5.p.rapidapi.com"
   }
   response = requests.request("GET", main_url, headers=headers, params=querystring)
   print("nslookup results:")
   print(response.json())
   print("----------------------------------------------------------------------------------------------------------")


def safe_browsing(url):
   key='<Enter Google SafeBrowsing Key>'
   s = SafeBrowsing(key)
   r = s.lookup_url(url)
   print("Google Safe SafeBrowsing Results:")
   print(r)
   print("----------------------------------------------------------------------------------------------------------")

def virustotal_search(url):
   with virustotal_python.Virustotal("<Enter VirusTotal Key>") as vtotal:
      try:
         resp = vtotal.request("urls", data={"url": url}, method="POST")
         # Safe encode URL in base64 format
         # https://developers.virustotal.com/reference/url
         url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
         report = vtotal.request(f"urls/{url_id}")
         print("VirusTotal Results:")
         pprint(report.object_type)
         pprint(report.data)
         print("----------------------------------------------------------------------------------------------------------")
      except virustotal_python.VirustotalError as err:
         print(f"Failed to send URL: {url} for analysis to VirusTotal and get the report: {err}")
         print("----------------------------------------------------------------------------------------------------------")

if __name__ == "__main__":
   parser = argparse.ArgumentParser()
   parser = argparse.ArgumentParser(description="Check the maliciousness of a URL")
   parser.add_argument("--url", help="URL to be investigated")
   args = parser.parse_args()

   if args.url:
      url_search = args.url
      print("----------------------------------RESULTS----------------------------------------------------------")
      nslookup(url_search)
      safe_browsing(url_search)   
      virustotal_search(url_search)       