import time
import requests
import json
from urllib.parse import urljoin, urldefrag, urlparse
from bs4 import BeautifulSoup

class SimpleCrawler:
    def __init__(self,base_url,max_pages=10,delay=1):
        self.base_url=base_url.rstrip("/")
        self.visited=set()
        self.max_pages=max_pages
        self.pages={}
        self.forms={}
        self.delay=delay
        self.queue=[self.base_url]
    def fetch(self, url):
        try:
            response=requests.get(url,timeout=10)
            response.raise_for_status()
            return response.text
        except Exception as e:
            print(f"Failed to fetch {url}: {e}")
            return None
    def extract_links(self,html,base_url):
        soup = BeautifulSoup(html,"html.parser")
        links = []
        for a in soup.find_all("a",href=True):
            link=urljoin(base_url, a["href"])
            link, _ =urldefrag(link)
            if(urlparse(link).netloc == urlparse(self.base_url).netloc):
                links.append(link.rstrip("/"))
        return links
    def extract_forms(self, html, page_url):
      soup = BeautifulSoup(html,"html.parser")
      forms=[]
      for i in soup.find_all("form"):
          inputs=[]
          for inp in i.find_all("input"):
              inputs.append({
                  "tag": "input",
                  "name": inp.get("name"),
                  "type": inp.get("type", "text"),
                  "placeholder": inp.get("placeholder"),
                  "value": inp.get("value")
              })
          for textarea in i.find_all("textarea"):
              inputs.append({
                  "tag": "textarea",
                  "name": textarea.get("name"),
                  "placeholder": textarea.get("placeholder"),
                  "value": textarea.text.strip()
              })
          for select in i.find_all("select"):
              options = []
              for option in select.find_all("option"):
                  options.append({
                      "value": option.get("value"),
                      "text": option.text.strip(),
                      "selected": option.has_attr("selected")
                  })
              inputs.append({
                  "tag": "select",
                  "name": select.get("name"),
                  "options": options
              })

          form_details = {
              "action": i.get("action"),
              "method": i.get("method", "get").lower(),
              "inputs": inputs
          }
          forms.append(form_details)
      return forms
    def crawl(self):
        while(self.queue and len(self.visited) < self.max_pages):
            url=self.queue.pop(0)
            if url in self.visited:
                continue
            print(f"Crawling: {url}")
            html=self.fetch(url)
            if not html:
                continue
            self.pages[url]=html
            page_forms=self.extract_forms(html,url)
            self.forms[url]=page_forms
            for link in self.extract_links(html,url):
                if (link not in self.visited and link not in self.queue):
                    self.queue.append(link)
            self.visited.add(url)
            time.sleep(self.delay)
        return {"pages": list(self.pages.keys()), "forms": self.forms}

if __name__ == "__main__":
    crawler = SimpleCrawler("https://quotes.toscrape.com/", max_pages=30
                            , delay=1)
    result = crawler.crawl()
    with open("crawler_output.json", "w") as f:
        json.dump(result, f, indent=4)

