# importing required packages for this section
from urllib.parse import urlparse,urlencode
import ipaddress
import re
from bs4 import BeautifulSoup
import whois
import urllib
import urllib.request
from datetime import datetime
import requests
#importing packages
from sklearn.metrics import accuracy_score
#importing basic packages
import pandas as pd
import numpy as np
import seaborn as sns
# Splitting the dataset into train and test sets: 80-20 split
from sklearn.model_selection import train_test_split                                           
#Support vector machine model
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score
    
class PhisingClassifier:


    
    # 1.Domain of the URL (Domain) 
    def getDomain(self,url):  
      domain = urlparse(url).netloc
      if re.match(r"^www.",domain):
               domain = domain.replace("www.","")
      return domain


# 2.Checks for IP address in URL (Have_IP)
    def havingIP(self,url):
      try:
        ipaddress.ip_address(url)
        ip = 1
      except:
        ip = 0
      return ip

# 3.Checks the presence of @ in URL (Have_At)
    def haveAtSign(self,url):
      if "@" in url:
        at = 1    
      else:
        at = 0    
      return at

# 4.Finding the length of URL and categorizing (URL_Length)
    def getLength(self,url):
      if len(url) < 54:
        length = 0            
      else:
        length = 1            
      return length

# 5.Gives number of '/' in URL (URL_Depth)
    def getDepth(self,url):
      s = urlparse(url).path.split('/')
      depth = 0
      for j in range(len(s)):
        if len(s[j]) != 0:
          depth = depth+1
      return depth

# 6.Checking for redirection '//' in the url (Redirection)
    def redirection(self,url):
      pos = url.rfind('//')
      if pos > 6:
        if pos > 7:
          return 1
        else:
          return 0
      else:
        return 0

# 7.Existence of “HTTPS” Token in the Domain Part of the URL (https_Domain)
    def httpDomain(self,url):
      domain = urlparse(url).netloc
      if 'https' in domain:
        return 1
      else:
        return 0


# 8. Checking for Shortening Services in URL (Tiny_URL)
    def tinyURL(self,url):
        #listing shortening services
        shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"

        match=re.search(shortening_services,url)
        if match:
            return 1
        else:
            return 0
    
# 9.Checking for Prefix or Suffix Separated by (-) in the Domain (Prefix/Suffix)
    def prefixSuffix(self,url):
        if '-' in urlparse(url).netloc:
            return 1            # phishing
        else:
            return 0            # legitimate
    

# importing required packages for this section


# 11.DNS Record availability (DNS_Record)
# obtained in the featureExtraction function itself

# 12.Web traffic (Web_Traffic)
    def web_traffic(self,url):
        try:
        #Filling the whitespaces in the URL if any
            url = urllib.parse.quote(url)
            rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "lxml").find(
                "REACH")['RANK']
            rank = int(rank)
        except TypeError:
            return 1
        if rank <100000:
            return 1
        else:
            return 0

# 13.Survival time of domain: The difference between termination time and creation time (Domain_Age)  
    def domainAge(self,domain_name):
      creation_date = domain_name.creation_date
      expiration_date = domain_name.expiration_date
      if (isinstance(creation_date,str) or isinstance(expiration_date,str)):
        try:
          creation_date = datetime.strptime(creation_date,'%Y-%m-%d')
          expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
        except:
          return 1
      if ((expiration_date is None) or (creation_date is None)):
          return 1
      elif ((type(expiration_date) is list) or (type(creation_date) is list)):
          return 1
      else:
        ageofdomain = abs((expiration_date - creation_date).days)
        if ((ageofdomain/30) < 6):
          age = 1
        else:
          age = 0
      return age

# 14.End time of domain: The difference between termination time and current time (Domain_End) 
    def domainEnd(self,domain_name):
      expiration_date = domain_name.expiration_date
      if isinstance(expiration_date,str):
        try:
          expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
        except:
          return 1
      if (expiration_date is None):
          return 1
      elif (type(expiration_date) is list):
          return 1
      else:
        today = datetime.now()
        end = abs((expiration_date - today).days)
        if ((end/30) < 6):
          end = 0
        else:
          end = 1
      return end

# importing required packages for this section


# 15. IFrame Redirection (iFrame)
    def iframe(self,response):
      if response == "":
          return 1
      else:
          if re.findall(r"[<iframe>|<frameBorder>]", response.text):
              return 0
          else:
              return 1
    
# 16.Checks the effect of mouse over on status bar (Mouse_Over)
    def mouseOver(self,response): 
      if response == "" :
        return 1
      else:
        if re.findall("<script>.+onmouseover.+</script>", response.text):
          return 1
        else:
          return 0

# 17.Checks the status of the right click attribute (Right_Click)
    def rightClick(self,response):
      if response == "":
        return 1
      else:
        if re.findall(r"event.button ?== ?2", response.text):
          return 0
        else:
          return 1

# 18.Checks the number of forwardings (Web_Forwards)    
    def forwarding(self,response):
      if response == "":
        return 1
      else:
        if len(response.history) <= 2:
          return 0
        else:
          return 1


#Function to extract features
    def featureExtraction(self,url,label):
      features = []
      #Address bar based features (10)
      features.append(self.getDomain(url))
      features.append(self.havingIP(url))
      features.append(self.haveAtSign(url))
      features.append(self.getLength(url))
      features.append(self.getDepth(url))
      features.append(self.redirection(url))
      features.append(self.httpDomain(url))
      features.append(self.tinyURL(url))
      features.append(self.prefixSuffix(url))
  
      #Domain based features (4)
      dns = 0
      try:
        domain_name = whois.whois(self.urlparse(url).netloc)
      except:
        dns = 1

      features.append(dns)
      features.append(self.web_traffic(url))
      features.append(1 if dns == 1 else self.domainAge(domain_name))
      features.append(1 if dns == 1 else self.domainEnd(domain_name))
  
      # HTML & Javascript based features (4)
      try:
        response = requests.get(url)
      except:
        response = ""
      features.append(self.iframe(response))
      features.append(self.mouseOver(response))
      features.append(self.rightClick(response))
      features.append(self.forwarding(response))
    
      return features

    #function to call for storing the results
    # Creating holders to store the model performance results
    ML_Model = []
    acc_train = []
    acc_test = []
    def storeResults(self,model, a,b):
      ML_Model.append(model)
      acc_train.append(round(a, 3))
      acc_test.append(round(b, 3))
    
    def prediksi(self,urlpising):
      url = urlpising
        
      #Loading the data
      data0 = pd.read_csv(r'apps\ml\phising_classifier\5.urldata.csv')
      data0.head()

      data0.describe()

      #Dropping the Domain column
      data = data0.drop(['Domain'], axis = 1).copy()

      #checking the data for null or missing values
      data.isnull().sum()

      # Sepratating & assigning features and target columns to X & y
      y = data['Label']
      X = data.drop('Label',axis=1)
      X.shape, y.shape

      X_train = X
      y_train = y 
        

      # instantiate the model
      svm = SVC(kernel='linear', C=1.0, random_state=12)
      #fit the model
      svm.fit(X_train, y_train)

      #predicting the target value from the model for the samples

      #Extracting the feautres & storing them in a list
      legi_features = []
      label = 0
      legi_features.append(self.featureExtraction(url,label))
    
      #converting the list to dataframe
      feature_names = ['Domain', 'Have_IP', 'Have_At', 'URL_Length', 'URL_Depth','Redirection', 
                    'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record', 'Web_Traffic', 
                    'Domain_Age', 'Domain_End', 'iFrame', 'Mouse_Over','Right_Click', 'Web_Forwards']

      legitimate = pd.DataFrame(legi_features, columns= feature_names)
      #print(legitimate)
      legitimate.describe()
      #Dropping the Domain column
      legitimate2 = legitimate.drop(['Domain'], axis = 1).copy()

      y_test_svm = svm.predict(legitimate2)
      #y_train_svm = svm.predict(X_train)
        
      return y_test_svm