import os
from flask import Flask, render_template, request
import matplotlib
import pandas as pd
from urllib.parse import urlparse
import ipaddress
import re
from bs4 import BeautifulSoup
import whois
import urllib
import urllib.request
from datetime import datetime
import requests
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split

app = Flask(__name__)

app.config['upload folder'] =r'uploads'
top_doms = pd.read_csv('top-1m.csv', header=None)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/load data',methods = ["POST","GET"])
def load_data():
    if request.method == "POST":
        file = request.files['file']
        filetype = os.path.splitext(file.filename)[1]
        print(filetype)
        if filetype == '.csv':
            mypath = os.path.join(app.config['upload folder'],file.filename)
            file.save(mypath)
            return render_template('load data.html',msg = 'success')
        else:
            return render_template('load data.html',msg = 'invalid')
    return render_template('load data.html')

@app.route('/view data',methods = ["POST","GET"])
def view_data():
    path = os.listdir(app.config['upload folder'])
    file = os.path.join(app.config['upload folder'],path[0])
    df = pd.read_csv(file)
    return render_template('view data.html',col_name = df.columns,row_val = list(df.values.tolist()))

@app.route('/model',methods = ['GET',"POST"])
def model():
    global score1,score2,score3
    if request.method == "POST":
        model = int(request.form['selected'])
        print(model)
        path = os.listdir(app.config['upload folder'])
        file = os.path.join(app.config['upload folder'], path[0])
        df = pd.read_csv(file)

        print(df.columns)
        print('#######################################################')

        X = df.drop(['Label','Domain'], axis =1)
        y = df.Label
        x_train,x_test,y_train,y_test =train_test_split(X,y,test_size=0.3,random_state  =20)

        print(df)
        if model == 1:
            rfr = RandomForestClassifier()
            X = df.drop(['Label','Domain'], axis =1)
            y = df.Label
            x_train,x_test,y_train,y_test =train_test_split(X,y,test_size=0.3,random_state  =20)
            rfr.fit(x_train,y_train)
            pred = rfr.predict(x_test)
            score1 = accuracy_score(y_test,pred)*100
            print(score1)
            msg = 'The accuracy obtained by Random Forest Classifier is ' + str(score1) + str('%')
            return render_template('model.html',msg=msg)
        elif model ==2:
            classifier = DecisionTreeClassifier(max_leaf_nodes=39, random_state=0)
            classifier.fit(x_train,y_train)
            pred = classifier.predict(x_test)
            score2 = accuracy_score(y_test,pred)*100
            print(score2)
            msg = 'The accuracy obtained by Decision Tree Classifier is ' + str(score2) + str('%')
            return render_template('model.html',msg=msg)
        elif model ==3:
            from xgboost import XGBClassifier
            xgb = XGBClassifier()
            xgb.fit(x_train,y_train)
            pred = xgb.predict(x_test)
            score3 = accuracy_score(y_test, pred)*100
            print(score3)
            msg = 'The accuracy obtained by Support Vector Machine is ' + str(score3) + str('%')


            return render_template('model.html',msg=msg)
    return render_template('model.html')

@app.route('/prediction', methods=["POST","GET"])
def prediction():
    if request.method == "POST":
        url1 = request.form['a']
        def getDomain(url):
            domain = urlparse(url).netloc
            if re.match(r"^www.", domain):
                domain = domain.replace("www.", "")
            return domain

        def havingIP(url):
            try:
                ipaddress.ip_address(url)
                ip = 1
            except:
                ip = 0
            return ip

        def haveAtSign(url):
            if "@" in url:
                at = 1
            else:
                at = 0
            return at

        def getLength(url):
            if len(url) < 54:
                length = 0
            else:
                length = 1
            return length

        def getDepth(url):
            s = urlparse(url).path.split('/')
            depth = 0
            for j in range(len(s)):
                if len(s[j]) != 0:
                    depth = depth + 1
            return depth

        def redirection(url):
            pos = url.rfind('//')
            if pos > 6:
                if pos > 7:
                    return 1
                else:
                    return 0
            else:
                return 0

        def httpDomain(url):
            domain = urlparse(url).netloc
            if 'https' in domain:
                return 1
            else:
                return 0

        shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                              r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                              r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                              r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                              r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                              r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                              r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                              r"tr\.im|link\.zip\.net"

        def tinyURL(url):
            match = re.search(shortening_services, url)
            if match:
                return 1
            else:
                return 0

        def prefixSuffix(url):
            if '-' in urlparse(url).netloc:
                return 1  # phishing
            else:
                return 0  # legitimate

        def web_traffic(url):
            try:
                # Filling the whitespaces in the URL if any
                url = urllib.parse.quote(url)
                rank = \
                BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(),
                              "xml").find(
                    "REACH")['RANK']
                rank = int(rank)
            except TypeError:
                return 1
            if rank < 100000:
                return 1
            else:
                return 0

        def domainAge(domain_name):
            creation_date = domain_name.creation_date
            expiration_date = domain_name.expiration_date
            if (isinstance(creation_date, str) or isinstance(expiration_date, str)):
                try:
                    creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
                    expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
                except:
                    return 1
            if ((expiration_date is None) or (creation_date is None)):
                return 1
            elif ((type(expiration_date) is list) or (type(creation_date) is list)):
                return 1
            else:
                ageofdomain = abs((expiration_date - creation_date).days)
                if ((ageofdomain / 30) < 6):
                    age = 1
                else:
                    age = 0
            return age

        def domainEnd(domain_name):
            expiration_date = domain_name.expiration_date
            if isinstance(expiration_date, str):
                try:
                    expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
                except:
                    return 1
            if (expiration_date is None):
                return 1
            elif (type(expiration_date) is list):
                return 1
            else:
                today = datetime.now()
                end = abs((expiration_date - today).days)
                if ((end / 30) < 6):
                    end = 0
                else:
                    end = 1
            return end

        def iframe(response):
            if response == "":
                return 1
            else:
                if re.findall(r"[<iframe>|<frameBorder>]", response.text):
                    return 0
                else:
                    return 1

        def mouseOver(response):
            if response == "":
                return 1
            else:
                if re.findall("<script>.+onmouseover.+</script>", response.text):
                    return 1
                else:
                    return 0

        def rightClick(response):
            if response == "":
                return 1
            else:
                if re.findall(r"event.button ?== ?2", response.text):
                    return 0
                else:
                    return 1

        def forwarding(response):
            if response == "":
                return 1
            else:
                if len(response.history) <= 2:
                    return 0
                else:
                    return 1

        def featureExtraction(url):
            features = []
            # Address bar based features (10)
            features.append(getDomain(url))
            features.append(havingIP(url))
            features.append(haveAtSign(url))
            features.append(getLength(url))
            features.append(getDepth(url))
            features.append(redirection(url))
            features.append(httpDomain(url))
            features.append(tinyURL(url))
            features.append(prefixSuffix(url))

            # Domain based features (4)
            dns = 0
            try:
                domain_name = whois.whois(urlparse(url).netloc)
            except:
                dns = 1

            features.append(dns)
            features.append(web_traffic(url))
            features.append(1 if dns == 1 else domainAge(domain_name))
            features.append(1 if dns == 1 else domainEnd(domain_name))

            # HTML & Javascript based features (4)
            try:
                response = requests.get(url)
            except:
                response = ""
            features.append(iframe(response))
            features.append(mouseOver(response))
            features.append(rightClick(response))
            features.append(forwarding(response))
            # features.append(label)

            return features

        data0 = pd.read_csv('uploads/url_data_modified.csv')
        data = data0.drop(['Domain'], axis=1).copy()
        data = data.sample(frac=1).reset_index(drop=True)
        y = data['Label']
        X = data.drop('Label', axis=1)
        from sklearn.model_selection import train_test_split

        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=12)
        from sklearn.ensemble import RandomForestClassifier

        # instantiate the model
        forest = RandomForestClassifier(max_depth=5)

        # fit the model
        forest.fit(X_train, y_train)
        print('aa')
        print(url1)
        print(type(url1))
        my_features = featureExtraction(url1)
        prob_of_doms = top_doms[1].values
        if my_features[0] in prob_of_doms:
            return render_template('prediction.html',msg = 'success')
        else:
            pred1 = forest.predict([my_features[1:]])
            return render_template('prediction.html',result=pred1)
    return render_template('prediction.html')

@app.route('/graph')
def graph ():

    # import matplotlib.pyplot as plt
    
    # import seaborn as sns

    # x1=['Random Forest','Decision Tree', 'Support Vector Machine']
    # y2 = [score1,score2,score3]
    # sns.barplot(x1,y2)

    return render_template('graph.html')




if __name__ == '__main__':
    app.run(debug=True)