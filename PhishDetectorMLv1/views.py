from django.shortcuts import render

# Create your views here.

from django.http import HttpResponse
from django.shortcuts import render, get_object_or_404, redirect
from django.template.loader import render_to_string
from django.views.generic import CreateView
import requests

from PhishDetectorMLv1.models import URLForm



import numpy as np
from sklearn import *
from sklearn import tree
from sklearn.metrics import accuracy_score


import re
import regex
from tldextract import extract
import ssl
import socket
import whois
import datetime

from PhishDetectorMLv1.models import URLForm
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError


def home(request):
    form = URLForm
    return render(request, 'PhishDetectorMLv1\\search_form.html', {'form': form})

def results(request):
    if request.method == "POST":
        dataForm = URLForm(request.POST)
        url = str(dataForm['url'])
    else:
        dataForm = URLForm()

    def url_having_ip(url):
        # regexp = re.compile('[@_!#$%^&*()<>?/\|}{~:]')
        # if (len(regexp.search(url)) == 0):
        #     return -1
        # else:
        #     return 1
        return 1

    def url_length(url):
        if (len(url) < 54):
            return -1
        elif (54 <= len(url) < 74):
            return 0
        else:
            return 1

    def url_short(url):
        return 1

    def having_at_symbol(url):
        symbol = regex.findall(r'@', url)
        if (len(symbol) == 0):
            return -1
        else:
            return 1

    def doubleSlash(url):
        return 1

    def prefix_suffix(url):
        subDomain, domain, suffix = extract(url)
        if (domain.count('-')):
            return -1
        else:
            return 1

    def sub_domain(url):
        subDomain, domain, suffix = extract(url)
        if (subDomain.count('.') == 0):
            return 1
        elif (subDomain.count('.') == 1):
            return 0
        else:
            return -1

    def SSLfinal_State(url):
        try:
            # check wheather contains https
            if (regex.search('^https', url)):
                usehttps = 1
            else:
                usehttps = 0
            # getting the certificate issuer to later compare with trusted issuer
            # getting host name
            subDomain, domain, suffix = extract(url)
            host_name = domain + "." + suffix
            context = ssl.create_default_context()
            sct = context.wrap_socket(socket.socket(), server_hostname=host_name)
            sct.connect((host_name, 443))
            certificate = sct.getpeercert()
            issuer = dict(x[0] for x in certificate['issuer'])
            certificate_Auth = str(issuer['commonName'])
            certificate_Auth = certificate_Auth.split()
            if (certificate_Auth[0] == "Network" or certificate_Auth == "Deutsche"):
                certificate_Auth = certificate_Auth[0] + " " + certificate_Auth[1]
            else:
                certificate_Auth = certificate_Auth[0]
            trusted_Auth = ['Comodo', 'Symantec', 'GoDaddy', 'GlobalSign', 'DigiCert', 'StartCom', 'Entrust', 'Verizon',
                            'Trustwave', 'Unizeto', 'Buypass', 'QuoVadis', 'Deutsche Telekom', 'Network Solutions',
                            'SwissSign', 'IdenTrust', 'Secom', 'TWCA', 'GeoTrust', 'Thawte', 'Doster', 'VeriSign']
            # getting age of certificate
            startingDate = str(certificate['notBefore'])
            endingDate = str(certificate['notAfter'])
            startingYear = int(startingDate.split()[3])
            endingYear = int(endingDate.split()[3])
            Age_of_certificate = endingYear - startingYear

            # checking final conditions
            if ((usehttps == 1) and (certificate_Auth in trusted_Auth) and (Age_of_certificate >= 1)):
                return -1  # legitimate
            elif ((usehttps == 1) and (certificate_Auth not in trusted_Auth)):
                return 0  # suspicious
            else:
                return 1  # phishing

        except Exception as e:

            return 1

    def domain_registration(url):
        try:
            w = whois.whois(url)
            updated = w.updated_date
            exp = w.expiration_date
            length = (exp[0] - updated[0]).days
            if (length <= 365):
                return 1
            else:
                return -1
        except:
            return 0

    def https_token(url):
        subDomain, domain, suffix = extract(url)
        host = subDomain + '.' + domain + '.' + suffix
        if (host.count('https')):  # attacker can trick by putting https in domain part
            return -1
        else:
            return 1

    check = [[url_having_ip(url), url_length(url), url_short(url), having_at_symbol(url),
              doubleSlash(url), prefix_suffix(url), sub_domain(url), SSLfinal_State(url),
              domain_registration(url), https_token(url)]]

    training_data = np.genfromtxt('C:\\Users\\prai\\PycharmProjects\\PhishDetectorML\\PhishDetectorMLv1\\12csv_result-Training Dataset.csv', delimiter=',', dtype=np.int32)

    inputs = training_data[:, :-1]
    outputs = training_data[:, -1]

    training_inputs = inputs[:1000]
    training_outputs = outputs[:1000]

    classifier = tree.DecisionTreeClassifier()
    classifier.fit(training_inputs, training_outputs)

    prediction = classifier.predict(check)

    if(prediction==1):
        entity = 'phishing'
    else:
        entity = 'legitimate'



    return render(request, 'PhishDetectorMLv1\\results.html', {'entity': entity})
