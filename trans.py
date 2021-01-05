#!/usr/bin/python

# coding=utf-8

import os
import sys
import json
import time 
import base64
import getopt
import xml.dom.minidom
import xml.parsers.expat
import subprocess as sp
from yajl import *
from time import strftime,gmtime

gMatchMap = {}
gKeyMapping = {}
gFltTranCode = []
gExcludeTranCode = []
gEndPointList = []
gPcapList = []
gOutPut = None
gOutFile = None
gOutPath = None
gOutInterval = None
gBPFFilter = 'host 0'
gLastTime = 0
gMsgCount = 1
gXmlParser = None
gXmlLastKey = None
gXmlFeatures = '<?xml'

reload(sys)
sys.setdefaultencoding('utf8')
SOCK_ADDR, SOCK_PORT = range(2)
SRCINFO, CONVSTR, DSTINFO = range(3)

def mappingKeyVal(out, key, val):
  global gKeyMapping
  for k,v in gKeyMapping.items():
    if k == key: out[v] = val

class JsonHandler(YajlContentHandler):
  def __init__(self):
    self.outdict = None
    self.lastKey = None

  def setOutput(self, outdict): self.outdict = outdict
  def processField(self, val): mappingKeyVal(self.outdict, self.lastKey, val)

  def yajl_null(self, ctx): self.processField(None)
  def yajl_boolean(self, ctx, boolVal): self.processField(boolVal)
  def yajl_number(self, ctx, stringNum): self.processField(stringNum)
  def yajl_string(self, ctx, stringVal): self.processField(stringVal)
  def yajl_map_key(self, ctx, stringVal): self.lastKey = stringVal

  def yajl_start_map(self, ctx): pass
  def yajl_end_map(self, ctx): pass
  def yajl_start_array(self, ctx): pass
  def yajl_end_array(self, ctx): pass

def startElement(tag, attributes):
  global gOutPut, gXmlLastKey
  if isinstance(attributes, list):
    for attr in attributes: mappingKeyVal(gOutPut, attr[0], attr[1])
  else:
    for key in attributes.keys(): mappingKeyVal(gOutPut, key, attributes[key])
  gXmlLastKey = tag

def elementContent(content):
  global gOutPut, gXmlLastKey
  mappingKeyVal(gOutPut, gXmlLastKey, content)
  pass

gJsonHandle = JsonHandler()
gJsonParser = YajlParser(gJsonHandle)

gXmlParser = xml.parsers.expat.ParserCreate()
gXmlParser.StartElementHandler = startElement
gXmlParser.CharacterDataHandler = elementContent

def getPcapList(pcapDir):
  fileList = os.listdir(pcapDir)
  fileList = sorted(fileList,  key=lambda x: os.path.getmtime(os.path.join(pcapDir, x)))
  for f in fileList:
    if 'pcap' in f: gPcapList.append(pcapDir+'/'+f)
  
def readConf(confFile):
  dom = xml.dom.minidom.parse(confFile)
  
  root = dom.documentElement
  endPointList = root.getElementsByTagName('end-point')
  mappingList = root.getElementsByTagName('mapping')
  transCodeList = root.getElementsByTagName('transcode')
  excTransCodeList = root.getElementsByTagName('exclude-transcode')
  outPath = root.getElementsByTagName('store-path')
  outInterval = root.getElementsByTagName('interval')

  for endPoint in endPointList:
    global gBPFFilter
    addr = endPoint.getElementsByTagName('address')[0].firstChild.data
    port = endPoint.getElementsByTagName('port')[0].firstChild.data
    gEndPointList.append({'address': addr, 'port': port})
    gBPFFilter += ' or (host %s and port %s)' % (addr, port)
  
  for transCode in transCodeList:
    val = transCode.firstChild.data
    gFltTranCode.append(val)
  
  for excTransCode in excTransCodeList:
    val = excTransCode.firstChild.data
    gExcludeTranCode.append(val)
  
  for mapping in mappingList:
    origin = mapping.firstChild.data
    replace = mapping.getAttribute('name')
    gKeyMapping[origin] = replace

  global gOutPath
  global gOutInterval
  gOutPath = outPath[0].firstChild.data
  gOutInterval = int(outInterval[0].firstChild.data)

def parseHttpHead(httpMsg, out):
  fieldList = httpMsg.split('\r\n')
  urlFieldList = fieldList[0].split(' ')
  if 'POST' in fieldList[0] or 'GET' in fieldList[0]:
    path = urlFieldList[1]
    out['msgType'] = 'req'
    out['transCode']= urlFieldList[1]
    if '?' in path: out['transCode'] = path[0:path.find('?')]
    extension = {'method': urlFieldList[0], 'path': out['transCode'], 'version': urlFieldList[2]}
  else:
    extension = {'version': urlFieldList[0], 'httpcode': urlFieldList[1]}
    out['msgType'] = 'res'
  for field in fieldList[1:]:
    keyVal = field.split(':')
    if 2 != len(keyVal): continue
    extension[keyVal[0]] = keyVal[1].strip()
  out['extension'] = extension

def processMsg(msg):
  global gXmlFeatures
  baseEnd   = msg.find(': ')
  msgBody   = msg[baseEnd+2:]
  baseField = msg[:baseEnd].split('#')
  timeField = baseField[0]
  srcIp   = baseField[1].split('_')[0]
  dstIp   = baseField[2].split('_')[0]
  srcPort = baseField[1].split('_')[1]
  dstPort = baseField[2].split('_')[1]

  # gen matchId field
  realMatchId = None
  matchId = '%s_%s_%s_%s' % (srcIp.replace('.', '_'), srcPort, dstIp.replace('.', '_'), dstPort)
  if int(srcPort) < int(dstPort): matchId = '%s_%s_%s_%s' % (dstIp.replace('.', '_'), dstPort, srcIp.replace('.', '_'), srcPort)
  if gMatchMap.has_key(matchId): gMatchMap[matchId] += 1
  else: gMatchMap[matchId] = 1
  realMatchId = '%s_%03d' % (matchId, (gMatchMap[matchId]-1)/2)

  # gen base field
  timeSplit =  timeField.split('.')
  timeStr =  strftime("%Y-%m-%d %H:%M:%S.", time.localtime(float(timeField))) + timeSplit[1]
  output = {'srcIp': srcIp, 'dstIp': dstIp, 'srcPort': srcPort, 'dstPort': dstPort, 'channelId': '', 'timestamp': timeStr, 'matchId': realMatchId}

  # parse http header
  httpKey = msgBody[:4]
  if 'POST' in httpKey or 'GET' in httpKey or 'HTTP' in httpKey:
    output['commProtocol'] = 'HTTP'
    parseHttpHead(msgBody, output)

  # parse json body
  jsonStart = -1
  dictStart = msgBody.find('{')
  listStart = msgBody.find('[')
  if -1 != dictStart and -1 == listStart: jsonStart = dictStart
  if -1 == dictStart and -1 != listStart: jsonStart = listStart
  if -1 != dictStart and -1 != listStart: jsonStart = dictStart if dictStart < listStart else listStart 
  if -1 != dictStart or  -1 != listStart:
    global gJsonHandle, gJsonParser
    gJsonHandle.setOutput(output)
    originStr = msgBody[jsonStart:].strip()
    with open('/tmp/jsontmp', 'w') as f: f.write(originStr)
    with open('/tmp/jsontmp', 'r') as f: gJsonParser.parse(f)
    output['msgData'] = base64.b64encode(originStr)

  # parse xml body
  xmlStart = msgBody.find(gXmlFeatures)
  if -1 != xmlStart:
    global gOutPut
    gOutPut = output 
    originStr = msgBody[xmlStart:].strip()
    originStr = originStr[originStr.find('>')+1:]
    gXmlParser.Parse(originStr)
    output['msgData'] = base64.b64encode(originStr)

  # write reslut to file
  gOutFile.write(json.dumps(output, ensure_ascii=False))
  gOutFile.write('\n')

  # print msg count
  global gMsgCount
  print('write msg %d' % (gMsgCount))
  gMsgCount += 1

def fileTimeOut(now, timeLine):
  global gOutFile, gLastTime
  gLastTime = now
  timeStr = timeLine.split('#')[0].split('.')[0]
  filepath = '%s/original_single_message_%s' % (gOutPath, timeStr)
  if None != gOutFile: gOutFile.close()
  gOutFile = open(filepath, 'w')

def getTcpStream(fname):
  lineList = []
  global gLastTime, gOutInterval
  allArgs = ['ipmstream', '-r', fname, '-s', '-B', '-T', '####%T#%A_%a#%B_%b', gBPFFilter]
  p = sp.Popen(allArgs, stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.PIPE, close_fds=True)
  line = p.stdout.readline()
  while line:
    now = time.time()
    if '####' in line:
      line = line[4:]
      if now - gLastTime >= gOutInterval: fileTimeOut(now, line)
      if 0 != len(lineList): processMsg(''.join(lineList))
      lineList = []
    lineList.append(line)
    line = p.stdout.readline()
  if 0 != len(lineList): processMsg(''.join(lineList))
  p.stdout.close()
  p.stdin.close()

opts,args = getopt.getopt(sys.argv[1:],'-p:-c:-e:-x:')
print(opts)
for optName,optValue in opts:
  if optName in ('-p'):
    getPcapList(optValue)
  if optName in ('-c'):
    readConf(optValue)
  if optName in ('-x'):
    gXmlFeatures = optValue

for pcapFile in gPcapList:
  print('========================= Process file: %s ========================' % (pcapFile))
  getTcpStream(pcapFile)

# print(gPcapList)
# print(gEndPointList)
# print(gKeyMapping)
# print(gFltTranCode)
# print(gExcludeTranCode)
