#!/usr/bin/python

# coding=utf-8

import os
import sys
import json
import time 
import base64
import xml.dom.minidom
import subprocess as sp
from io import StringIO
from time import strftime,gmtime
from splitstream import splitfile

gMatchMap = {}
gKeyMapping = {}
gFltTranCode = []
gExcludeTranCode = []
gEndPointList = []
gPcapList = []
gOutFile = None
gOutPath = None
gOutInterval = None
gBPFFilter = 'host 0'
gLastTime = 0

SOCK_ADDR, SOCK_PORT = range(2)
SRCINFO, CONVSTR, DSTINFO = range(3)

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

  global gBPFFilter
  for endPoint in endPointList:
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

def recuDict(d, out, key):
  if isinstance(d, list):
    for i in d: recuDict(i, out, key)
  elif isinstance(d, dict):
    for key, value in d.items():
      recuDict(value, out, key)
  else:
    for k,v in gKeyMapping.items():
      if k == key: out[v] = d

def processMsg(msg):
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

  parse http header
  httpKey = msgBody[:4]
  if 'POST' in httpKey or 'GET' in httpKey or 'HTTP' in httpKey:
    out['commProtocol'] = 'HTTP'
    parseHttpHead(msgBody, output)

  # parse json body
  jsonStart = -1
  dictStart = msgBody.find('{')
  listStart = msgBody.find('[')
  if -1 != dictStart and -1 == listStart: jsonStart = dictStart
  if -1 == dictStart and -1 != listStart: jsonStart = listStart
  if -1 != dictStart and -1 != listStart: jsonStart = dictStart if dictStart < listStart else listStart 
  if -1 != dictStart or  -1 != listStart:
    originStr = msgBody[jsonStart:].strip()
    originDict = json.loads(originStr)
    recuDict(originDict, output, None)
    output['msgData'] = base64.b64encode(originStr)

  # write reslut to file
  gOutFile.write(json.dumps(output))
  gOutFile.write('\n')

def fileTimeOut(now, timeLine):
  global gOutFile, gLastTime
  gLastTime = now
  timeStr = timeLine.split('#')[0].split('.')[0]
  filepath = '%s/original_single_message_%s' % (gOutPath, timeStr)
  if None != gOutFile: gOutFile.close()
  gOutFile = open(filepath, 'w')

def getTcpStream(fname):
  msgCount = 0
  lineList = []
  global gLastTime, gOutInterval
  allArgs = ['ipmstream', '-r', fname, '-s', '-B', '-T', '####%T#%A_%a#%B_%b', gBPFFilter]
  p = sp.Popen(allArgs, stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.PIPE, close_fds=True)
  line = p.stdout.readline()
  while line:
    now = time.time()
    if '####' in line:
      msgCount += 1
      print('write msg %d' % (msgCount))
      line = line[4:]
      if now - gLastTime >= gOutInterval: fileTimeOut(now, line)
      if 0 != len(lineList): processMsg(''.join(lineList))
      lineList = []
    lineList.append(line)
    line = p.stdout.readline()
  if 0 != len(lineList): processMsg(''.join(lineList))
  p.stdout.close()
  p.stdin.close()

getPcapList(sys.argv[1])
readConf(sys.argv[2])

for pcapFile in gPcapList:
  print('========================= Process file: %s ========================' % (pcapFile))
  getTcpStream(pcapFile)

# print(gPcapList)
# print(gEndPointList)
# print(gKeyMapping)
# print(gFltTranCode)
# print(gExcludeTranCode)