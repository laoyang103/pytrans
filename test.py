#!/usr/bin/python
# coding=utf-8

import sys
import json
from yajl import *

class JsonHandler(YajlContentHandler):
  def __init__(self):
    self.outdict = None
    self.lastKey = None

  def setOutput(self, outdict): self.outdict = outdict
  def processField(self, val): self.outdict[self.lastKey] = val

  def yajl_null(self, ctx): self.processField(None)
  def yajl_boolean(self, ctx, boolVal): self.processField(boolVal)
  def yajl_number(self, ctx, stringNum): self.processField(stringNum)
  def yajl_string(self, ctx, stringVal): self.processField(stringVal)
  def yajl_map_key(self, ctx, stringVal): self.lastKey = stringVal

  def yajl_start_map(self, ctx): pass
  def yajl_end_map(self, ctx): pass
  def yajl_start_array(self, ctx): pass
  def yajl_end_array(self, ctx): pass

handle = JsonHandler()
parser = YajlParser(handle)

laoyang = {"laoyang": 333}
handle.setOutput(laoyang)
parser.parse()
print(json.dumps(laoyang, encoding="UTF-8", ensure_ascii=False))
