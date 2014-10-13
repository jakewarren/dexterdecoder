#! /usr/bin/env python

# Description: Decodes the post data from the Dexter PoS malware
# Author: Jake Warren
# Reference Link: http://blog.spiderlabs.com/2012/12/the-dexter-malware-getting-your-hands-dirty.html


from operator import xor
import base64
import array

#fill in this variable with the posted data from the POST request
postdata ="page=AwICB1VWVwRMUVVYVUxVUwAHTABWAFZMUVJTUlECWAVVVlVU&val=ZnJ0a2o="

variables = dict(item.split("=",1) for item in postdata.split("&"))

xorkey = base64.b64decode(variables['val']) 
print "XOR Key: "+ xorkey
print

# decode all variables
for var in variables:
	rawdata = array.array("B",base64.b64decode(variables[var] ))
	for i in range(len(rawdata)):
		for char in xorkey:
			rawdata[i] ^= ord(char)
	variables[var] = rawdata.tostring()

# print all variables
for var in variables:
	data = variables[var]

	if var == "val": #skip the encryption key
		continue
	if var == "page":
		print var +" (Mutex String):  " +variables[var] 
	if var == "ump":
		print var +" (Track data):  " +variables[var]
	if var == "unm":
		print var +" (Username):  " +variables[var]
	if var == "cnm":
		print var +" (Hostname):  " +variables[var] 
	if var == "query":
		print var +" (Victim OS):  " +variables[var]
	if var == "spec":
		print var +" (Processor type):  " +variables[var]
	if var == "opt":
		print var +" (Unknown):  " +variables[var] 
	if var == "view":
		print var +" (Process List):  " +variables[var]
	if var == "var":
		print var +" (Campaign name?):  " +variables[var]
	




