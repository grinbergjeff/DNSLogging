#!/usr/bin/env python

# What: Project 2
# Code by: Jeffrey Grinberg
# For: EECE 480F - Computer Network Security, Spring 2016
# Due Date: 5/01/16

import re # allows the use of the regex search capabilities

# 2. Write a program in python to process the dnslog file and extract useful information from it:

# Take in a file and read it, store it to a variable, then close it.
inputFile = open('dnslog.txt','r')
readFile = inputFile.read()
inputFile.close();

# Upon looking at my dnslog.txt file I noticed I had some duplicate entries of just `IN A` scenarios.
	# An example is:

				# 2016-04-24 17:36:02.197922 Client IP: 127.0.0.1    request is    www.google.com. IN A    
				# 2016-04-24 17:36:02.229640 Client IP: 127.0.0.1    request is    www.google.com. IN AAAA
				# 2016-04-24 17:36:02.260476 Client IP: 127.0.0.1    request is    www.google.com. IN A -------SAME AS FIRST www.google.com
				# 2016-04-24 17:36:03.002694 Client IP: 127.0.0.1    request is    www.gstatic.com. IN A
				# 2016-04-24 17:36:03.034607 Client IP: 127.0.0.1    request is    www.gstatic.com. IN AAAA
				# 2016-04-24 17:36:03.065649 Client IP: 127.0.0.1    request is    www.gstatic.com. IN A -------SAME AS FIRST www.gstatic.com
				# 2016-04-24 17:36:03.259524 Client IP: 127.0.0.1    request is    apis.google.com. IN A
				# 2016-04-24 17:36:03.292542 Client IP: 127.0.0.1    request is    apis.google.com. IN AAAA
				# 2016-04-24 17:36:03.322956 Client IP: 127.0.0.1    request is    apis.google.com. IN A -------SAME AS FIRST apis.google.com

# Therefore to find only unique address entries, I want to only look for the ones that have `IN AAAA`. Would you say this is the correct approach?

inputArray = readFile.split('\n')
# Traverse through the array search for the `IN AAAA` values.
stringlook = "IN AAAA"
inputArray = "\n".join(s for s in inputArray if stringlook.lower() in s.lower()).split("\n")


filteredArrayCount = len(inputArray)

# Make an array that stores the timestamps in milliseconds.
timeStampMS = []


# Make an array that stores the host link in the same order as the timestamps
siteLink = []

#Make an array that stores the times in the same order as the timestamps
siteTimeFormatCorrect = []

for index, info in enumerate(inputArray):
	# Look for just the time stamps
	dnslogs = info.split(' ')
	# After some tests, I've found that the second element contains the time stamp that I desire
	siteTime = dnslogs[1]
	siteTimeFormatCorrect.append(dnslogs[1])
	# and the website is the 14th element
	siteLink.append(dnslogs[13])

	siteTimeArray = siteTime.split(':')

	#convert the first index of siteTimeArray, hour to milliseconds
		##### NOTE : INTs are not big enough for this math.
	hoursMS = 3600000 * long(siteTimeArray[0])
	#convert the second index of siteTimeArray, minute to milliseconds
	minutesMS = 60000 * long(siteTimeArray[1])
	#convert the third index of siteTimeArray, second to milliseconds
	secondsAndMS = siteTimeArray[2].split('.')
	secondsMS = 1000 * long(secondsAndMS[0])
	# The milliseconds are stored after the . in the log file.
	mS = long(secondsAndMS[1])

	# Calculate the time for each timestamp in milliseconds and store it in the end of the array that holds each time in milliseconds
	timeStampMS.append(hoursMS + minutesMS + secondsMS + mS)

# Now that we have the timestamps in milliseconds, we will look for timestamps that are at least 60,000 ms
# away. We can calculate this by traversing through each timestamp and subtracting to find the difference

# Make an array to store potentially correct links (indexes to the links) that are at least 60,000 ms apart
maybe_correct_index = []
# The first query is always the first element in the filter only `IN AAAA` array
maybe_correct_index.append(0)	

for index, time in enumerate(timeStampMS):
	# index will constantly traverse through the array where check me will be stuck at the first link that appears every 60,000ms
	subtraction = abs(time - timeStampMS[index-1] )
	if subtraction > 15000:
			# Look for what exists in the link and filter it
			# Typical links have 3 dots:
		if siteLink[index].count('.') >= 2:
			# Now search for the standard website: www . ___________ . com/edu/org/net.
			# www identifies that the website is on the internet, not some potentially local site overiding like we did with yahoo.com in our lab
			# if re.search('www(\.)(\S+)(\.)(com|edu|org|net)', siteLink[index]) :
				# If we go past a minute, then we should store this as possibly a right DNS that we entered:
			maybe_correct_index.append(index)
				# Now we need to jump the stuck checkme to the current address that has the minute past.
				# checkme = index
maybe_correct_index.pop(0)
print maybe_correct_index

# Calculate the length between each properly made (man-made) queries and store it into an array.
queryLength = []
for index, linkname in enumerate(maybe_correct_index):
	# Find the length in amount of queries occur for each entered one.
	difference = abs(linkname - maybe_correct_index[index-1]-1)
	# Store these lengths to an array
	queryLength.append(difference)
# Find the amount of the last entered queries
queryLength.append(abs(maybe_correct_index[-1] - filteredArrayCount))
# First length is garbage.
queryLength.pop(0)

# Array for which indexes I need to pop because they are duplicates:
needToPopIndex=[]

for index, correctIndex in enumerate(maybe_correct_index):
	# Filter the duplicates that appear:
	tempFiltered = []
	for x in range(correctIndex, (correctIndex + queryLength[index])):
		if siteLink[x] not in tempFiltered:
			tempFiltered.append(siteLink[x])
		else:
			needToPopIndex.append(x)
			print 'popping site: %s' % (siteLink[x])
			print 'popping time: %s' % (siteTimeFormatCorrect[x])
print needToPopIndex



for index, popthis in enumerate(needToPopIndex):
	print index
	siteLink.pop(popthis)
	siteTimeFormatCorrect.pop(popthis)

 # Print Stuff:

 #Prepare to write to a report file:
outputFile = open('report.txt', 'w')

counter = 0
for index, correctIndex in enumerate(maybe_correct_index):
 	potentiallyCorrectLink = siteLink[correctIndex]
	cleanCorrectLink = potentiallyCorrectLink[:-1]
	# a) For visited page count the number of unique DNS requests.
	# c) For visited page, print out the time the first requested webpage was visited.
	outputFile.write('%s: %d Time: %s \n' % (cleanCorrectLink, queryLength[index], siteTimeFormatCorrect[linkname]))
	for x in range(correctIndex, (correctIndex + queryLength[index])):
		counter += 1
		# b) For visited page, print out the unique DNS names observed.
		outputFile.write('%d. %s \n' %(counter, siteLink[x][:-1]))
	counter = 0
outputFile.close()

	

