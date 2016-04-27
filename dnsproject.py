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

# Therefore to find only unique address entries, I want to only look for the ones that have `IN A`. Would you say this is the correct approach?

inputArray = readFile.split('\n')
# Traverse through the array search for the `IN AAAA` values.
#stringlook = "IN A"
#inputArray = "\n".join(s for s in inputArray if stringlook.lower() in s.lower()).split("\n")


filteredArrayCount = len(inputArray)

# Make an array that stores the host link in the same order as the timestamps
siteLink = []

#Make an array that stores the unformatted in the same order as the timestamps
siteTimeFormatCorrect = []

# Make an array that stores the timestamps in milliseconds.
timeStampMS = []

# Go through every element inside the dnslog and extract information from it to the respective arrays.
for index, info in enumerate(inputArray):
	dnslogs = info.split(' ')
	# After some tests, I've found that the second element contains the time stamp that I desire
	siteTime = dnslogs[1]
	siteTimeFormatCorrect.append(siteTime)
	# and the website is the 14th element
	siteLink.append(dnslogs[13])

	siteTimeArray = siteTime.split(':')

	# Convert the timestamps to millisconds:
		# NOTE : INTs are not big enough for this math.
	hoursMS = 3600000 * long(siteTimeArray[0])
	minutesMS = 60000 * long(siteTimeArray[1])
	secondsAndMS = siteTimeArray[2].split('.')
	secondsMS = 1000 * long(secondsAndMS[0])
	# The milliseconds are stored after the . in the log file.
	mS = long(secondsAndMS[1])

	# Calculate the time for each timestamp in milliseconds and store it in the end of the array that holds each time in milliseconds
	timeStampMS.append(hoursMS + minutesMS + secondsMS + mS)

# Now that we have the timestamps in milliseconds, we will look for timestamps that are at least 15,000 ms
# away. We can calculate this by traversing through each timestamp and subtracting from the indexed value before

# Array that holds the INDEXES of where the possible man-made searches were made.
maybe_correct_index = []

# The first possibly correct man-made search is always the first link (first index)
# maybe_correct_index.append(0)	

for index, time in enumerate(timeStampMS):
	subtraction = abs(time - timeStampMS[index-1] )
	if subtraction > 15000:
			# Look for what exists in the link and filter it
			# Typical links have at least dots:
		if siteLink[index].count('.') >= 2:
					# Now search for the standard website: www . ___________ . com/edu/org/net.
					# www identifies that the website is on the internet, not some potentially local site overiding like we did with yahoo.com in our lab
					# if re.search('www(\.)(\S+)(\.)(com|edu|org|net)', siteLink[index]) :
				# If we go past 15000ms, then we should store this as possibly a right DNS that we entered:
			maybe_correct_index.append(index)
# maybe_correct_index.pop(0)
# print maybe_correct_index

# Calculate the length between each properly made (man-made) queries and store it into an array.
# For every element in the maybe_correct_index calculate the difference between the element and the element before it-1.
# This will find how long this query goes for until the next man-made query occurs. However, need to be careful and
# account for when the length of the query of the last man-made query which will not be taken account for in the for-loop.
# This length will be commented about below:
queryLength = []
for index, linkname in enumerate(maybe_correct_index):
	difference = abs(linkname - maybe_correct_index[index-1]-1)
	queryLength.append(difference)
# Still need to account for the last man-made query length.
# This will equal the difference of the element minute the length of the array since it contains the last number of the element of all the queries.
queryLength.append(abs(maybe_correct_index[-1] - filteredArrayCount))
# First length is garbage since its 0 - the biggest value. It is useless.
# When index is 0, it looks for the index-1 value (as it does in all other index values), but index-1 in this case is the last element of this array.
# I don't care about this value so Im going to pop it.
queryLength.pop(0)
# This kills two birds with one stone becuase it synchronizes the indexes with their respective lengths:
# Basically, maybe_correct_index[1] will have queryLength[1] values, so on and so forth.


# Array that will hold all the dns requests but get rid of any duplicates
inputArrayFiltered = []

#Array that will hold count of null (duplicate) values for each respective query call
duplicateCount =[]

# Go through every element of the possibly correct man-made queries and traverse from that index to the last one before the new man made search
# and find if we have a duplicate link. If we do, mark that indexed value as NULL and count how many NULL we have for every possibly correct index
for index, correctIndex in enumerate(maybe_correct_index):
	# Filter the duplicates that appear:
	tempFiltered = []
	NullValues = 0
	for x in range(correctIndex, (correctIndex + queryLength[index])):
		if siteLink[x] not in tempFiltered:
			tempFiltered.append(siteLink[x])
		else:
			siteLink[x] = None
			siteTimeFormatCorrect[x] = None
			NullValues += 1
	duplicateCount.append(NullValues)


# PART A, PART B AND PART C
# Time to write the output file.
# For each possibly correct link, print the Link, the amount of unique DNS values that follow it (including the man-made query), and the timestamp of the link.
# Then underneath, go through all the links that appear after the link until the next man-made search is made.
outputFile = open('report.txt', 'w')
counter = 0
for index, correctIndex in enumerate(maybe_correct_index):
 	potentiallyCorrectLink = siteLink[correctIndex]
	cleanCorrectLink = potentiallyCorrectLink[:-1]
	# The unique values count (queryLength[index] - duplicateCount[index]) was calculated by taking
	# the original length of links after the man-made query and getting rid of the duplicates.
	outputFile.write('%s: %d Time: %s \n' % (cleanCorrectLink, (queryLength[index] - duplicateCount[index]), siteTimeFormatCorrect[correctIndex]))
	for x in range(correctIndex, (correctIndex + queryLength[index])):
		if siteLink[x] != None:
			counter += 1
			outputFile.write('%d. %s \n' %(counter, siteLink[x][:-1]))
	counter = 0
outputFile.close()

	

