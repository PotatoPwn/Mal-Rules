import Utils.Algorithms.TripleDes

def FindData(Offset, FileName):
	with open(FileName, "rb") as file:
		file.seek(Offset)
		Data = file.read(0xc0)
		Results = Data.split(b'\x00')
		CleanedResults = [items for items in Results if items != b'']

		file.close()

		return CleanedResults

def GetKeys(Results):
	IV = Results[4]
	# Arrange Key

	SubKey3 = Results[5]
	SubKey2 = Results[6]
	SubKey1 = Results[7]

	Key = SubKey1 + SubKey2 + SubKey3

	return IV, Key

def GetEndpoints(Results):
	EndpointArray = [Results[0], Results[1], Results[2], Results[3]]

	return EndpointArray



def LokiBotConfigExtraction(FileName):
	Offset = 0x174d0
	#FileName = "LokiBotbotExe.bin"

	Results = FindData(Offset, FileName)

	IV, Key = GetKeys(Results)

	EndPointArray = GetEndpoints(Results)

	# CBC Routine
	Des = TripleDes.triple_des(Key, TripleDes.CBC, IV)
	
	ResultArray = []

	for item in EndPointArray:
		Result = Des.decrypt(item).decode("utf-8")
		ResultArray.append(Result)

	return ResultArray
