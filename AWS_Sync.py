# vpc To be ran on AWS lambda with data files in S3
#  pip3 install <module> -t ./
#  chmod -R 755 .
#  zip -r ../<name>.zip .

import json
import copy
import requests
import boto3
from time import sleep
from time import time
from time import ctime
# import eventlet
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

storedDataFiles = {
    "/api/config/v1/service/customServices/java": "Data/CustomServices.json",
    "/api/config/v1/service/requestNaming": "Data/RequestNaming.json",
    "/api/config/v1/service/requestAttributes": "Data/RequestAttributes.json",
    "/api/config/v1/autoTags": "Data/AutoTags.json",
    "/api/config/v1/managementZones": "Data/ManagementZones.json",
    "/api/config/v1/anomalyDetection/services": "Data/AnomDetectionServices.json",
    "/api/config/v1/anomalyDetection/applications": "Data/AnomDetectionApps.json",
    "/api/config/v1/anomalyDetection/databaseServices": "Data/AnomDetectionDatabaseServices.json",
    "/api/config/v1/anomalyDetection/hosts": "Data/AnomDetectionHosts.json",
    "/api/config/v1/anomalyDetection/vmware": "Data/AnomDetectionVMware.json",
    "/api/v1.0/onpremise/users/": "Data/Users.json"
}
logFile = "Log/Log.json"

tokenParam = "?Api-Token="
comparisonKey = "name"

# for checking Api limit
callLimit = 50
timeLimit = 60
timeList = []

bucketName = "syncdynatrace"


def lambda_handler(event, context):
    endpoints = []
    for item in event['api']:
        endpoints.append(item['endpoint'])

    global comparisonKey
    for endpoint in endpoints:
        if "/requestNaming" in endpoint:
            comparisonKey = "namingPattern"
        else:
            comparisonKey = "name"

        if endpoint == "/api/v1.0/onpremise/users/":
            Sync(event['clusters'], endpoint)
        else:
            Sync(event['environments'], endpoint)
    return {"done": ctime(time())}


def Sync(environmentsInfo, endpoint):
    start = time()
    bucketData = readData(storedDataFiles[endpoint])  # get data from bucket, used to compare
    print("Get data from Bucket: " + str(str(time() - start)))

    start = time()
    envsDataList = []  # combined list that holds all further data for all environments
    for env in environmentsInfo:
        envsDataList.append(getData(env, endpoint))
    fullEnvsDataList = copy.deepcopy(envsDataList)  # used to keep IDs used for requests deleting
    print("Get data from Dynatrace API: " + str(str(time() - start)))

    start = time()
    # strip data of metadata and id
    if endpoint != "/api/v1.0/onpremise/users/":
        for item in envsDataList:
            stripData(item, endpoint)
    print("strip data of metadata and id: " + str(time() - start))

    start = time()
    # compare and get new items that need to be added
    newItems = []
    updateItems = []
    removedItems = []
    # used to hold the names of items that were updated but not selected because it was selected first in another environment.
    collisionUpdates = []
    for item in envsDataList:
        compareForNewItems(newItems, item, bucketData, endpoint, updateItems, collisionUpdates)
    # print("NEW ITEMS:")
    # print("New Items Length: ", len(newItems))
    print("Compare and get new items that need to be added: " + str(time() - start))
    
    start = time()
    # apply new items to each environment
    for idx, env in enumerate(environmentsInfo):
        EnvAddNewItems(newItems, env, envsDataList[idx], endpoint)
    print("Apply new Items: " + str(time() - start))
    # for item in newItems:
    #     print(item)

    start = time()
    # compare and find items that have been removed
    if endpoint != "/api/v1.0/onpremise/users/":
        if "/anomalyDetection/" not in endpoint:  # deletion not needed for anomaly detection
            for item in envsDataList:
                compareForRemovedItems(removedItems, item, bucketData, endpoint, updateItems)
            # print("REMOVED ITEMS:")
            # print("Removed Items Length: ", len(removedItems))
            
            print("Compare and find items that have been removed: " + str(time() - start))
            start = time()
            
            start = time()
            # apply removed items to each environment
            for idx, env in enumerate(environmentsInfo):
                EnvDeleteRemovedItems(removedItems, env, envsDataList[idx], fullEnvsDataList[idx], endpoint)
            print("Apply removed items to each environment: " + str(time() - start))
            # for item in removedItems:
            #     print(item)

        # Updated items
        # print("UPDATED ITEMS:")
        # print("Updated Items Length: ", len(updateItems))
        # for item in updateItems:
        #     print(item)
        start = time()
        # apply updated items to each environment
        for idx, env in enumerate(environmentsInfo):
            EnvUpdateItems(updateItems, env, envsDataList[idx], fullEnvsDataList[idx], endpoint)
        print("Apply updated items to each environment: " + str(time() - start))

    start = time()
    # update bucket data - new items
    if len(newItems) > 0:
        AddToBucket(bucketData, newItems, endpoint)

    # update bucket data - remove items
    if len(removedItems) > 0:
        RemoveFromBucket(bucketData, removedItems, endpoint)

    # print(updateItems)
    # update bucket data - update items
    if len(updateItems) > 0:
        UpdateToBucket(bucketData, updateItems, endpoint)

    # write to bucket
    writeData(storedDataFiles[endpoint], bucketData)
    
    # Log
    Logs = readData(logFile)
    Logs.append({"time": ctime(time()), "Endpoint": endpoint,  "NEW ITEMS": len(newItems), "UPDATED ITEMS": len(updateItems), "REMOVED ITEMS": len(removedItems), "Collision Updates": ', '.join(collisionUpdates)})
    writeData(logFile, Logs)
    
    print("Update Bucket data: " + str(time() - start))


def printData(data):  # print json/list data in readable format
    print(json.dumps(data, indent=2))


def readData(fileName):  # read information from s3
    s3 = boto3.resource("s3")
    content_object = s3.Object(bucketName, fileName)
    file_content = content_object.get()["Body"].read().decode("utf-8")
    json_content = json.loads(file_content)
    return json_content


def writeData(fileName, data):  # write information to s3
    s3 = boto3.resource("s3")
    s3.Object(bucketName, fileName).put(Body=json.dumps(data))


def getData(env, endpoint):  # two api calls, first to get IDs and names, second to get further details of each.
    data = tryGetRequest(env['url'] + endpoint + tokenParam + env['token']).json()
    # data = requests.get(env['url'] + endpoint + tokenParam + env['token'], verify=False).json()
    count = 0
    result = []
    if "/anomalyDetection/" not in endpoint and endpoint != "/api/v1.0/onpremise/users/":  # anomaly detection doesn't need the second call
        for item in data['values']:
            # ignore management zones starting with @
            if endpoint == "/api/config/v1/managementZones":      
                if "@" in item['name']:
                    continue
            # if SaaS, limit api calls
            if "live.dynatrace.com" in env['url']:
                checkApiLimit()
            requestData = tryGetRequest(env['url'] + endpoint + "/" + item['id'] + tokenParam + env['token']).json()
            # requestData = requests.get(env['url'] + endpoint + "/" + item['id'] + tokenParam + env['token'], verify=False)
            # ignore Ship and Environment tags
            if endpoint == "/api/config/v1/autoTags":       
                if requestData['name'] == "Ship" or requestData['name'] == "Environment":
                    # print("Ignored " + requestData['name'] + " tag")
                    continue
            result.append(requestData)
            # print(requestData)
            count += 1
            # print(count)
    elif endpoint == "/api/v1.0/onpremise/users/":
        return data 
    else:
        result.append(data)
    return result


def stripData(data, endpoint):
    if "/anomalyDetection/" in endpoint:
        for element in data:
            del element['metadata']
    else:
        for element in data:
            del element['metadata']
            del element['id']

def compareForNewItems(newItems, envItem, bucketData, endpoint, updateItems, collisionUpdates):
    for item in envItem:
        if endpoint == "/api/config/v1/autoTags" or endpoint == "/api/config/v1/managementZones":
            for element in item['rules']:  # sort items in propagationTypes due to issue with items returned in mixed order
                if "propagationTypes" in element:
                    element["propagationTypes"].sort()
        if item not in bucketData and item not in newItems:
            if endpoint == "/api/v1.0/onpremise/users/":
                newItems.append(item)
            else:
                # loop through bucket data, compare names to determine if item exists and needs updated
                itemUpdate = False
                for bucketItem in bucketData:
                    if bucketItem['name'] == item['name']:
                        # loop through update items to determine if item had been updated in another environment and was selected.
                        alreadyUpdated = False
                        for updateItem in updateItems:
                            if updateItem['name'] == item['name']:
                                if item['name'] not in collisionUpdates:
                                    collisionUpdates.append(item['name'])
                                alreadyUpdated = True
                                itemUpdate = True
                                break
                        if alreadyUpdated == True:
                            break
                        else:
                            updateItems.append(item)
                            itemUpdate = True
                            break
                if itemUpdate == False:
                    newItems.append(item)

def compareForRemovedItems(removedItems, envItem, bucketData, endpoint, updateItems):
    for item in bucketData:
        if endpoint == "/api/config/v1/autoTags" or endpoint == "/api/config/v1/managementZones":
            for element in item['rules']:  # sort items in propagationTypes due to issue with items returned in mixed order
                if "propagationTypes" in element:
                    element["propagationTypes"].sort()
        if item not in envItem and item not in removedItems:
            # loop through update items, compare names to determine if item exists and was updated
            itemUpdate = False
            for x in updateItems:
                if x['name'] == item['name']:
                    itemUpdate = True
                    break
            if itemUpdate == True:
                pass
            else:
                removedItems.append(item)


def EnvAddNewItems(newItems, env, envsDataList, endpoint):
    for newItem in newItems:
        if newItem not in envsDataList:
            # if SaaS, limit api calls
            if "live.dynatrace.com" in env['url']:
                checkApiLimit()
            if "/anomalyDetection/" in endpoint:
                response = requests.put(env['url'] + endpoint + tokenParam + env['token'], json=newItem, verify=False)
                # print(env['url'])
                # print(response)
            else:
                # print(env)
                # print(newItem[comparisonKey])
                response = requests.post(env['url'] + endpoint + tokenParam + env['token'], json=newItem, verify=False)
                # print("Add")
                # print(response)


def EnvDeleteRemovedItems(removedItems, env, envsDataList, fullDataList, endpoint):
    idList = []  # list of IDs to delete
    for removedItem in removedItems:
        if removedItem in envsDataList:
            for item in fullDataList:  # get the id of the item in order to delete
                if item[comparisonKey] == removedItem[comparisonKey]:
                    idList.append(item['id'])
                    break
    for id in idList:
        if "live.dynatrace.com" in env['url']:  # if SaaS, limit api calls
            checkApiLimit()
        response = requests.delete(env['url'] + endpoint + "/" + id + tokenParam + env['token'], verify=False)
        # print("Remove")
        # print(response)


def EnvUpdateItems(updateItems, env, envsDataList, fullDataList, endpoint):
    idList = []  # list of IDs to update
    updateList = []
    for updatedItem in updateItems:
        if updatedItem not in envsDataList:
            for item in fullDataList:   # get the id of the item in order to update
                if item[comparisonKey] == updatedItem[comparisonKey]:
                    idList.append(item['id'])
                    updateList.append(updatedItem)
                    break
    for id, item in zip(idList, updateList):
        if "live.dynatrace.com" in env['url']:  # if SaaS, limit api calls
            checkApiLimit()
        response = requests.put(env['url'] + endpoint + "/" + id + tokenParam + env['token'], json=item, verify=False)
        # print("Update")
        # print(env['url'])
        # print(response)


def AddToBucket(bucketData, newItems, endpoint):
    for item in newItems:
        bucketData.append(item)


def RemoveFromBucket(bucketData, removedItems, endpoint):
    for item in removedItems:
        bucketData.remove(item)


def UpdateToBucket(bucketData, updatedItems, endpoint):
    removeItems = []
    addItems = []
    for item in updatedItems:
        # loop through bucket data to find matching item to be updated
        for index, bucketItem in enumerate(bucketData):
            if bucketItem['name'] == item['name']:
                bucketData[index] = item
                # removeItems.append(bucketItem)
                # addItems.append(item)

    # for item in removeItems:
    #     bucketData.remove(item)
    # for item in addItems:
    #     bucketData.append(item)


def checkApiLimit():
    if len(timeList) >= callLimit:
        sleepTime = timeLimit - (timeList[-1] - timeList[0])
        if sleepTime > 0:
            # print("Sleeping", sleepTime)
            sleep(sleepTime)
        timeList.pop(0)
        timeList.append(time())
    else:
        timeList.append(time())

def tryGetRequest(url):
    connectTimeout = 10
    readTimeout = 10
    eventletTimeout = 15
    try:
        # valudate this code
        # with eventlet.Timeout(eventletTimeout, False):
        #     data = requests.get(url, timeout=(connectTimeout, readTimeout))
        data = requests.get(url, timeout=(connectTimeout, readTimeout), verify=False)
        if data is None:
            # print("Eventlet timeout")
            quit()
        if data.status_code != 200:
            # print("Bad response")
            quit()
        return data
    except Exception as e:
        # print(e)
        # print("Timeout")
        quit()
