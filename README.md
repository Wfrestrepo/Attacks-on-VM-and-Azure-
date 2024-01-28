<h1>Azure VM exposed to the internet.</h1>


<h2>Description</h2>
<b>The main purpose is to identify the attacks through Microsoft Sentinel and Logs Analytics. We will run a script on PowerShell ISE and make use of an API to identify the IP addresses and the location. By the end of the project, we could be able to see the attacks in a Map and recognise the source of them.
</b>
<br />
<br />
<b>Create a new resource called “Honeypot”. Give a name to your VM, and select the OS, in this case, Windows. Networking section go to NIC network security group and select advance. Delete the existing rule and create a new one, allowing all the traffic without restrictions.</b>

<br />
<br />

![NIC rules](https://github.com/Wfrestrepo/Attacks-on-VM-and-Azure-/assets/108705302/22ed0364-957f-4119-8a41-0ede57289066)

<b>Go to Logs analytics and create a new one. Make sure you select the resource group.
Microsoft Defender For Cloud > Environment SettingsDefender plans to choose Servers and turn off the rest. Data collection, select all the events.<b/>
<b>Now, let’s connect the logs analytics and our VM. Add the log analytics to Microsoft Sentinel.
<b/>

<br />
<br />

![Conecting vm to log](https://github.com/Wfrestrepo/Attacks-on-VM-and-Azure-/assets/108705302/c9587e73-89fd-418a-81ff-e01ff39d0178)

<b>From here, we need to connect to our VM through our physic machine and RDP. Create an account on ipgeolocation, and take the API key. We will use it in our script.<b/>

<br />
<br />

![account ip](https://github.com/Wfrestrepo/Attacks-on-VM-and-Azure-/assets/108705302/cfe6fc92-04d3-400f-9168-7cd7091ebb22)

<b>I did this project and took the script from, @joshmakador1. The link below is the script.<b/>
<b>https://github.com/joshmadakor1/Sentinel-Lab/blob/main/Custom_Security_Log_Exporter.ps1<b/>
<b>Basically, will take the info from the attacks in our VM, identify it with the API, then move it to Logs analytics and then parse it on Microsoft Sentinel.<b/>

<br />
<br />

![change values on script](https://github.com/Wfrestrepo/Attacks-on-VM-and-Azure-/assets/108705302/cd325c38-2940-40c3-acaf-39bb4083090b)

<b>Create a notepad on the VM to add the logs collected. Run the script on the VM in PowerShell ISE. Remember to change the API key and the name of the file to collect the logs.
Go to Logs analytics and create a new table, Select Windows and the path of your notepad in the VM. Example FAILED_RDP_GEO.<b/>

<br />
<br />

![script with values](https://github.com/Wfrestrepo/Attacks-on-VM-and-Azure-/assets/108705302/806063ec-95d7-4178-8188-2a6e0722e108)

<br />

![attacks on sentinel](https://github.com/Wfrestrepo/Attacks-on-VM-and-Azure-/assets/108705302/8e8d3b08-86e1-4f81-8931-b30b767ef25c)

<b>-	Go to Sentinel and run the Query created as a name in the table “FAILED_RDP_GEO”.
-	In Sentinel select and create a Workbook.
-	Delete all in new Workbook. Create a new query and run the next script to parse the info from the RawData:
-	FAILED_RDP_GEO_CL
-	
-	 |extend username = extract(@"username:([^,]+)", 1, RawData),
-	
-	         timestamp = extract(@"timestamp:([^,]+)", 1, RawData),
-	
-	         latitude = extract(@"latitude:([^,]+)", 1, RawData),
-	
-	         longitude = extract(@"longitude:([^,]+)", 1, RawData),
-	
-	         sourcehost = extract(@"sourcehost:([^,]+)", 1, RawData),
-	
-	         state = extract(@"state:([^,]+)", 1, RawData),
-	
-	         label = extract(@"label:([^,]+)", 1, RawData),
-	
-	         destination = extract(@"destinationhost:([^,]+)", 1, RawData),
-	
-	         country = extract(@"country:([^,]+)", 1, RawData)
-	
-	 |where destination != "samplehost"
-	
-	 |where sourcehost != ""
-	
-	 |summarize event_count=count() by timestamp, label, country, state, sourcehost, username, destination, longitude, latitude <b/>

<br />
<br />

<b>Change the visualization to Map, and change the settings according to the info. Leave the VM on and the script running for a couple of hours or days. You will end up with something like this.<b/>

<br />
<br />

![running attacks 1](https://github.com/Wfrestrepo/Attacks-on-VM-and-Azure-/assets/108705302/8c10c9ed-3526-4f05-8728-e67672e5970a)

<b>I leave my VM running for a couple an hours but you can see all the attacks from different parts of the world.<b/>
















