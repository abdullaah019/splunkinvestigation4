<h1>Splunk Investigation 4 Lab</h1>



<h2>Description</h2>
Security Information and Event Monitoring
Using Splunk SIEM
Lab) Splunk Investigation 4 Solution<br />


<h2>Languages and Utilities Used</h2>

- <b>PowerShell</b> 
- <b>Splunk</b>

<h2>Environments Used </h2>

- <b>Windows 10</b> 

<h2>Program walk-through </h2>


Question 1 - Click on Dashboards and go to Splunk Investigation 4. How many Suricata alerts are there, and how many Fortigate alerts are there?

 ![image](https://github.com/abdullaah019/splunkinvestigation4/assets/139023222/694d6d69-29ac-4f97-8421-59b700c826b8)


First we'll click on Search & Reporting App, then Dashboards at the top of the page. At the top of the Splunk Investigation 4 dashboard we can see two panels being used as counters for both Fortigate alerts and Suricata alerts.

Question 2 - Edit the dashboard and look at the search query for the Fortigate Alerts counter. What is the full query used to generate this number?

To see the search queries that are powering dashboard panels we first need to Edit the dashboard in the top right corner. Then we can click on the magnifying glass icon of a panel, which is the ‘Edit Search’ option.

 ![image](https://github.com/abdullaah019/splunkinvestigation4/assets/139023222/2f877deb-820e-4611-8943-7518f8ed2a94)


Question 3 - What is the full query used to generate the Suricata Alerts counter?

We'll take the same actions as we did for Q2, and click the magnifying glass icon on the Suricata Alerts counter panel to see the search query behind it.

 ![image](https://github.com/abdullaah019/splunkinvestigation4/assets/139023222/2acd7a74-071f-4344-9372-c1683c67c0ca)


Question 4 - Click on the Suricata alert titled 'Information Leak' to see the associated events. What is the source IP address, and what is the destination IP address?

We can find this alert category on Line 6 of the Suricata Alerts (Categories) table.

 ![image](https://github.com/abdullaah019/splunkinvestigation4/assets/139023222/c860c0bc-0836-4c54-86aa-fcc20b2f2abf)


Looking at the 2 events, we can see the dest_ip and src_ip are shown immediately, giving us our answer. The external IP 40.80.148.42 is connecting to our internal system which is hosted internally on 192.168.250.70 on port 80 (HTTP).

 ![image](https://github.com/abdullaah019/splunkinvestigation4/assets/139023222/1119ca59-252b-4ad5-b6c5-633e24072c26)


Question 5 - What action did Suricata take after observing these events?

Just looking at the events in the screenshot above, we cannot see any fields that would tell me what actions Suricata took, so we'll click on 'Show as raw text' at the bottom of each event to change the displayed format. We can now see a field called ‘action’!

 ![image](https://github.com/abdullaah019/splunkinvestigation4/assets/139023222/f1e008d8-4637-4d31-bb59-5a511d4bfdd7)


In this case, both events were allowed by Suricata. If this tool is deployed in Network Intrusion Prevention System mode (NIPS) as opposed to Network Intrusion Detection System (NIDS) then it could take actions to stop malicious connections, such as applying the ‘block’ action to end the connection!

Question 6 - We know the alert category is 'Information Leak', however the specific signature can provide us with more information about this activity. What is the signature shared by both events?

In the below screenshot, we have showed two different ways to view this field within the Suricata logs. This signature is a lot less generic than the category, and can provide context to what is actually happening.

 ![image](https://github.com/abdullaah019/splunkinvestigation4/assets/139023222/807b0038-42f8-42a0-9290-c6da3f8b0594)


Question 7 - Based on the logs, combine two fields to understand the full website addresses being accessed by the attacker (Remember, in some logs a "/" character must be escaped by putting a "\" in front of it. You should not reference the "\")

Looking at the logs we can see two fields that will help us answer this question: hostname and URL. Using these we can see the two targeted full URLs were:

imreallynotbatman.com/phpinfo.php5
imreallynotbatman.com/phpinfo.php

 ![image](https://github.com/abdullaah019/splunkinvestigation4/assets/139023222/df2f8fea-05c3-48e0-88e7-20be4d416631)


Question 8 - What HTTP status code is returned to both of these requests, that tells us this attack was not successful?

Looking at the logs we can see a field named ‘status’, where the value is 404 for both event. This tells us that the attacker tried to reach these URLs, but there is nothing there (Error 404, Not Found).

 ![image](https://github.com/abdullaah019/splunkinvestigation4/assets/139023222/f65d98ad-5852-4274-b2fa-e8d5e5d2fc08)


Question 9 - Return to the Dashboard and click on the Suricata alert titled 'A Network Trojan was detected' to load this search. Modify the search query to show count of every signature field within this alert category. How many unique suricata signatures are present?

Looking at the Suricata Security Alerts (Categories) table we can see the category we want on line 3.

 ![image](https://github.com/abdullaah019/splunkinvestigation4/assets/139023222/8cdb20d9-6448-4221-bf79-f5dbbc86fa5c)


We're being asked to identify how many signatures are found within this category of alerts. To do this we'll add the following to our search query to get the count of signature values: | stats count by signature. Looking at the Statistics title, we can see there are 12 unique signatures that have been observed within logs for this category.

 ![image](https://github.com/abdullaah019/splunkinvestigation4/assets/139023222/7ed13217-3f2d-4365-a4d7-b7f268e7a03a)


Question 10 - Search manually through Suricata logs where the HTTP status code is 200, then perform a count of each signature field to find two signatures that reference a vulnerability CVE identifier. Search this CVE on the National Vulnerability Database.- what is the CVSS Version 3 Score?

Okay - there's a lot to do in this question, so let's go step by step. Firstly we'll build our brand new search query for Suricata logs, specifically alert logs, where the status code is 200. The query will look like this: index="botsv1" sourcetype=suricata event_type=alert status=200.

 ![image](https://github.com/abdullaah019/splunkinvestigation4/assets/139023222/18c800ee-b454-48ac-8e78-67adbeded161)


Great, next we need to get the count of values in the signature field. We'll add the following to our search: | stats count by signature.

 ![image](https://github.com/abdullaah019/splunkinvestigation4/assets/139023222/a4853c47-0b10-408d-a1e0-99f236bf59e6)


Great, we've found the reference to a Common Vulnerability and Exposures identifier, used as an identification method for vulnerabilities. Next we're asked to find the score of this vulnerability, so we'll search for it on Google using the search “CVE-2014-6271 national vulnerability database”.

 ![image](https://github.com/abdullaah019/splunkinvestigation4/assets/139023222/0d3083ff-f16b-47a1-9557-4e0a72299471)

  ![image](https://github.com/abdullaah019/splunkinvestigation4/assets/139023222/d0236d13-bbeb-416e-b197-428acd336104)



Question 11 - On the Fortigate Security Alerts dashboard table click on 'MS.Windows.CMD.Reverse.Shell'. Identify the internal IP within this event, and use your SIEM skills to identify the name of this system.

We can find the associated Fortigate alert category on the final row (13) of the dashboard table.

 ![image](https://github.com/abdullaah019/splunkinvestigation4/assets/139023222/e96e448f-0781-4e81-9e77-07e305d36b1b)


Clicking on the row will take us to a single Fortigate_UTM log. We can see that the internal IP address is in the ‘dstip’ field, and is 192.168.250.70. Because this log is from a Firewall, Fortigate has no idea what the hostname is for this system, so we'll need to use a different log source to find this.

 ![image](https://github.com/abdullaah019/splunkinvestigation4/assets/139023222/d4d5eaf1-d868-4102-bd02-f31dcbcf9f49)


Let's be smart about this, this alert is about abuse of the Microsoft Windows Command Prompt. It is possible that the internal system is running Windows, and should have Sysmon logs enabled (xmlwineventlog). Let's change our search query to look at that sourcetype and free-search the IP (without declaring a field name, as we don't know what format it will be).

 ![image](https://github.com/abdullaah019/splunkinvestigation4/assets/139023222/f4d3ddc7-007b-4b28-8d7e-e3fe4d08a5d2)


Question 12 - Go back to the Fortigate Security Events table and click on 'Apache.Roller.OGNL.Injection.Remote.Code.Execution'. Find the reference field in the log and open the URL on your host machine. What is the Affected Products text, and the CVE identifier?

We can find the relevant Fortigate alert category on the 10th row of the dashboard table.

 ![image](https://github.com/abdullaah019/splunkinvestigation4/assets/139023222/5faca281-9ac6-4b6a-a32d-8fddacfa6c5f)


Looking at the event we can see there is a field titled ‘ref’ which contains a URL.

 ![image](https://github.com/abdullaah019/splunkinvestigation4/assets/139023222/0287a0e6-476a-4cee-b0aa-f3097bf3f3a1)


Unfortunately, when trying to visit the URL, we get redirected to FortGuard's homepage. In the top right we can see there is a search bar, and clicking on it offers us the ability to change it to an ‘ID Lookup’ search. Let's try that with our VID number!

 ![image](https://github.com/abdullaah019/splunkinvestigation4/assets/139023222/078f4674-6f04-46c9-991c-af0d9cfaa5bd)


Next we want to click on the right search result, based on the name of the category we saw in Splunk:

Here we can find all the information we need


