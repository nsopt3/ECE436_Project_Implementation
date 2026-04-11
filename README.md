# ECE436_Project_Implementation
 ## Netwrok traffic measurement and analysis
### **This is the official README of group 15's project implementation using wireshark and python!**

**Background:**
Understanding network behavior often relies on passive measurement and traffic analysis rather than direct control.

**Objective:**
Analyze real or simulated packet traces to understand traffic composition and network behavior.

**Tools**
• Wireshark
• Python (for analysis)

**Required Tasks**
• Capture or generate packet traces
• Extract timing and size features
• Analyze protocol and application behavior

**Metrics**
• Flow duration
• Packet size distribution
• Inter-arrival times

**Extension**
• DNS or HTTP/HTTPS behavior study

---

## **Here's our general project layout / outline:**
The implementation part doesn’t seem too bad. It looks like we are just capturing data packets, extracting the data, and analyzing the packets. Now, it’s best that we split this into 4 parts.

**Part 1 - Data collection**

Literally open wireshark and generate some traffic like streaming a 4K youtube video, download an app, etc. 
We can then save the trace so that the python script can analyze it.
We have to save that wireshark trace as a **.pcap** or **.pcapng** file so that the python script can read through it.

**Part 2 - Parse all the data**

I did some digging around on the internet and found that there exists a cool python plugin for wireshark that can parse a lot of the data for us. 
- **Pyshark - It’s essentially a python wrapper for wireshark’s parsing engine.**

Pyshark can extract important data from the wireshark trace and append them to a **Pandas** dataframe.
Using that dataframe, we can calculate the metrics needed for part 3.


**Part 3 - Get all the metrics**

Once we get all the data appended to the pandas dataframe, we have to plot the data on to a graph.
We’d most likely have to plot that data as a histogram to visually see all the data packet sizes from our scan.
The python script has a function called **matplotlib** that can plot any one of our desired data points.
- **pandas.Series.diff()** is another function that can find the exact difference between each packet. 
    -  We will need this for the inter-arrival times part.

**Part 4 - Picking out extension**
- HTTP/HTTPS or DNS behavior study:
    - Clear DNS cache and start a fresh wireshark capture
    - Start streaming some videos, music, or anything complex
    - In the python analysis, we can filter for DNS (most likely port 53)
    - We can map out all the domains the computer had to resolve before actually loading the website
    - In the python analysis, we can filter for HTTP traffic as well. (most likely port 443?) 
    - We can then map out the volume of data exchanged with those IP addresses. 
---
## To do:
- ~~Part 1: Collect data~~ 
    - [x] [COMPLETE]
    <br>
- ~~Part 2: Parse all the data~~ 
    - [x] [COMPLETE]
    <br>
- ~~Part 3: Calculate all the metrics~~ 
    - [x] [COMPLETE]
    <br>
- ~~Part 4: HTTP/HTTPS or DNS Behavior study~~ 
    - [x] [COMPLETE]
    <br>
- Part 5: 3 Page report on implementation part of project 
    - [ ] [INCOMPLETE]

