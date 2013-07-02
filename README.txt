Name:           Directory and File Listing Parser and Burp Site Map Importer
Version:        1.0
Date:           7/02/2013
Author:         Smeege
Contact:        SmeegeSec@gmail.com

Description:    This is a Burp Suite extension in Python to parse a directory and file listing text file of a web application.  
                Once the directories and files are parsed a list of URLs is generated based on a couple of parameters given by 
                the user.  After the list of URLs is generated the user can either copy the list and use as desired or choose
                to import the list into Burp's Target Site Map.  By importing the list a request will be made via each URL and
                a proper response will be checked for before adding the request/response pair to Burp's Target Site Map.