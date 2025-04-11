
Search
Write
Sign up

Sign in



Top highlight

Get Anyone’s Location Using Seeker
Nirmal 🇮🇳
Nirmal 🇮🇳

·
Follow

3 min read
·
Sep 4, 2021
142


3



Hello Folks, I am Nirmal Unagar

Today i am Writing My First Blog so Please Bear With me For My English Skill :)

In This blog, I will Tell You How to Get Anyone's Location Using Tool seeker, so without further do let’s start…


Photo by Lagos Techie on Unsplash
I Am Dividing This Blog Into Different Different Steps So You can Going Through Flow

STEP : 1
First You Need To Download seeker Tools, So Download From Below Link

GitHub - thewhiteh4t/seeker: Accurately Locate Smartphones using Social Engineering
Available in Concept behind Seeker is simple, just like we host phishing pages to get credentials why not host a fake…
github.com

How To Install :
Ubuntu/Debian/Kali/Parrot -

#git clone https://github.com/thewhiteh4t/seeker.git
#cd seeker/
#apt update
#apt install python3 python3-pip php
#pip3 install requests

Blackarch Linux -

#pacman -S seeker

After installing Completed go to down…

STEP : 2
Now We Need To Setup ngrok for server so Go to https://ngrok.com/ and Signup.

After You will Get This Page So Download ngrok According to Your OS


After Do Unzip downloaded File, You will find Step in below page How To Unzip


Now We Need To Add AuthToken in our ngrok Configuration So You will See Second Option Which is Show Your Token

$ ./ngrok authtoken <Your AuthToken>

Now We done All Configuration Let’s do Practical

STEP : 3
Go to Seeker Directory


If seeker.py file doesn’t have execute permission then set using Below cmd

# chmod +x seeker.py

Now Run…

#./seeker.py -t manual


Select [0] After Server Will Start

STEP : 4
Go to Directory Where ngrok is unzipped and run below command


After You will Get like This


Copy Forwarding Link and send to Victim using Phishing or Any Social Engineering Methods

Eg. https://e078-49-34-114-151.ngrok.io

STEP : 5
Now We Are in Victim Side, Once Victim Click on the Link Then it will look like This


When Victim Click On Continue, Webpage Take Permission So Allow it

“Note : Mostly People Don’t Notice What is Permission and people Easily allow it”


STEP : 6
Now Coming Back To Hacker’s Terminal(seeker’s)


You will Get Many Information About Victim but We need Only Google Maps Links So Copy Link and Open it on Browser

Boom You will See Victim Live Location

So,Thank You For Your Time

If You like This Blog Then Share it

You can connect me on Twitter : https://twitter.com/Nirmalunagar

Linkedin : https://www.linkedin.com/in/nirmalmprajapati/

Cybersecurity
Hacking
Hacking Tools
Info Sec Writeups
142


3


Nirmal 🇮🇳
Written by Nirmal 🇮🇳
24 Followers
·
18 Following
🔐 Cybersecurity Enthusiast | Master's Student @ University of Greenwich 🎓 Pursuing a Cybersecurity Master's Degree | Class of 2023

Follow

Responses (3)

Write a response

What are your thoughts?

Cancel
Respond
Noder_SS
Noder_SS

Nov 4, 2022


Doesn't work :/ who can help?
Reply

mr.smashy
mr.smashy

Sep 13, 2021


This will only fool stupid people. I don’t even have location services enabled on my phone, and I still use an app to set a mock location (location spoofing). Any app or site that asks for any permissions gets intense scrutiny. Anyone I’m trying to track is probably not as good as me, but definitely isn’t stupid.
Reply

Harsh Patel
Harsh Patel

Sep 4, 2021


Informative article! Please do more like this so we can get intro to cyber security.
Reply



