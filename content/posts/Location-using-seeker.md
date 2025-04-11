---
title: "Get Anyone’s Location Using Seeker"
date: 2021-09-04T00:00:00+05:30
draft: false
author: "Nirmal 🇮🇳"
description: "Learn how to accurately locate smartphones using the Seeker tool with social engineering techniques."
categories: ["Cybersecurity"]
tags: ["Hacking", "Hacking Tools", "Info Sec"]
---

Hello Folks, I am Nirmal Unagar

Today I am writing my first blog so please bear with me for my English skills :)

In this blog, I will tell you how to get anyone's location using the tool Seeker. Without further ado, let's start...

![Photo by Lagos Techie on Unsplash](images/seeker-location-tool.jpg)

I'm dividing this blog into different steps so you can follow along easily.

## Step 1: Download and Install Seeker

First, you need to download the Seeker tool from the link below:

```bash
git clone https://github.com/thewhiteh4t/seeker.git
```

### How To Install:

**Ubuntu/Debian/Kali/Parrot:**
```bash
git clone https://github.com/thewhiteh4t/seeker.git
cd seeker/
apt update
apt install python3 python3-pip php
pip3 install requests
```


## Step 2: Setup ngrok for Server

Now we need to setup ngrok for the server. Go to [ngrok.com](https://ngrok.com/) and sign up.

After signing up, you'll get this page where you can download ngrok according to your operating system:


{{< figure src="images/Seeker/img1.webp" alt="Security Guide" class="text-center" >}}

After downloading the file, unzip it. You'll find instructions on the ngrok website about how to unzip it properly.

Now we need to add the AuthToken to our ngrok configuration. You'll see the second option which shows your token:

```bash
./ngrok authtoken <Your AuthToken>
```

Now We done All Configuration Let’s do Practical

## Step 3: 

Go to Seeker Directory

{{< figure src="images/Seeker/img2.webp" alt="Security Guide" class="text-center" >}}

If seeker.py file doesn’t have execute permission then set using Below cmd
```bash
# chmod +x seeker.py
```
Now Run…

```bash
#./seeker.py -t manual
```

{{< figure src="images/Seeker/img3.webp" alt="Security Guide" class="text-center" >}}


## Step 4
Go to Directory Where ngrok is unzipped and run below command

{{< figure src="images/Seeker/img4.webp" alt="Security Guide" class="text-center" >}}

After You will Get like This

{{< figure src="images/Seeker/img5.webp" alt="Security Guide" class="text-center" >}}

Copy Forwarding Link and send to Victim using Phishing or Any Social Engineering Methods

Eg. https://e078-49-34-114-151.ngrok.io


## Step 5
Now We Are in Victim Side, Once Victim Click on the Link Then it will look like This

{{< figure src="images/Seeker/img6.webp" alt="Security Guide" class="text-center" >}}

When Victim Click On Continue, Webpage Take Permission So Allow it

“Note : Mostly People Don’t Notice What is Permission and people Easily allow it”

{{< figure src="images/Seeker/img7.webp" alt="Security Guide" class="text-center" >}}


## Step 6
Now Coming Back To Hacker’s Terminal(seeker’s)


{{< figure src="images/Seeker/img8.webp" alt="Security Guide" class="text-center" >}}

You will Get Many Information About Victim but We need Only Google Maps Links So Copy Link and Open it on Browser

Boom You will See Victim Live Location

So,Thank You For Your Time

