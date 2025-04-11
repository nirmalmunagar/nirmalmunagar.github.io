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

[GitHub - thewhiteh4t/seeker](https://github.com/thewhiteh4t/seeker)

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

![Download ngrok page](image.png)

After downloading the file, unzip it. You'll find instructions on the ngrok website about how to unzip it properly.

Now we need to add the AuthToken to our ngrok configuration. You'll see the second option which shows your token:

```bash
./ngrok authtoken <Your AuthToken>
```
