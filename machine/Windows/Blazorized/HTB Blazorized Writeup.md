# 概要



| IP   | 10.10.11.22 |
| :--- | ----------- |

![](screenshot/Blazorized.png)

# Enumeration

## nmap

```
# Nmap 7.94SVN scan initiated Mon Jul  1 18:42:12 2024 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN /home/hatto/CTF/HTB/machine/Windows/Blazorized/results/10.10.11.22/scans/_full_tcp_nmap.txt -oX /home/hatto/CTF/HTB/machine/Windows/Blazorized/results/10.10.11.22/scans/xml/_full_tcp_nmap.xml 10.10.11.22
Increasing send delay for 10.10.11.22 from 0 to 5 due to 328 out of 819 dropped probes since last increase.
Increasing send delay for 10.10.11.22 from 5 to 10 due to 11 out of 24 dropped probes since last increase.
adjust_timeouts2: packet supposedly had rtt of -60709 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -60709 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -79350 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -79350 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -104503 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -104503 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -133399 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -133399 microseconds.  Ignoring time.
Nmap scan report for 10.10.11.22
Host is up, received user-set (0.15s latency).
Scanned at 2024-07-01 18:42:13 JST for 1325s
Not shown: 65510 closed tcp ports (reset)
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://blazorized.htb
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2024-07-01 09:53:39Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
1433/tcp  open  ms-sql-s      syn-ack ttl 127 Microsoft SQL Server 2022 16.00.1115.00; RC0+
|_ssl-date: 2024-07-01T09:57:01+00:00; -7m14s from scanner time.
| ms-sql-ntlm-info: 
|   10.10.11.22\BLAZORIZED: 
|     Target_Name: BLAZORIZED
|     NetBIOS_Domain_Name: BLAZORIZED
|     NetBIOS_Computer_Name: DC1
|     DNS_Domain_Name: blazorized.htb
|     DNS_Computer_Name: DC1.blazorized.htb
|     DNS_Tree_Name: blazorized.htb
|_    Product_Version: 10.0.17763
| ms-sql-info: 
|   10.10.11.22\BLAZORIZED: 
|     Instance name: BLAZORIZED
|     Version: 
|       name: Microsoft SQL Server 2022 RC0+
|       number: 16.00.1115.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RC0
|       Post-SP patches applied: true
|     TCP port: 1433
|_    Clustered: false
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 3072
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-07-01T04:50:50
| Not valid after:  2054-07-01T04:50:50
| MD5:   b4b4:9921:3d12:afb2:c637:1538:ad30:7fa9
| SHA-1: a2d6:81ea:0a5e:9837:4ccc:2664:c875:d948:5304:d3c6
| -----BEGIN CERTIFICATE-----
| MIIEADCCAmigAwIBAgIQGc4e/XIFbYJMBrvs7/2N7zANBgkqhkiG9w0BAQsFADA7
| MTkwNwYDVQQDHjAAUwBTAEwAXwBTAGUAbABmAF8AUwBpAGcAbgBlAGQAXwBGAGEA
| bABsAGIAYQBjAGswIBcNMjQwNzAxMDQ1MDUwWhgPMjA1NDA3MDEwNDUwNTBaMDsx
| OTA3BgNVBAMeMABTAFMATABfAFMAZQBsAGYAXwBTAGkAZwBuAGUAZABfAEYAYQBs
| AGwAYgBhAGMAazCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAM2icENs
| iuGpb04xPjwYEnPEFLaMDVrT4zSKpDOCg0tfZcP2sXSg6jS3FOlHeOjw5uhSMxau
| z+niSRYmgAfQJODeaivVUxXIj6oZqhN1AdUnatHFAxe+AEGsrXHNZuOD9y6R1ktr
| HR0Dgn59wwHU93Xv/HIlM2zcpA7ZoaXhdd2i+UWZw0j5xwrviVKZZFAim/HF45Ej
| xLCOHklqp7GX/OiIMGFX7V94hI7qQIQttwKOlgNTRxaJ259cQkXvD+OwG4QKTC43
| dG8GRn9fDG1YotERDjZkByvCl+TO/TUbPd4NwEXGW9mzbwcem0HVPnWmoocOtb3G
| QBZZPVW28g431N4CqsNd7/oTxjDgntr0RaAByFweREWL0bcj1HGXqM7n70s/T0og
| 1A2EItjodA+b1DpI9zKaBdxZoo1R3autRXdrM1IuO9d0YIj/LNyAnani0NeobsL+
| nAoaJwiUDgFcK9yOOzxGO1gG3dWtDS2Qr8hKVn2uDO2DSEr5nn+C/GVPEQIDAQAB
| MA0GCSqGSIb3DQEBCwUAA4IBgQB57WwxZ/Gn2dL4u73waDTC/OQjXYeXDvI3s8CS
| sf1oarvloqh+CMaQXrdxGAr9Q+HDg4TjTbITglBljleZ0xXhGbQ+8hWWPp00A5bq
| q04M62ekeCaW75V/lr2NTV2iEFmByN1ucesYPrVy2STHq8hMC9jNK4Yx2x7XMt40
| THEJJPzVsj3aTIoBt9+QlWwUOIqIhXmSpXJYSXx43b7rLJdoiLCfx1FnRIBzTm/h
| eSJ3vE1JYqA4yOHlZjfrZTispp5AwOiVeOKKSUPPOEg7ejw28kqoPzefH7oQrmuK
| SagHCTZ2Apbjwi39QCfGwXDGRlM2V7CXGL2c6Vpr9OP+LnuVQm3qcJJpJQegj6LX
| j4CxrnzLPaM/sJWl4WsiJQCWOhj7Kaxzd7FB9jBeZQCy0VeWtKtxoCqRUd+21RVC
| pWbvOQERGiuPBCY8jycFFUwCXIIzCSAvv/AsnAYl1Fl6ftrtf0IDZR1DRJGdfm9F
| Bv+Z2AbNEgP/WI946vjh2FTzStY=
|_-----END CERTIFICATE-----
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: blazorized.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49670/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49671/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49672/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49677/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49776/tcp open  ms-sql-s      syn-ack ttl 127 Microsoft SQL Server 2022 16.00.1115.00; RC0+
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 3072
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-07-01T04:50:50
| Not valid after:  2054-07-01T04:50:50
| MD5:   b4b4:9921:3d12:afb2:c637:1538:ad30:7fa9
| SHA-1: a2d6:81ea:0a5e:9837:4ccc:2664:c875:d948:5304:d3c6
| -----BEGIN CERTIFICATE-----
| MIIEADCCAmigAwIBAgIQGc4e/XIFbYJMBrvs7/2N7zANBgkqhkiG9w0BAQsFADA7
| MTkwNwYDVQQDHjAAUwBTAEwAXwBTAGUAbABmAF8AUwBpAGcAbgBlAGQAXwBGAGEA
| bABsAGIAYQBjAGswIBcNMjQwNzAxMDQ1MDUwWhgPMjA1NDA3MDEwNDUwNTBaMDsx
| OTA3BgNVBAMeMABTAFMATABfAFMAZQBsAGYAXwBTAGkAZwBuAGUAZABfAEYAYQBs
| AGwAYgBhAGMAazCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAM2icENs
| iuGpb04xPjwYEnPEFLaMDVrT4zSKpDOCg0tfZcP2sXSg6jS3FOlHeOjw5uhSMxau
| z+niSRYmgAfQJODeaivVUxXIj6oZqhN1AdUnatHFAxe+AEGsrXHNZuOD9y6R1ktr
| HR0Dgn59wwHU93Xv/HIlM2zcpA7ZoaXhdd2i+UWZw0j5xwrviVKZZFAim/HF45Ej
| xLCOHklqp7GX/OiIMGFX7V94hI7qQIQttwKOlgNTRxaJ259cQkXvD+OwG4QKTC43
| dG8GRn9fDG1YotERDjZkByvCl+TO/TUbPd4NwEXGW9mzbwcem0HVPnWmoocOtb3G
| QBZZPVW28g431N4CqsNd7/oTxjDgntr0RaAByFweREWL0bcj1HGXqM7n70s/T0og
| 1A2EItjodA+b1DpI9zKaBdxZoo1R3autRXdrM1IuO9d0YIj/LNyAnani0NeobsL+
| nAoaJwiUDgFcK9yOOzxGO1gG3dWtDS2Qr8hKVn2uDO2DSEr5nn+C/GVPEQIDAQAB
| MA0GCSqGSIb3DQEBCwUAA4IBgQB57WwxZ/Gn2dL4u73waDTC/OQjXYeXDvI3s8CS
| sf1oarvloqh+CMaQXrdxGAr9Q+HDg4TjTbITglBljleZ0xXhGbQ+8hWWPp00A5bq
| q04M62ekeCaW75V/lr2NTV2iEFmByN1ucesYPrVy2STHq8hMC9jNK4Yx2x7XMt40
| THEJJPzVsj3aTIoBt9+QlWwUOIqIhXmSpXJYSXx43b7rLJdoiLCfx1FnRIBzTm/h
| eSJ3vE1JYqA4yOHlZjfrZTispp5AwOiVeOKKSUPPOEg7ejw28kqoPzefH7oQrmuK
| SagHCTZ2Apbjwi39QCfGwXDGRlM2V7CXGL2c6Vpr9OP+LnuVQm3qcJJpJQegj6LX
| j4CxrnzLPaM/sJWl4WsiJQCWOhj7Kaxzd7FB9jBeZQCy0VeWtKtxoCqRUd+21RVC
| pWbvOQERGiuPBCY8jycFFUwCXIIzCSAvv/AsnAYl1Fl6ftrtf0IDZR1DRJGdfm9F
| Bv+Z2AbNEgP/WI946vjh2FTzStY=
|_-----END CERTIFICATE-----
|_ssl-date: 2024-07-01T09:57:01+00:00; -7m14s from scanner time.
| ms-sql-ntlm-info: 
|   10.10.11.22:49776: 
|     Target_Name: BLAZORIZED
|     NetBIOS_Domain_Name: BLAZORIZED
|     NetBIOS_Computer_Name: DC1
|     DNS_Domain_Name: blazorized.htb
|     DNS_Computer_Name: DC1.blazorized.htb
|     DNS_Tree_Name: blazorized.htb
|_    Product_Version: 10.0.17763
| ms-sql-info: 
|   10.10.11.22:49776: 
|     Version: 
|       name: Microsoft SQL Server 2022 RC0+
|       number: 16.00.1115.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RC0
|       Post-SP patches applied: true
|_    TCP port: 49776
49783/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Aggressive OS guesses: Microsoft Windows Server 2019 (96%), Microsoft Windows Server 2016 (93%), Microsoft Windows 10 1709 - 1909 (92%), Microsoft Windows Server 2012 (92%), Microsoft Windows Vista SP1 (91%), Microsoft Windows Longhorn (91%), Microsoft Windows Server 2012 R2 (90%), Microsoft Windows Server 2012 R2 Update 1 (90%), Microsoft Windows Server 2016 build 10586 - 14393 (90%), Microsoft Windows 7, Windows Server 2012, or Windows 8.1 Update 1 (90%)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=7/1%OT=53%CT=1%CU=33052%PV=Y%DS=2%DC=T%G=Y%TM=66827
OS:F22%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=105%TS=U)SEQ(SP=104%GCD=1
OS:%ISR=105%II=I%TS=U)SEQ(SP=104%GCD=1%ISR=105%CI=RD%II=I%TS=U)SEQ(SP=104%G
OS:CD=1%ISR=105%TI=RD%TS=U)SEQ(SP=104%GCD=1%ISR=105%TI=RD%CI=RD%TS=U)OPS(O1
OS:=M53ANW8NNS%O2=M53ANW8NNS%O3=M53ANW8%O4=M53ANW8NNS%O5=M53ANW8NNS%O6=M53A
OS:NNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(R=Y%DF=Y%T=8
OS:0%W=FFFF%O=M53ANW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(
OS:R=Y%DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F
OS:=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%
OS:T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=O%A=O%F=R%O=%RD=0
OS:%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=
OS:Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=
OS:Y%DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=
OS:AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%
OS:RUD=G)IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=260 (Good luck!)
IP ID Sequence Generation: Busy server or unknown class
Service Info: Host: DC1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 49214/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 46880/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 35591/udp): CLEAN (Failed to receive data)
|   Check 4 (port 56268/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: -7m14s, deviation: 0s, median: -7m14s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-07-01T09:56:52
|_  start_date: N/A

TRACEROUTE (using port 1025/tcp)
HOP RTT       ADDRESS
1   150.41 ms 10.10.16.1
2   386.69 ms 10.10.11.22

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jul  1 19:04:18 2024 -- 1 IP address (1 host up) scanned in 1325.39 seconds
```

`blazorized.htb` というドメインを見つけたのでhostsファイルに追加

```
10.10.11.22	blazorized.htb
```

80番ポートが開いているのでサイトにアクセスしてみる

![](screenshot/024-07-01-190954.png)

アイデア、メモ、知識、考察を育むための文書コレクションサイトらしい(Qiitaみたいなやつ)

Blazor WebAssemblyを使用しているらしい

サブドメインがないか調べてみる

![](screenshot/2024-07-01-191524.png)

`admin`が見つかったのでhostsファイルに追加してアクセスする

![](screenshot/2024-07-01-191944.png)

ログインページが出てきたが認諸情報がないのでログインすることができない





