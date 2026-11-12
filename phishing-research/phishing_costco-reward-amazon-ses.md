# Day 17 — Everything Passed

A phishing email promising a free YETI beach wagon to "valued Costco customers" landed straight in a Microsoft inbox. SPF, DKIM, DMARC, composite authentication and Sender ID all passed. The spam score was 1 and the bulk score was 0. This writeup takes that email apart, from the headers to the attachment, to see how every layer was built to look legitimate.

## The sample

The email comes from phishing_pot, a public collection of real phishing emails gathered by researchers through decoy mailboxes. Recipient addresses are anonymised by the collectors and replaced with `phishing@pot`.

```
sample-10010.eml
41102 bytes
sha256 6513f2ccf933ebb1ce99db0234353a68955a7a530ff9faf1b9de5f670803b7cc
```

I picked it because it carries an attachment. The analysis was done on an offline Linux VM with nothing more than `grep`, `sed` and a few lines of Python. The email was never opened in a mail client, no link was visited and the attachment was never opened in a PDF reader.

## The route

An email's `Received` headers are added by every server that handles it, newest on top. Read from the bottom up, they show the real path.

```
a57-30.smtp-out.us-west-2.amazonses.com (54.240.57.30)
  -> BL6PEPF00020E5F.mail.protection.outlook.com
  -> MN2PR03CA0019.namprd03.prod.outlook.com
  -> PH0PR10MB5609.namprd10.prod.outlook.com
  -> MW4PR10MB5749.namprd10.prod.outlook.com
```

The email was sent through **Amazon Simple Email Service (SES)**, a legitimate bulk mail service, and delivered to a Microsoft mailbox on Wednesday 1 April 2026 at 22.05 UTC. Delivery took under three seconds.

## Authentication, all green

```
Authentication-Results: spf=pass (sender IP is 54.240.57.30)
 smtp.mailfrom=us-west-2.amazonses.com; dkim=pass (signature was verified)
 header.d=procam.in;dkim=pass (signature was verified)
 header.d=amazonses.com;dmarc=pass action=none
 header.from=procam.in;compauth=pass reason=100
X-SID-PRA: INDIAMOVEASONE@PROCAM.IN
X-SID-Result: PASS
```

| Check | Result | What it actually proves |
|---|---|---|
| SPF | pass for `us-west-2.amazonses.com` | the envelope sender is Amazon, and Amazon may send from this IP |
| DKIM | pass for `procam.in` and for `amazonses.com` | the message was signed with keys published by both domains and wasn't altered |
| DMARC | pass for `procam.in` | the visible From domain matches a passing DKIM domain |
| compauth | pass | Microsoft's own combined verdict |
| Sender ID | pass | the address the user sees passed Microsoft's check |

This is the first lesson of the sample. These checks prove that the email was sent through infrastructure that `procam.in` authorised. They say nothing about whether the sender can be trusted. That leaves two options. Either the attacker controls `procam.in`, or, more likely given what follows, the SES account or mail setup of a real organisation was taken over and used to send this campaign. Stolen cloud credentials being used to send through SES is a well-known pattern.

## Four identities

```
From: =?UTF-8?Q?Get_Your_YETI_Beach_Lounge_Wagon_#87?= <Indiamoveasone@procam.in>
To: phishing@pot, admin@wxo.HORsXrZA.arz
Subject: Your payment could be returned as ...
Reply-To: feedback-ewek16yugnxu4v@listmanage1.com
Return-Path: 0101019d4b1479a3-269efb56-d4f9-41b1-9f2d-ff3f851d0d4a-000000@us-west-2.amazonses.com
Message-ID: <0101019d4b1479a3-269efb56-d4f9-41b1-9f2d-ff3f851d0d4a-000000@us-west-2.amazonses.com>
```

A legitimate email from one company has one identity. This one has four that have nothing to do with each other.

| Where | Identity |
|---|---|
| display name | **YETI**, the outdoor and cooler brand |
| email body | **Costco**, "Dear Costco customer" |
| From address | **procam.in**, an Indian domain, sender `Indiamoveasone@`, which reads like a real marketing campaign of that organisation |
| Reply-To and links | **listmanage1.com** |

`listmanage1.com` is a lookalike of `list-manage.com`, the domain Mailchimp uses for mailing list links and unsubscribe pages. Without the hyphen and with a `1` added, it passes a quick glance. The DKIM signature covers the `Reply-To` header, so the redirect of replies to the attacker's domain is part of the signed, "authentic" message.

The `Return-Path` and `Message-ID` on `amazonses.com` are normal for SES and not suspicious on their own.

## Structure

```
Content-Type: multipart/mixed
  text/html; charset=UTF-8            quoted-printable
  application/pdf; "phishing@pot.pdf"  base64, size=18476
```

There is no `text/plain` part. Real newsletters almost always include both a plain text and an HTML version. An HTML-only message is a small signal that spam filters weigh as well.

## The body

Decoded and stripped of HTML, the visible message is short.

> Dear Costco customer, A Special Reward Just for You. You have been chosen to receive a YETI Beach Lounge Wagon as part of our customer appreciation initiative. Thank you for your continued trust and for being a valued member of our community. ➔ GET YOUR REWARD

This is a classic reward scam. The victim gets an expensive product "for free" and only has to pay shipping or fill in a survey, which is where card details are stolen. The unsubscribe line even has a typo, "recieving".

### The links

| Link | Purpose |
|---|---|
| `https://23nbpth9.r.us-west-2.awstrack.me/L0/https:%2F%2Flistmanage1.com%2F431_1_9968lip7LCQtV8bMda0.x6fwC2976454_4M0UY7z2q_6.2/1/…` | the **GET YOUR REWARD** button |
| `https://23nbpth9.r.us-west-2.awstrack.me/I0/…` | an **open tracking pixel** |
| `http://23nbpth9.r.us-west-2.awstrack.me/L0/%2F/1/…` | a second tracked link to `/` |
| `mailto:feedback-nl2no3whel8bvj@listmanage1.com?subject=Unsubscribe` | the "unsubscribe" link |

**The button hides behind Amazon.** `awstrack.me` is Amazon SES's own click tracking domain. Hovering over the button shows an Amazon domain, which looks trustworthy and has a clean reputation. Only after the click does Amazon redirect to the real target. The target is visible in the URL if you decode it. `https:%2F%2Flistmanage1.com` is `https://listmanage1.com`. The attacker uses SES's built-in tracking to wrap the malicious destination in a reputable domain.

**The pixel.** The `I0` link is an image of 1 by 1 pixel, also styled `display: none`. When the email is opened and images load, the request tells the sender the mailbox is active.

**Different local parts.** The `Reply-To` address uses `feedback-ewek16yugnxu4v@` and the unsubscribe link uses `feedback-nl2no3whel8bvj@`. Both are on `listmanage1.com`, with randomly generated names. That's consistent with per-message or per-recipient tracking.

### The filler

After the lure comes text that doesn't belong.

1. A disclaimer from **NJM Insurance Group**, a real US insurer, with "The information you have requested is attached" and a link to `http://www.njm.com/`. This is text copied from a genuine business email.
2. Dozens of lines of random strings, such as `QeZJjNlwb|WBCZZ+Qwuh|rYoL|…`.

This is **hash busting**. The copied business text makes the message look more like normal mail to a content filter, and the random strings make every copy unique, so filters can't group thousands of identical messages. My first guess was that this block was hidden with CSS. It isn't. The only `display: none` in the message belongs to the tracking pixel. The filler is pushed below a long line of dashes and underscores, out of view unless the reader scrolls down.

## The attachment

```
phishing@pot.pdf   18354 bytes
sha256  3351250345e4b65b906dd100aef7aafed2b4560c59f881d5112cb24acc661735
sha1    2660406d1da0e4247790ecff82d38d11207b8091
md5     b13299134acb15dec00db24277fde6f5
PDF document, version 1.4, 1 page
```

The attachment was decoded from base64 with Python's `email` module and written to disk under a `.bin` name.

### No active content

Malicious PDFs rely on a small set of keywords. `/JavaScript` and `/JS` carry code, `/OpenAction` and `/AA` trigger actions when the file opens, `/Launch` starts a program, `/URI` adds links and `/EmbeddedFile` hides a file inside. Many of these sit inside compressed streams, so the six streams were decompressed with `zlib` before searching.

| Keyword | Count, including decompressed streams |
|---|---|
| /JavaScript, /JS | 0 |
| /OpenAction, /AA, /Launch | 0 |
| /URI, /Annot | 0 |
| /EmbeddedFile, /ObjStm, /XFA, /AcroForm | 0 |

The PDF contains no code, no actions, no links and no embedded files. It is plain text on one page.

### Real, and stolen

The text in the streams is a genuine NJM "Temporary Evidence of Insurance" for a car, in the name of a private individual, with a home address, policy number and vehicle identification number. I'm not repeating those details here.

So the NJM disclaimer in the body and the PDF belong together. Both come from one real email that NJM sent to a customer, "The information you have requested is attached", with the insurance card attached. The attacker reused that email and its attachment as filler. A real document from a real insurer makes the message look more legitimate to filters, and antivirus has nothing to find. How the attacker obtained the original email isn't visible. It could be a compromised mailbox, a data breach or an earlier campaign. Either way, the person named on that insurance card is a victim too.

### Truncated

The `Content-Disposition` header announced `size=18476`. The decoded file is 18,354 bytes, 122 bytes short. I first wrote that off as a sloppy mail client. A detection on VirusTotal, `SuspiciousFile.PDF.Truncated`, made me look again.

```
0000017794 00000 n
trailer
<< /Size 21
/Root
```

The file ends in the middle of its trailer, right after `/Root`. Everything a complete PDF has after that is missing, the reference to the catalog object, usually an `/Info` and an `/ID`, the closing `>>`, `startxref` and `%%EOF`. A search confirms it, with zero matches for `%%EOF`, `startxref`, a `/Root` reference or a `/Catalog` object. The missing part of a typical trailer is roughly 100 to 130 bytes, which fits the 122-byte gap. The `file` command still reports "1 pages" because it only looks for recognisable fragments such as `/Count 1` and doesn't check whether the file is complete.

The truncation happened in the campaign itself, not at phishing_pot. VirusTotal had already seen this exact file, with the same hash and size, before this email was sent. phishing_pot also only replaces addresses in the message text, and cutting bytes from base64 would break the encoding. Whether the truncation is deliberate or a bug in the sending tool can't be determined. For the attacker it hardly matters. The PDF is filler, and a broken file that scanners can't fully parse draws less attention, not more.

### Seen before

| VirusTotal field | Value |
|---|---|
| first submission | `2026-03-31 08:10:45 UTC` |
| last submission | `2026-11-07 18:16:29 UTC` |
| detections | 1 of 60 (VBA32, SuspiciousFile.PDF.Truncated) |
| sandbox | Acrobat contacted only Adobe services and DNS, no detections, no IDS or Sigma hits |

The same PDF was first seen the day before this email and was still being submitted seven months later. VirusTotal also lists it under several other filenames that look like the usernames of individual recipients. The campaign renames the attachment after each recipient, so the document appears to be about them. In this sample the collectors replaced the recipient address with `phishing@pot`, which is why the file has that name.

## Microsoft's verdict

```
X-MS-Exchange-Organization-SCL: 1
X-Microsoft-Antispam: BCL:0;...
X-Microsoft-Antispam-Mailbox-Delivery: ucf:0;jmr:0;ex:0;auth:1;dest:I;...
X-Message-Delivery: V=1.1;us=0;l=0;a=0;D=1;GD=1;SCL=3   (decoded from base64)
X-MS-Exchange-Organization-AuthAs: Anonymous
X-MS-Exchange-Transport-EndToEndLatency: 00:00:02.9857137
```

| Field | Value | Meaning |
|---|---|---|
| SCL | 1 | Spam Confidence Level. 0 and 1 mean not spam and go to the inbox, 5 and higher go to junk |
| BCL | 0 | Bulk Complaint Level. Not seen as bulk or marketing mail |
| dest | I | delivered to the **Inbox**. Junk would be `J` |
| ucf, jmr | 0 | no custom user filter or junk rule applied |
| second SCL | 3 | a score from another stage of filtering, also below the junk threshold |

The tenant ID ending in `aaaaaaaaaaaa`, together with `X-MS-UserLastLogonTime` and `X-Message-Delivery`, is typically seen on personal Outlook.com and Hotmail accounts, which fits a decoy mailbox. I'm fairly but not fully certain of that. It doesn't change the conclusion, since Outlook.com uses the same Exchange Online Protection filtering. Microsoft can still remove a delivered message later with zero-hour auto purge, and whether that happened isn't visible in the headers.

Every technique in this email pushed the verdict towards clean. A reputable sending IP with passing authentication, a destination hidden behind an Amazon domain, a harmless attachment from a real company, and filler that made every copy unique.

## The destination domain

| Source | Result |
|---|---|
| VirusTotal | 0 of 92 vendors flag it. Registrar Unstoppable Domains, created about a year ago, which puts registration around late 2025 |
| ICANN registration lookup | not found, the domain is no longer registered |
| urlscan.io | no results in the last 30 days, the limit for searches without an account |

The domain existed a few months before the campaign and is gone now. Whether it lapsed after its first year or was taken down isn't visible. At the time this email was sent, no reputation list knew it.

## Detection ideas

Authentication results alone won't catch this. What does stand out is the mismatch between the layers.

- **Display name versus domain.** A well-known brand in the display name, sent from a domain that doesn't belong to that brand.
- **Reply-To on a different domain than From**, especially a lookalike of a known service.
- **Wrapped links.** Click tracking URLs such as `awstrack.me` contain the real destination URL-encoded in the path. Decoding them before reputation checks exposes the target.
- **HTML only, with a large block of unrelated text below the visible content.**
- **An attachment named after the recipient**, combined with a PDF that is structurally incomplete.

In Microsoft Defender XDR, two starting points for hunting. Field values may need adjusting per tenant.

```kusto
// Decode the real destination of SES-tracked links in delivered mail
EmailUrlInfo
| where UrlDomain endswith "awstrack.me"
| extend TargetDomain = extract(@"/L0/https?:%2F%2F([^%/]+)", 1, Url)
| where isnotempty(TargetDomain)
| join kind=inner (EmailEvents | where DeliveryLocation == "Inbox/folder") on NetworkMessageId
| summarize Messages = dcount(NetworkMessageId) by TargetDomain, SenderFromDomain
| order by Messages desc
```

```kusto
// Brand names in the display name, sent from unrelated domains
EmailEvents
| where SenderDisplayName has_any ("Costco", "YETI")
| where not(SenderFromDomain has_any ("costco.com", "yeti.com"))
| project Timestamp, SenderDisplayName, SenderFromAddress, Subject, DeliveryLocation
```

## Open questions

- Whether procam.in's SES account was compromised, or the domain was abused another way. The headers alone can't show that.
- What listmanage1.com served after the redirect. With the domain gone, only an archived scan from April 2026 could show the landing page.
- Where the attacker got the original NJM email and its attachment.
- Whether the truncated PDF is deliberate or a bug.

## Indicators

```
Sending IP              54.240.57.30 (Amazon SES, us-west-2)
From                    Indiamoveasone@procam.in
Reply-To domain         listmanage1[.]com
Click-through target    hxxps://listmanage1[.]com/431_1_9968lip7LCQtV8bMda0.x6fwC2976454_4M0UY7z2q_6.2
Tracking domain         23nbpth9.r.us-west-2.awstrack[.]me
Subject                 Your payment could be returned as ...
Display name            Get Your YETI Beach Lounge Wagon #87

Email      sha256  6513f2ccf933ebb1ce99db0234353a68955a7a530ff9faf1b9de5f670803b7cc
Attachment sha256  3351250345e4b65b906dd100aef7aafed2b4560c59f881d5112cb24acc661735
           sha1    2660406d1da0e4247790ecff82d38d11207b8091
           md5     b13299134acb15dec00db24277fde6f5
```

## Source

■ [phishing_pot, a collection of real phishing samples](https://github.com/rf-peixoto/phishing_pot), sample-10010.eml
