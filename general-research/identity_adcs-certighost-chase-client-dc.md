# Day 12 — Section 3.1.1.4.3.1.1

While reading up on Certighost for Day 11 I wrote down the preconditions, noted that the chase only happens on CAs with `EDITF_ENABLECHASECLIENTDC` set, and moved on. It sat wrong with me for two days.

The description was that the CA, when it needs information about the client requesting a certificate, will follow a host **the requester supplied** over SMB and LDAP. That is not a subtle bug. That is a certificate authority asking the person in front of it who can confirm their identity, and then going to ask that person.

My assumption was that this had to be vestigial. Some half-finished code path from an early build, never removed, that somebody finally poked at in 2026. Features do not get designed that way.

That assumption was wrong, and finding out how wrong turned out to be the interesting part.

## It has a name, which already told me something

`EDITF_ENABLECHASECLIENTDC`. Bit `0x00100000` in the CA's EditFlags.

Dead code does not get a constant name with a vendor prefix, a documented bit position, and a `certutil` switch to toggle it. Somebody specified this. Somebody wrote documentation for it. Somebody had a reason.

So the question changed from "why is this still here" to "what problem was this solving", which is a much better question.

## The spec has a section for it

The flag makes the CA honour a request attribute called `cdc`. It is in [MS-WCCE], the Windows Client Certificate Enrollment Protocol, in the certificate request attributes alongside things like `CertificateTemplate` and `SAN`. There is a companion attribute called `rmd` that names the FQDN of the machine object behind the request. Certighost abused both.

The description of `cdc` in section 3.1.1.4.3.1.1 is that the client supplies an Active Directory server FQDN that the CA can **fall back on** if it cannot obtain the end entity's information itself.

Then I found the section title that ended the investigation for me.

> **Search Requests for Querying End Entity Object Attributes with an End Entity Provided DC Name**

Read that slowly. It is a named, specified, documented behaviour. "End entity provided DC name." The entity asking for the certificate provides the name of the server that will be consulted about the entity asking for the certificate.

That is not a bug that slipped in. That is a design, written down, with a heading.

## What it was actually for

Once you know it is intentional, the reason is obvious and almost sympathetic.

Picture a large forest in roughly 2003. The enterprise CA lives in one domain. A machine in a child domain, or across a forest trust, wants a certificate. The CA needs to look up that machine's attributes in Active Directory to fill in the certificate, but the CA cannot reach that domain's controllers. Network segmentation, DNS, trust direction, name resolution across a forest boundary, pick your favourite.

The CA has a real distributed systems problem. It needs information from a directory it cannot find.

And the answer somebody landed on was, well, the client knows which DC it talks to, so let the client tell us.

In 2003 that is not even unreasonable. The client is a domain-joined machine, already authenticated, sitting on the corporate network behind the perimeter. If it says the DC is `dc03.child.corp.local`, why would it lie. The whole mental model of the era was that being inside the network was itself a form of trust.

That assumption is the artifact here. Not the code.

## The bug is not the feature

This is the bit I actually wanted to understand, and it reframes the whole thing.

Microsoft's fix on 14 July 2026 did not remove the chase. It added validation that the host being chased is genuinely a domain controller. [CVE-2026-54121](https://techcommunity.microsoft.com/blog/microsoftthreatprotectionblog/detecting-cve-2026-54121-certighost-with-microsoft-defender/4542861) is classified as CWE-285, improper authorization, and that classification is precise. The feature was always meant to let a client name a DC. What was missing for two decades was anyone checking that the name pointed at a DC.

So for the entire life of the feature, the CA would accept an answer to the question "who can vouch for you" without verifying that the thing named was qualified to vouch for anything.

The flaw is one missing check inside an intentional design, and the design only became dangerous when the surrounding assumption about network trust stopped being true. Which it did, slowly, somewhere between 2003 and now, without anyone going back to re-read section 3.1.1.4.3.1.1.

## Why did this survive the ESC wave

This is where I start guessing, and I want to be clear that it is guessing.

The 2021 Certified Pre-Owned research and everything that followed went extremely thoroughly through **templates** and **CA permissions**. ESC1 through ESC16 are, with few exceptions, about who may request what, and what they may put in it. That is the enrollment policy surface.

The `cdc` attribute is not in that surface. It is not a template setting and it is not an ACL. It is a request attribute that changes how the CA **resolves information about the requester**, which is a different mechanism sitting one layer down. If your research question is "which templates let me ask for the wrong thing", you can read every template in the forest and never arrive at it.

So my working theory is that the ESC family mapped enrollment policy very well and the request processing path much less so, and `cdc` lived in the second one. If that is right then there is probably more down there, because request attributes are a list and only two of them have been interesting so far.

I have no evidence for that beyond the shape of it.

## What I could not find out

Two things I wanted and did not get.

**How common the flag actually is.** The sources genuinely disagree. One lab write-up had to enable it manually to reproduce. Another describes it as commonly found but offers nothing to support that. One researcher says outright that they have no hard data and will not guess, which I respect more than the confident answers. So the honest position is that nobody published a prevalence number, and "check your own CAs" is not a dodge, it is the only available answer.

```
certutil -getreg policy\EditFlags
```

**When it was introduced.** I could not pin it to a Windows Server version. MS-WCCE documents the behaviour but the spec is a description of the protocol as it exists, not a changelog. Finding the introduction date would mean digging through old Windows Server documentation revisions, and I stopped.

One more thing I noticed and have not followed. There is a detection angle in the `cdc` value itself, because a request carrying a `cdc` that is not one of your domain controllers is suspicious regardless of patch state. Event 4886 is where certificate requests land. That is probably where I would start if I came back to this.

## The thing I will actually remember

I went looking for a mistake and found a decision.

The feature made sense when it was written, against a threat model where the inside of the network was trustworthy. Nobody did anything stupid. The code did what it was designed to do for over twenty years. What changed was the world around it, and nothing in the system is capable of noticing that its own founding assumption has expired.

That is the part worth keeping. Not "AD CS has another ESC". The idea that somewhere in every old system there are decisions that were correct when made, are still running exactly as specified, and are now wrong, and that the system cannot tell you which ones they are.

Certighost is one that got found. Section 3.1.1.4.3.1.1 was sitting in public documentation the whole time.

---

Where I ended up reading.

[MS-WCCE] certificate request attributes, [2.2.2.7](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/9503393d-7b41-42d0-adcf-2c4ac206406d) and the PKCS #10 request section [3.1.1.4.3.1.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/f4eb50d5-62f6-470b-8846-9489af9dea62), plus the section that answered it, [Search Requests for Querying End Entity Object Attributes with an End Entity Provided DC Name](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/596a8f7e-5a1c-424a-b69e-709510312142).

[Microsoft on detecting Certighost](https://techcommunity.microsoft.com/blog/microsoftthreatprotectionblog/detecting-cve-2026-54121-certighost-with-microsoft-defender/4542861), [Nextron's Sigma coverage](https://www.nextron-systems.com/2026/08/04/detecting-certighost-cve-2026-54121-sigma-coverage-across-the-full-attack-chain/) which was the clearest on the flag itself, [PKI Solutions on working out whether a CA was actually exploited](https://www.pkisolutions.com/blog/certighost-how-to-determine-whether-your-enterprise-ca-was-exploited/), and [Gradenegger on event 4886](https://www.gradenegger.eu/en/details-of-the-event-with-id-4886-of-the-source-microsoft-windows-security-auditing/).
