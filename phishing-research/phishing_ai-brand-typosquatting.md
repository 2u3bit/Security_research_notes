# Day 18 — Typos that lead to ChatGPT, and one that leads to a magician

A news piece this week said attackers register lookalikes of AI tool addresses, so that someone who mistypes `chatgpt.com` lands on a fake page that installs malware. They called it TypoPrompting and gave a number, 186 domains across 27 AI brands, credited to researchers at Island.

I went looking for the Island report and couldn't find it. What Island did publish is about fake ChatGPT pages pushed through Google Ads and custom GPTs, not a count of lookalike domains. The only other number I found was from a Decodo study in January 2026, about 1,200 registered variants for ChatGPT and more than 2,800 for Gemini. Two numbers that are far apart, and neither says how many of those domains actually do something bad.

So I measured it myself. How many lookalikes of AI brands exist today, who owns them, and what is on them.

Everything ran on Kali on Sunday 15 November 2026, between 15.26 and 16.15 Dutch time. Nothing was opened in a browser. Pages were fetched as text with `curl`, no JavaScript was executed.

## The tool

`dnstwist` takes a domain and generates thousands of variants. A letter dropped, two letters swapped, a neighbouring key, an extra character, a look-alike Unicode letter. For each variant it does a DNS lookup and `--registered` keeps only the ones that exist.

```bash
sudo apt update && sudo apt install -y dnstwist
mkdir -p ~/research/typoprompting/raw && cd ~/research/typoprompting
```

Kali asks DNS from `192.168.37.2`, which is VMware, which forwards to whatever DNS my Windows host uses. If that filters malicious domains I would count too few. So every run gets fixed public resolvers, which also makes it repeatable for someone else.

## First count, chatgpt.com

```bash
dnstwist --registered --nameservers 1.1.1.1,8.8.8.8 --format csv chatgpt.com > raw/chatgpt.com.csv
wc -l raw/chatgpt.com.csv
head -5 raw/chatgpt.com.csv
```

```
159 raw/chatgpt.com.csv
fuzzer,domain,dns_a,dns_aaaa,dns_mx,dns_ns
*original,chatgpt.com,104.18.32.47,2606:4700:4408::ac40:9bd1,route1.mx.cloudflare.net,hassan.ns.cloudflare.com
addition,chatgptc.com,103.224.212.214,,park-mx.above.com,ns15.abovedomains.com
addition,chatgpt2.com,13.248.169.48,,,ns3.afternic.com
addition,chatgpt3.com,13.248.169.48,,,ns1.dan.com
```

159 lines minus the header and the original is 157 registered lookalikes. Already in the first three the nameservers tell a story. `abovedomains.com` is a parking service, `afternic.com` and `dan.com` are marketplaces where domains are for sale. Domain trading, not malware.

157 is also nowhere near Decodo's 1,200. By default dnstwist mostly stays on the same TLD, and I suspect Decodo included `.net`, `.ai`, `.app` and others. So the method decides the number, which is worth knowing before anyone quotes one.

## Seven brands

I took the AI brands that have their own domain. Gemini lives on `gemini.google.com` and Copilot on `copilot.microsoft.com`, subdomains of companies with huge domain portfolios, so I left them out.

```bash
echo "$(date -Is) dnstwist=$(dnstwist --version 2>&1 | head -1) resolvers=1.1.1.1,8.8.8.8 flags=--registered" | tee -a runs.log

for d in openai.com claude.ai perplexity.ai deepseek.com grok.com mistral.ai; do
  dnstwist --registered --nameservers 1.1.1.1,8.8.8.8 --format csv "$d" > "raw/$d.csv"
  echo "$d $(( $(wc -l < raw/$d.csv) - 2 ))"
done | tee -a runs.log
```

```
2026-11-15T15:33:05+01:00 dnstwist=dnstwist 20250130 resolvers=1.1.1.1,8.8.8.8 flags=--registered
openai.com 140
claude.ai 72
perplexity.ai 41
deepseek.com 109
grok.com 111
mistral.ai 10
```

| Brand | Lookalikes |
| :-- | --: |
| chatgpt.com | 157 |
| openai.com | 140 |
| grok.com | 111 |
| deepseek.com | 109 |
| claude.ai | 72 |
| perplexity.ai | 41 |
| mistral.ai | 10 |
| **Total** | **640** |

The `.ai` brands score low. A `.ai` domain costs somewhere around 70 to 100 dollars a year against about 10 for a `.com`, so registering typos in bulk is expensive there. That's a guess I haven't tested.

`grok.com` is probably inflated. A four letter name produces variants that are ordinary words or existing companies, registered for their own reasons and not as fake Grok. Every short brand has that problem.

## Who owns them

I merged all brands into one file and counted which nameserver provider shows up most.

```bash
awk -F, 'FNR>1 && $1!="*original" {b=FILENAME; sub(/^raw\//,"",b); sub(/\.csv$/,"",b); print b","$0}' raw/*.csv > all.csv
wc -l all.csv

cut -d, -f7 all.csv | cut -d';' -f1 | awk -F. 'NF>=2{print $(NF-1)"."$NF} NF<2{print "(geen NS)"}' \
  | sort | uniq -c | sort -rn | head -25
```

```
640 all.csv
     93 cloudflare.com
     53 domaincontrol.com
     53 afternic.com
     48 giantpanda.com
     44 abovedomains.com
     35 hichina.com
     28 registrar-servers.com
     26 (geen NS)
     19 spaceship.net
     16 namebrightdns.com
     15 markmonitor.com
     12 porkbun.com
     11 parklogic.com
     10 fabulous.com
     10 dyna-ns.net
      9 dnspod.net
      8 googledomains.com
      7 digitalocean.com
      7 atom.com
      6 share-dns.com
      6 sedoparking.com
      5 park-my-domain.net
      5 dan.com
      4 parity.domains
      4 julydns.com
```

My grouping.

- **Trade and parking.** afternic, abovedomains, parklogic, fabulous, atom, sedoparking, park-my-domain, dan. Parking pages with ads, or domains for sale.
- **Brand protection.** MarkMonitor registers domains for large brands. These are most likely typos the brand bought itself so nobody else can.
- **Ordinary hosting and registrars.** Cloudflare, GoDaddy (`domaincontrol.com`), Namecheap (`registrar-servers.com`), Spaceship, Porkbun, Alibaba Cloud (`hichina.com`) and Tencent (`dnspod.net`). Anything can sit behind these.
- **Unsure.** giantpanda, namebrightdns and dyna-ns might be domain investors too, but I didn't want to guess.
- **No NS.** The domain has an address but the NS lookup returned nothing.

I put the rules in a script so the grouping is visible and can be rerun when I move a provider.

```bash
cat > classify.sh <<'EOF'
#!/bin/bash
# geeft elke regel van all.csv een categorie op basis van de nameserver
awk -F, 'BEGIN{OFS=","}
{
  ns=$7; split(ns,n,";"); split(n[1],p,"."); k=(length(p)>=2)?p[length(p)-1]"."p[length(p)]:"";
  if (k=="")                                   c="geen_ns";
  else if (k ~ /^(afternic|abovedomains|above|parklogic|fabulous|atom|sedoparking|park-my-domain|dan|bodis|parkingcrew)\.(com|net)$/) c="handel";
  else if (k=="markmonitor.com")               c="merk";
  else if (k ~ /^(giantpanda|namebrightdns|dyna-ns)\./) c="onzeker";
  else                                         c="onderzoeken";
  print c,$0
}' all.csv > classified.csv
EOF
chmod +x classify.sh && ./classify.sh

cut -d, -f1 classified.csv | sort | uniq -c | sort -rn
cut -d, -f1,2 classified.csv | sort | uniq -c | awk '{split($2,a,","); printf "%-14s %-12s %4d\n", a[2], a[1], $1}' | sort
```

```
    383 onderzoeken
    142 handel
     74 onzeker
     26 geen_ns
     15 merk
```

| Brand | Trade | Brand-owned | Unsure | No NS | To check |
| :-- | --: | --: | --: | --: | --: |
| chatgpt.com | 46 | 0 | 19 | 4 | 88 |
| openai.com | 24 | 7 | 15 | 5 | 89 |
| grok.com | 29 | 0 | 12 | 3 | 67 |
| deepseek.com | 19 | 0 | 11 | 9 | 70 |
| claude.ai | 10 | 8 | 9 | 3 | 42 |
| perplexity.ai | 14 | 0 | 8 | 1 | 18 |
| mistral.ai | 0 | 0 | 0 | 1 | 9 |

Only `claude.ai` and `openai.com` have MarkMonitor registrations. OpenAI protects `openai.com` but not `chatgpt.com`, which is the address people actually type. Nameservers are only a proxy though. A brand can also register through someone else.

## Looking at what's on them

That left 483 domains (to check, unsure and no NS). Fetching them shows my home IP to whoever runs them, so I switched on a VPN on the host first and checked that Kali's traffic went through it.

```bash
curl -s https://ipinfo.io/json | grep -E '"city"|"country"|"org"'
#  "city": "Montréal",
#  "country": "CA",
#  "org": "AS212238 Datacamp Limited",
echo "$(date -Is) probe via VPN exit: CA Montreal, AS212238 Datacamp Limited (datacenter IP)" >> runs.log
```

That's a datacenter address. Malicious sites often show datacenter visitors something harmless because those are usually scanners, so whatever I find is a lower bound.

For each domain the script records the status code, where it ends up after redirects, and the page title. It tries https first, then http, follows at most five redirects, gives up after 15 seconds and stops at 2 MB.

```bash
cat > probe.sh <<'EOF'
#!/bin/bash
# haalt statuscode, eindbestemming en titel op van een domein, voert niets uit
d="$1"
for s in https http; do
  r=$(curl -sS -L --max-time 15 --max-redirs 5 --max-filesize 2000000 \
      -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
      -o "pages/$d.html" -w '%{http_code}|%{url_effective}' "$s://$d" 2>/dev/null)
  code=${r%%|*}
  [ -n "$code" ] && [ "$code" != "000" ] && break
done
t=$(grep -io '<title[^>]*>[^<]*' "pages/$d.html" 2>/dev/null | head -1 | sed 's/<title[^>]*>//I' | tr -d ',\r\n' | cut -c1-80)
echo "$d,${code:-000},${r#*|},$t"
EOF
chmod +x probe.sh && mkdir -p pages

awk -F, '$1!="handel" && $1!="merk" {print $4}' classified.csv | sort -u > todo.txt
echo "domain,code,final_url,title" > probe.csv
date -Is | tee -a runs.log
xargs -P 10 -n 1 ./probe.sh < todo.txt >> probe.csv

awk -F, 'NR>1{split($3,u,"/"); print (u[3]==""?"(geen antwoord)":u[3])}' probe.csv | sort | uniq -c | sort -rn | head -30
```

```
483 todo.txt
2026-11-15T15:48:30+01:00
     13 www.hugedomains.com
      8 gotowww.aipages.dev
      6 choto.click
      4 deepxeek.com
      3 chatgpt.com
      2 www.xhat.com
      2 forsale.dynadot.com
      2 bitcoindose.win
      2 accounts.binance.com
      ...
      1 xn--penai-zta.com
      1 xn--penai-uua.com
      1 xn--opena-xsa.com
      ...
```

"(geen antwoord)" never showed up. When a domain doesn't answer, curl still reports the requested address as the final one, so dead domains looked like sites that stay on their own domain. The status codes separate them.

```bash
cut -d, -f2 probe.csv | tail -n +2 | sort | uniq -c | sort -rn
```

```
    302 200
    106 000
     30 403
     13 301
     11 404
      5 410
     ...
```

106 domains didn't answer at all. Among the titles, 21 were "Just a moment...", 3 "Making sure you're not a bot!" and 2 "Attention Required! | Cloudflare". Bot challenges curl can't get through. With the 106 silent ones that's 132 domains I can say nothing about.

The `xn--` names are Punycode, how DNS stores names with non-ASCII letters. For `openai.com` alone there are about ten of them, each showing up in a browser as `openai.com` with one letter swapped for a look-alike.

## How the typos make money

Three commands on `probe.csv` and the saved pages.

```bash
awk -F, 'NR>1 && $2!="000" {print ($4==""?"(geen titel)":$4)}' probe.csv | sort | uniq -c | sort -rn | head -40
grep -E 'choto\.click|deepxeek|aipages\.dev|bitcoindose|binance' probe.csv
grep -iE ',(ChatGPT|chatgdp|Xhat|ChatPRO|you meant)' probe.csv
```

```
chatgtpt.com,202,https://accounts.binance.com/register?ref=15918626,
depeseek.com,202,https://accounts.binance.com/register?ref=15918626,
chwtgpt.com,200,https://bitcoindose.win/chat//,ChatPRO 5 online
czatgpt.com,200,https://bitcoindose.win/chat//,ChatPRO 5 online
chaytgpt.com,200,https://choto.click/vx/nvUd3d91kBjKKzVk,choto.click
cuatgpt.com,200,https://choto.click/vx/F7IFxMTb2TW1Zp2e,choto.click
lpenai.com,200,https://choto.click/vx/KOqk8AFvL8OjpkSp,choto.click
deepeeek.com,200,https://deepxeek.com/,Deep Seek Redirect
deeppseek.com,200,https://gotowww.aipages.dev/8d/?deeppseek.com,welcome
deepserk.com,200,https://gotowww.aipages.dev/6d/?deepserk.com,welcome
cahtgpt.com,200,https://cahtgpt.com/?utm_source=cahtgpt.com&...&ok=yes,chatgdp.com - Homepage
chatgppt.com,200,https://everydayconsumers.org/technology/chatgpt-tips-prompting-guide?...,ChatGPT Prompting Guide for Tech | Best Tips
chatgpt7.com,200,https://chatgpt7.com/,ChatGPT7｜AI兼职网站
vhatgpt.com,200,https://www.xhat.com/,Xhat - Freedom to Converse | Secured &amp; Creative AI Chat Platform
chatg0t.com,200,https://chatgpt.com/,ChatGPT
xn--chagpt-kmc.com,200,https://xn--chagpt-kmc.com/,ChatGPT
```

What I read in that.

- **One owner behind two brands.** `chatgtpt.com` and `depeseek.com` both send visitors to a Binance sign-up with the same referral ID `15918626`. Someone earns per new Binance customer that arrives through a typo, and the shared ID ties a ChatGPT typo and a DeepSeek typo to one person.
- **A fake chat app.** `chwtgpt.com` and `czatgpt.com` go to `bitcoindose.win/chat/`, titled "ChatPRO 5 online". Both pages are 36,749 bytes, identical.
- **A traffic distribution system.** Five ChatGPT and OpenAI typos go to `choto.click/vx/<code>`, each with its own code. That lets the owner count per typo and decide per visitor where they go. I only got a bare page titled "choto.click", which might be cloaking or might be nothing.
- **Domain networks.** Four DeepSeek typos end at another DeepSeek typo, `deepxeek.com`. Ten end at `gotowww.aipages.dev` under the paths `/6d/` and `/8d/`, which could be one investor with two portfolios.
- **Other ways to cash in.** `chatgdp.com` with UTM tags per typo, an article on `everydayconsumers.org` (content arbitrage), a competing AI chat `xhat.com` catching ChatGPT typos, and `chatgpt7.com` titled "AI side job site" in Chinese, which looks like a work-from-home scam.
- **Benign.** `chatg0t`, `chawtgpt` and `cxatgpt` send you to the real `chatgpt.com`.

I read the fake chat app as text, without scripts and styles.

```bash
python3 -I - pages/chwtgpt.com.html <<'EOF'
import sys, html.parser
class T(html.parser.HTMLParser):
    def __init__(s): super().__init__(); s.skip=0; s.out=[]
    def handle_starttag(s,t,a): s.skip += t in ("script","style")
    def handle_endtag(s,t): s.skip -= t in ("script","style") and s.skip>0
    def handle_data(s,d):
        if not s.skip and d.strip(): s.out.append(d.strip())
for f in sys.argv[1:]:
    p=T(); p.feed(open(f,encoding="utf-8",errors="replace").read())
    print("==",f); print(" | ".join(p.out)[:1500]); print()
EOF
grep -oE "https://app\.hyperliquid\.xyz[^\"' <)]*" pages/chwtgpt.com.html | sort | uniq -c
```

```
ChatPRO 5 online | New chat | Pizza recipe | How to earn bitcoin? | What is 3x leverage? | Write Python code | April Fools' joke | ... | Investment tips 2025 | ... | How to become a millionaire | ... | Where to invest | ... | ✨ April 1st – ask anything, get an honest answer ✨
     33 https://app.hyperliquid.xyz/join/REGISTERACCOUNT
```

An April Fools chat as the wrapper, with "How to earn bitcoin?" and "What is 3x leverage?" between the pizza recipes, and every link a Hyperliquid referral (`/join/REGISTERACCOUNT`). Hyperliquid is a crypto exchange for leveraged trading. Same model as the Binance link.

## The downloads that weren't there

A search for links to `.exe`, `.msi`, `.dmg`, `.apk`, `.zip` and similar listed six pages.

```bash
grep -lioE 'href="[^"]+\.(exe|msi|msix|dmg|pkg|apk|zip|rar)"' pages/*.html
# pages/chatgp6.com.html  pages/chatgpv.com.html  pages/deepseekq.com.html
# pages/grol.com.html     pages/opcnai.com.html   pages/qrok.com.html
```

The same pattern with `-o` printed nothing. I checked whether the files were compressed (`file` said plain HTML), searched again with `-a` and a wider pattern, and then for 80 characters of context around any of those extensions. Nothing. I can't reproduce the first hits, so they don't count as a finding. No password fields on any page either (`grep -lio 'type="password"'` returned nothing).

## chațgpt.com

`xn--chagpt-kmc.com` titled itself "ChatGPT" and stayed on its own domain.

```bash
python3 -c "print('xn--chagpt-kmc.com'.encode().decode('idna'))"
python3 -c "import unicodedata as u; [print(c, hex(ord(c)), u.name(c)) for c in 'xn--chagpt-kmc.com'.encode().decode('idna') if ord(c)>127]"
```

```
chațgpt.com
ț 0x21b LATIN SMALL LETTER T WITH COMMA BELOW
```

A Romanian letter with a tiny comma under the t. The visible text of the page was just "ChatGPT", everything is built by JavaScript. But the developer left comments in the HTML.

```html
<!-- Fallback-domain auto-upgrade. Only chatgptl.cc (the takedown-resistant Namecheap fallback) runs this:
on load it probes the chațgpt.com disguise (xn--chagpt-kmc.com) via a CORS read of /up.txt. If the disguise
is alive it silently upgrades the address bar to it; if it is dead (registrar takedown -> no DNS -> fetch
rejects) it reveals and serves the full show on chatgptl.cc itself. ... -->

<!-- NOT standalone-capable on purpose: in iOS standalone (home-screen) mode, a getaway to an
     external URL (chatgpt.com) is forced into a NEW Safari tab and can't overwrite the window.
     Running in Safari instead lets the New-chat / getaway do an in-place location.replace to
     chatgpt.com (same tab, no new tab), and shows the realistic collapsing address bar. ... -->
```

So there's a disguise domain, a backup `chatgptl.cc` that takes over if the disguise gets taken down, and a "getaway" that replaces the page with the real `chatgpt.com` in the same tab. `location.replace` doesn't leave an entry in the back button either.

DNS agreed with the comments.

```bash
for q in A NS; do echo "chatgptl.cc $q: $(dig +short chatgptl.cc $q | tr '\n' ' ')"; done
for q in A NS; do echo "xn--chagpt-kmc.com $q: $(dig +short xn--chagpt-kmc.com $q | tr '\n' ' ')"; done
whois 216.198.79.1 | grep -iE '^(orgname|org-name|netname|organization)' | head -3
```

```
chatgptl.cc A: 216.198.79.1 64.29.17.1
chatgptl.cc NS: dns1.registrar-servers.com. dns2.registrar-servers.com.
xn--chagpt-kmc.com A: 64.29.17.1 216.198.79.1
xn--chagpt-kmc.com NS: ns35.domaincontrol.com. ns36.domaincontrol.com.
NetName:        VERCEL-05
Organization:   Vercel, Inc (ZEITI)
OrgName:        Vercel, Inc
```

The backup is at Namecheap, exactly as the comment says, the disguise at GoDaddy. Two registrars on purpose, so one takedown doesn't kill both. Both run on Vercel.

Certificate transparency took a few tries. crt.sh failed on the first loop, worked on a single query, and failed again later. Cert Spotter answered "the free tier is temporarily unavailable". What crt.sh did return was enough.

```bash
curl -s --max-time 90 "https://crt.sh/?q=xn--chagpt-kmc.com&output=json" | python3 -I -c "
import sys,json
r=json.load(sys.stdin)
for x in sorted(r,key=lambda x:x['not_before']): print(x['not_before'], x['common_name'], '|', x['name_value'].replace(chr(10),' '))"
```

```
2026-08-19T22:32:02 chatgptl.cc | xn--chagpt-kmc.com
2026-08-19T22:36:54 xn--chagpt-kmc.com | xn--chagpt-kmc.com
```

One Let's Encrypt certificate carries both names. Only someone who controls both domains can get that, so the link holds without the comments. Online since 19 August, three months without a takedown.

The page loads a single Vite bundle. I downloaded it as a file and only grepped it.

```bash
grep -aoiE '<script[^>]*src=[^>]*>' pages/xn--chagpt-kmc.com.html
# <script type="module" crossorigin src="/assets/index-BD4dTMm_.js">
curl -s --max-time 30 -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
  -o evidence/chatgpt-homoglyph-index-BD4dTMm_.js "https://xn--chagpt-kmc.com/assets/index-BD4dTMm_.js"
# 275323 bytes

js=evidence/chatgpt-homoglyph-index-BD4dTMm_.js
grep -aoE '(https?|wss?)://[A-Za-z0-9._/-]+' "$js" | sort | uniq -c | sort -rn | head -30
grep -aoiE 'firebase|supabase|pusher|ably|socket\.io|peerjs|RTCPeerConnection|BroadcastChannel|EventSource|new WebSocket' "$js" | sort | uniq -c
grep -aoiE '.{0,60}(charlie|stage|pair|getaway|channel|show|performer|spectator|audience|magic|trick).{0,60}' "$js" | sort -u | head -40
grep -aoE '"[A-Z][^"]{30,160}"' "$js" | sort -u | head -40
```

The only outside endpoints were `https://chatgpt.com/`, `https://api.openai.com/v1/chat/completions` and `https://api.openai.com/v1/audio/transcriptions`. For syncing it uses `ably` (a realtime messaging service) and `BroadcastChannel`. And then the strings.

```
<h2>Performer settings
Waiting for pairing&hellip;<div class="sub">Pair a remote to this screen to
<label>Forced answer (shown verbatim)</label>
...prediction lands on. View or overwrite it here, even on the spectator's phone. Changes sync to your remote.
"The card you are thinking of is the Seven of Diamonds."
"There is a covertly typed word: "
"Each of these target words MUST have its exact cue word directly in front of it (use exactly these pairs): "
"Your task is to create a single polished image prompt that hides the covert word visually through objects embedded naturally in the scene."
"You are ChatGPT. Write a natural, helpful, realistic answer to the user's message."
```

It's a mentalism act. A spectator types into "ChatGPT" on their own phone, the performer watches and steers it from a paired remote, forces an answer or hides cue words in it, and the answers really come from OpenAI with the performer's own API key. When the spectator taps New chat, the page turns into the real `chatgpt.com`, so whoever checks afterwards sees nothing odd. The takedown-resistant setup protects a stage prop, because a registrar would pull a ChatGPT homoglyph for brand abuse.

The most sophisticated lookalike in the whole set, homoglyph, backup domain, two registrars, shared certificate, a getaway that wipes the trail, and it isn't malware. It is still impersonation, what the spectator types goes to a third party, and the same template would work for phishing without changing much.

## Where this leaves me

In this sample, typos of AI brands are mostly a business. Parking, domains for sale, crypto referrals, traffic resold through a TDS, content arbitrage, a competitor catching traffic. I found no confirmed malware download and no credential phishing, which doesn't match the TypoPrompting picture.

That comes with real limits. One measurement on one afternoon, only `.com` and each brand's own TLD, a datacenter IP that cloaking can filter, no JavaScript executed, 132 domains I couldn't see into, and nameservers used as a stand-in for ownership.

Still open.

- Repeat exactly this around 22 November. Which domains are new, which are gone, which changed destination.
- A round with `.net`, `.ai`, `.app` and `.org`, to see if that explains the gap with Decodo.
- What `choto.click` serves to a residential IP.
- Who is behind giantpanda, namebrightdns and dyna-ns.
- Whether the six download hits were real.

## Evidence

All raw data stays offline in `typoprompting-2026-11-15.tgz`. The saved pages and the JavaScript of the magic app are third party content and are not in this repo.

```
f1f53c561cd0525e75d70071594cf1665b1708e05ca3795ce154f3353cc79926  typoprompting-2026-11-15.tgz
378c15eaaf69e9d4d6ad476ea1cc565de1b9d21311e31564f269f68a626c6a7e  chatgpt-homoglyph-index-BD4dTMm_.js
c6aee61dbfeca74effa485d5f8a8ca189f2a290c515d81bd2e6a5bf5ef0be806  xn--chagpt-kmc.com.html
c2b89e7c8076976308266b3a17be0c9ee11602286593d95a6cce0e90b03165a1  chwtgpt.com.html
3c2e718ca8d9a3d59b86ced56eec5ab0e5b6fb57ce724c14f2615ee72541e9c0  chatgp6.com.html
6b77c2b88cf8aa93d055c2baf1d2b1d4bd8d5fb97b6d129d006448a2470241f6  chatgpv.com.html
8ec82c9cffc91ef887f57b68f713eef19ad40c3dc61f9924c1c145a192265a0c  deepseekq.com.html
6536d659b61e9a2afd873a222472ac21cf72cb7c275fc771cfff03794ffe2fe5  opcnai.com.html
4c1c4513a77ab1a621d01f7e5f58d88374ffe8c408746fdafff5c36149b3b546  grol.com.html
e3ada2dc665a8f95a74c4da13d46f989891aecd9ab3c34a83a805f3359c4c957  qrok.com.html
```

Sources
- [New TypoPrompting Attacks, Cybersecurity News](https://cybersecuritynews.com/new-typoprompting-attacks/)
- [How attackers use sponsored search and custom GPTs in malware delivery, Island](https://www.island.io/blog/how-attackers-use-sponsored-search-custom-gpts-in-malware-delivery)
- [Study finds 28,000 fake domains mimic top websites, SecurityBrief](https://securitybrief.news/story/study-finds-28-000-fake-domains-mimic-top-websites)
