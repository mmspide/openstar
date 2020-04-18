---
title: OpenStar(开心)说明
tags: OpenResty,OpenStar,waf+,云waf,nginx lua
grammar_cjkRuby: true

---

Welcome to ** {OpenStar} (WAF +) **, this project is generated from actual needs, after many iterations of the version, it is really not easy. Thanks to ** Spring Brother **, and the artifact of [Spring] [1] (** [OpenResty] [2] **)


Note: The version must be greater than 1.11.0 because ngx.var.request_id is used

** The code is relatively easy to understand, definitely not elegant ha ~ **


The WIKI chapter is being updated, and the installation chapter has been updated. Please check it yourself.

Update: rule support method
```
Existing: equal ("") contains ("in") list ("list") dictionary ("dict") regular ("jio | jo | ***")
Added: start list ("start_list")-what and what list to start with
       Case-insensitive start list ("ustart_list")
       End list ("end_list")-what and what ends the list
       Case-insensitive end list ("uend_list")
       Inclusion list ("in_list")-list form of inclusion
       Case-insensitive inclusion list ("uin_list") --in_list extension (case-insensitive)
       [Json is the same as list]
Increase: Length ("len") [Min, Max] means greater than or equal to Min, and less than or equal to Max

EG：
"host":[[
          "www.baidu.",
          "img.baidu."
        ],
            "start_list"
        ]
"referer":[[0,150],"len"]   --- referer 长度 在 0~150 之间
```

# Commercial version
https://www.kancloud.cn/openstar/install/1136671
<Personal free ^ _ ^>

# Change history

## 1.7 Update second-order matching rules to support negation, cancel next action, etc.
The original second-order rule: ["baidu", "in"], after support for reversal: ["baidu", "in", true]; the final default is nil, which is false, which means no reversal. Can be reused between, the action for next needs to be modified

## 1.7.1.11 Update rule matching is equal to judgment expression support ("="), post_form support ("*") matches all form names
```
["post_form",["(;|-|/)","jio",["*",2],false]] Match file names for all names of the form

["www.test.com",""]
["www.test.com","="] New expressions

```


## 1.7.1.10 Update to support speed limit based on business attributes
network_Mod: `" network ": {" maxReqs ": 30," pTime ": 10," blackTime ": 600," guid ":" cookie_userguid "}`, business code ngx.var [% guid%], is actually Go to the value from ngx.var for the speed limit operation, so it must be configured normally; here it means that the value of the userguid in the cookie is used for frequency statistics to limit the speed. The default is to use ip speed limit

### 1.7.1.1 Modify host_Mod rule matching
Currently there are only two rules (app_ext | network) Please refer to conf_json / host_json / 101.200.122.200.json

### 1.7.0.24 Original rule matching change: table-> list; list-> dict
Convenient to understand list means sequence, dict means dictionary.
EG:
```
"method":[
            {
                "POST":true,
                "GET":true
            },
            "dict" --- 原 list
        ]
"ips": [[
            "101.254.241.149",
            "106.37.236.170"],
            "list" --- 原 table
        ]
```

## 1.6 Update the count_dict to DB 2, the key is also separated, optimize the rule cache
The rules are cached, which greatly improves performance, and the json file is saved and beautified ...

## 1.5 Add Master / Slave mode at the strong request of some friends
Master: regularly push the configuration in memory to redis, slave: regularly pull data from redis to memory, and save to file

## 1.4 Update naming related to match with multiple rules
The original url is changed to uri, args is changed to query_string, more modified, and app_Mod is added to achieve multi-rule matching, and the connector supports OR

## 1.3 Update jump function, configurable for set-cookie operation
You can configure one or more URLs to use jump set-cookie operations. Cookies are stateless.

## 1.2 Update support to intercept external csrf
At referer_Mod, add action, `allow` means allowed and subsequent rules are not used for matching (usually static resources such as pictures / js / css, etc.),` next` means that after the whitelist match is successful, the following rule matching will continue Here it is used to intercept external CSRF) The increase in `next` is because in the original code, if the CSRF outside the protection station is configured, the subsequent rules will be bypassed, so it is added so that there will be no bypass problems.
** The following actions theoretically support this syntax **

## 1.1 Add app_Mod, enrich allow action (ip)
IP whitelist access control for a directory on the website (background, phpmyadmin, etc.)

## 0.9-1.0 Modified a lot of global functions
After studying [OpenResty Best Practices] [7], the code is too unprofessional and a lot of global variables and functions have been modified

## 0.8 Optimize the algorithm
It turns out that args traverses each parameter and connects it. I feel that performance is sometimes a bottleneck. I use the new api to extract all the parameters in the url. After testing, the effect is much better than the original.

## 0.7 Add cluster version
At that time, there were about 2-4 OpenStar servers for security protection, and the unified management through scripts did not perform real unified management, so redis was used when taking the time.

## 0.6 Add API related operations
Because I ’m a crappy programmer (I ca n’t help it, I ’m forced to write code now for safety; thanks to Chun, I ’m very happy in the writing process, so I called the project OpenStar [happy], please do n’t laugh ). I haven't thought about the front-end interface for a long time, so I first encapsulated the operation API to meet the scripting needs of the company at that time.

## 0.4-0.5 Add configuration file operation
At the beginning, it was written in lua code. As the function increased, I decided to operate through the configuration file, so all used json to define the configuration file.

## 0.3 Add waf protection module
With the success of cc protection, I have successively added waf related functions. The rules refer to [modsecurity] [8], [loveshell] [9] protection modules, and some filtering points collected by the Internet

## 0.2 CC protection application layer version
After the protection of the network layer + the application layer, I subsequently increased the security protection of the application layer, such as the application layer protection module such as set cookie, url jump, js jump, etc.

## 0.1 CC Protection Edition
At that time, it was to solve the company's CC attack. Because some hardware anti-D devices could not obtain the user's real IP header under the new network environment (with CDN network), I started to complete the first version. At that time, the function was Define the limit on how often the HTTP header gets the user's real IP for access. (OpenStar can limit the frequency according to a certain url, not just the entire website [exclude static files, such as the allow operation of resources in referer \ _Mod or url \ _Mod]]

# TOP

[Installation] [3]

[Basic configuration instructions]  base.json[4]

[STEP 0：realIpFrom_Mod][10]

[STEP 1：ip_Mod][11]

[STEP 2：host_method_Mod][12]

[STEP 3：rewrite_Mod][13]

[STEP 4：host_Mod][14]

[STEP 5：app_Mod][15]

[STEP 6：referer_Mod][16]

[STEP 7：uri_Mod][17]

[STEP 8：header_Mod][18]

[STEP 9：useragent_Mod][19]

[STEP 10：cookie_Mod][20]

[STEP 11：args_Mod][21]

[STEP 12：post_Mod][22]

[STEP 13：network_Mod][23]

[STEP 14：replace_Mod][24]


Some students ask more questions:

0: problem with rule group
Support IFTTT mode, if the condition is (referred to include baidu or cookie does not contain abc and useragent regular match spider) and other complex expressions, there are multiple actions that can be used to perform actions (deny allow log refile rehtml relua *) Customize various complex scenes


1: About multi-site

Not to mention the additional configuration file using ngx itself, use dynamic upstream can refer to my other project https://github.com/starjun/dynamic_upstream-by-balancer
Some interfaces are not added, it is very easy to get a look at the code itself. The host and back-end IP group of the reverse proxy are in DICT (note that it is an IP group, not just an IP that is similar to some balancer writing dynamic upstream), and supports multiple load balancing methods. . I have time behind https to improve.

2: Cluster related (provided Master / Slave configuration)

At present, openstar supports clusters. The rules synchronization and delivery are provided with APIs, which are passive methods. Why are the rules not put in redis, please test it yourself, each time the rule filtering is serialized after being taken from redis And take the serialization from the dict, and test the performance by yourself. By the way, the rules are of course in the redis under the cluster, and they are updated to the dict through the api operation, rather than being taken from the redis every time, and recently Added the function of regularly pulling configuration from redis (testing ...)

3: If there are some technical problems, please try to be more complete, including the ngx configuration file, and the more complete code, otherwise it is really difficult to answer, I will try to reply when I have time (not necessarily correct), please do not have time to reply understanding.

admin@17173.com email is no longer in use, please don't email this.

## TODO ##

 None

  Business Edition description：

  ** Support domain name Management, geoip(intercept by Country, City, etc.), SQL semantic analysis (in perfect function), more powerful api interface, more powerful default rules, etc.**

----------

CC protection, anti-grab, brush single protection algorithm：

CC attack points：

a: user can directly access the url (search request [database query], high calculation [cpu calculation], random url [connection consumption], etc)

b: embedded type of url (embedded verification code url [CPU calculation], ajax to determine whether the user exists in the url [database query], etc)

c: Non-browser type of interface (some public API, WEBservice, etc.)

d: specific language, server attacks (php dos, slow attacks, etc)

I provide protection algorithm is used to protect a, B type of attack, a type of protection is enabled, you can add a mark into a jump page, B type of protection is enabled, the dynamic rendering of the page to add tags, C type has sdk, write their own code to support their own set of protection algorithm is not a problem.

js static and dynamic validation：

Jump page / render page url for the next request to mark the increase (openstar has achieved increased url tail), add a get of args parameters, parameter names and values are generated by the server or Front-End Page js generation, such as the next request url increase 'cc=1ldldj' this tail,the server determines the legality of the legality of a static js enhancement: (get mouse track, mouse click event, random delay, js dialect based on specific browser）

Mouse trajectory, mouse click event these events will not be judged to fail the next step request; such as browser-based js dialect, some browsers will have their own dialect, those reptiles tools and attack tools are not possible to resolve js dialect, it will not be the next step request; and the use of js random delay function for the next time

Browser fingerprint: (a unique fingerprint is generated on the browser to determine the consistency of the chain request fingerprint）
Advertising vendors to do this thing on the multiplier, after all, the browser fingerprint data in the entire internet is still very valuable reference, after all, not to fingerprint corresponding advertising labels and other commercial value data, only need a fingerprint credibility of the library (with IP reputation library similar, Of course, timeliness), because CC attacks and some reptiles, brush a single tool
The company can establish their own system, the CC attack, page crawl, brush alone is quite a big help, after the companies can share these browser fingerprint data, form a coalition also, in order to determine whether the fingerprint is real users and some of the available data.

http://123.57.220.116/fgjs2.html look at their browser fingerprint it (if you can not access, ha, I bought the ECS expired!)

Reference:https://github.com/Valve/fingerprintjs2


Controls / Browser Protection:

Use js for the next jump request, as well as enhanced mouse trajectory, mouse events, browser js dialect, etc. these judgments still have some flaws, it can be used directly control mode, or cooperate with the browser(browser supports this protection tag）


```
PS: simple example
http://www.cc.com?cc=@{"api":"http://1.1.1.1/cc/api","key":"iodjdjkdldskl"}@
http://www.cc.com?cc=@{"api":"tcp://1.1.1.1:908","key":"iodjdjkdldskl"}@
http://www.cc.com?cc=@{"api":"local","key":"1:2345:44"}@
Jump page or render page, control / browser can recognize the contents of the middle of@, to the api using key to take a value, the next request to bring this value.

```

i: set a cookie, its legitimacy is generated by the control and web server two-way agreement or encryption, in order to determine the next request is legitimate

ii: added The args parameter of the tail, which is the value of legality by the controls and web server two-way agreement or encrypted to produce, in order to determine the next request is legitimate

iii: increase the POST parameter, the legitimacy of its value value generated by the control and web server two-way agreement or encryption, etc. to verify the next increase in the request

## Key points ##

These protection algorithms I am applying for patents, personal users after permanent free, only for business charges, please copy the party, Shameless company let a younger brother.

These protection algorithms I am applying for patents, personal users after permanent free, only for business charges, please copy the party, Shameless company let a younger brother.

These protection algorithms I am applying for patents, personal users after permanent free, only for business charges, please copy the party, Shameless company let a younger brother.


# Overview


----------


** OpenStar* * is based on [OpenResty] [2], high-performance WAF, also a corresponding increase in other flexible, friendly, practical features, is enhanced WAF.
** app_Mod support rule Group connector support or, refer to doc/demo.md documentation**
# WAF protection


----------


In**OpenStar * * in the WAF protection module, using the traditional string matching such as regular filter, including, etc. (*Some people will ask now is not the popular self-learning; regular, including, etc. there will be blind spots, will be bypassed; WAF false positives and false negatives, and so on......*).** Rules are not a panacea, but no rules are absolutely impossible * * here I briefly explain, independent analysis learning engine is our log analysis engine (reserved for real-time api can increase interception), here is a high-performance, high-concurrency point, with a simple and quick way to solve, and according to the actual business to adjust the protection strategy, you can solve the
WAF protection from header,args,post,access frequency, etc., layered in order of protection, detailed in the back function will be described in detail

 - **WEB security 1.0**
   In the era of 1.0, the attack is through the server vulnerabilities (iis6 overflow, etc.), WEB application vulnerabilities (SQL injection, file upload, command execution, file contains, etc.) belong to the server type of attack, the type of vulnerability although after so many years, unfortunately, such a vulnerability exists, and repeat the same mistake.

 - **WEB security 2.0**
   With the rise of social networks, the original not to be valued XSS, CSRF and other vulnerabilities gradually into people's horizons, then in the 2.0 era, the idea of exploiting the more important, play to your imagination, there can be too many possible.

 - **WEB security 3.0**
   With similar development and design patterns (interface, business logic, Data), 3.0 will focus on the application itself, business logic and data security, such as password modification bypass, secondary password bypass, payment vulnerabilities, brush money and other types of vulnerabilities, it is the focus of the product itself, Business Security, data security, risk control security.

   > 'Security is not only in the technical level, should also be in the administrative management level, the physical level to do a good job of security protection, in order to provide maximum protection.`
   > Security industry for many years of experience: people, is the biggest threat; both external, internal, unintentional, intentional negligence.(No ugly women, only lazy women) I think you can apply here, is purely a personal opinion.

# CC / capture protection
What is the * * CC attack**, simply say, is to use less cost of malicious requests web (application) in the heavy resource consumption point (CPU / IO / database, etc.) so as to achieve the purpose of denial of Service; * * data collection**, is the content of the crawl, simple so understand it
> `Unofficial academic explanation, First will understand the next`

** About this article on the CC attack analysis and related protection algorithms, are my analysis and summary in the actual combat, and the formation of their own methodology, shortcomings, welcome correct.**

## Type of attack
 - Behavior (GET, POST, etc）
  At present, mainly in the two method attack, the other few.
 - The point of attack

    1: user-accessible URLs (search, heavy CPU calculations, IO, database operations, etc）

    2: embedded URL (captcha, ajax interface, etc）

    3: non-browser oriented interfaces (some APIs, WEBservice, etc）

    4: specific attacks based on specific web services, languages, etc. (slow attacks, PHP-dos, etc）

> `In the face of CC attack we need to use different protection algorithms according to the actual situation, such as the point of attack is an ajax point, you use js jump / captcha must have a problem`

## Protection methods
 - Network layer
 By accessing the ip of frequency, statistics, etc. using the threshold value of the mode frequency and the number of restrictions, the blacklist way

- Network layer+application layer
 In the later Internet network, with the CDN added, Now increase the network layer protection needs to be extended, then the statistics of IP will be in the HTTP header IP, still use frequency, frequency, blacklist mode operation.
 > 'But many manufacturers of hardware flow cleaning equipment, some users get real IP from the HTTP header is taken in a fixed field (X-FOR-F), can not be customized, and even some manufacturers do not have the function, here do not say the specific name of these manufacturers' PS: in the traditional 4-layer protection, there is no problem

- Application layer
TAG authentication, SET COOKIE, URL jump, JS jump, verification code, page nested, forced static cache, etc
We can not use JS jump, 302 verification code and other such methods; * * in many CC protection in combat, such as the use of url jump, set cookie, in the new CC attack, these guards have failed**.Later I will share my protection algorithm, and in the**OpenStar * * already can implement what I said protection algorithm according to the situation.
The browser can perform JS and flash, here I share some JS-based protection algorithm, flash need to write their own (more complex than js), can achieve security and anti-flash application layer page grab (start your brain it）

1: client protection
Use JS for front-end protection (browser recognition, mouse trajectory judgment, url rules add tail (args parameters), random delay, mouse and keyboard event acquisition, etc.)-[1,]` this particular JS, some JS dialects, some browsers have custom tags, etc`；

2: server-side protection
the tail of the url (args parameter) is a token generated dynamically by the server, rather than using a static regex to match its legitimacy.

3: specific attacks
This kind of specific attacks, can quickly match out by the characteristics (slow attack, PHP5.3 http header attack）

** Simple scenes**

1: url that the user can access directly(this is the best defense）

Phase one：

 - Network layer: access frequency limit, beyond the threshold only blacklisted for a period of time

 - Application layer: js jump, captcha, flash strategy (drag recognition, etc）

2: embedded url (ajax checksum, image captcha）

Phase one：

 - Network layer: access frequency limit, beyond the threshold only blacklisted for a period of time

 - Application layer: load the attacked url page, rewrite the page, use js to link the attacked url.js random increase in the url of the tail has a certain rule check string, the server-side string static regular check.

Phase two：

 - Network layer + application layer: the user ip in the http header, you need to take the ip from the http header, during the frequency limit
(In fact, done, this layer of protection, basically do not enter the third stage of the application layer protection）

 - Application layer: the verification string uses the token generated by the server side to carry out strict server token verification checks

Phase three：

 - Application layer: js increase browser recognition (different agent matching different js dialect code), js random delay, mouse trajectory verification, keyboard and mouse event verification js increase validation, during the check string generation.

Description:many combat CC processing experience, rarely to the third stage, of course, a good reserve of these js script is very important, pure JS is certainly limited, all I put forward the use of controls, and even more precise protection methods and browser vendors cooperation.This attack on the CC, page crawl, brush a single very good protective effect.

> Application layer protection is used when the network layer+extended network layer protection effect is poor, the general situation is not much basic use, because in the protection of OpenStar, under rare circumstances, the need for the third stage of protection.In the anti-page grab, play your imagination (js is a good helper, use) use OpenStar can help you quickly; of course, the use of flash anti-grab better (not flexible).

# Directory

Follow-up updates!~

# Download

wget

git clone

** Some scripts already packaged, please refer to the bash directory**

# Install
 - Install OpenResty
 Here do not do too much to repeat the description, look directly at the link [OpenResty][2]
 - Configure nginx.conf
 In the http node, reference the waf.conf.Note: the original ngx related configuration without modification, the optimization optimization, the CPU affinity binding continue, the dynamic and static separation also continue, the IO, TIME optimization continue not to stop.
 - Configure waf.conf
 If you have any questions or concerns, please do not hesitate to contact us.
 - Set directory permissions
 OpenStar directory recommended to OR, easy to operate, the directory ngx run the user has read and write permissions can be.Because to write the log,*is not used ngx.log, follow-up may change*.
 - lua file modification
 Init.lua, modify the conf_json parameter, base.the absolute path of the json file is written correctly according to your situation.
 - api usage
June 7, 2016 23:31:09 update, citing waf.the interface is also in the planning, looking forward to someone can join, help me with the whole interface.

** Some scripts have been packaged, please refer to the bash directory, please read before running, thank you for your help to write the script**

# Use

## Configure rules

The second parameter identifies the first parameter type,and the third parameter indicates whether or not to negate, and the default is ' nil ' or 'false' means no negation

hostname：`["*",""]` = `["*","",false]`

= = >Means match all domain names(using string matching, non-regular, very fast）

hostname：`["*\\.game\\.com","jio"]`

This is the default <url> page that is distributed with NGINX on Fedora.)**）

hostname：`[["127.0.0.1","127.0.0.1:8080"],"list"]`

==>匹配 匹配 匹配 参数 参数 参数1 列表 列表中 所有有host = > > means match parameter 1 list all host

hostname：`[{"127.0.0.1":true,"127.0.0.1:5460":true},"dict"]`

==>Indicates that host is true in the matching dictionary

uri：`["/admin","in"]`

= = >Means all Uris containing/admin in the matching uri will be matched (**string.find ($uri, argument 1, 1, true)**）

ip：`[["127.0.0.1/32",""113.45.199.0/24""],"cidr"]`

= = >Indicates the matching ip in both ip segments/ip

args：`["*","",["args_name","all"],false]`
args：`["*","",["args_name","end"]]` = `["*","",["args_name","end"],false]`
args：`["*","",["args_name",1]]`

Description: the first three parameters represent the key name of the args parameter table,the first three parameters[2]represents the args[args_name]table, match any(all), match the last(end), match the first(number), the default take the first

==>The args parameter for Get Matching is named args_name, use the 4th parameter pattern to match, the matching rule is the first and the second parameter.Wherein the first and second parameters to support the rules described above.

** table type matching rules more trouble, temporarily thinking about is such a deal, have a good idea can tell me**
## Execution process

![enter description here][5]

 - init stage

 a: first load the local base.json configuration file, the configuration is read to config\_dict, host\_dict, ip\_dict

 - access stage (top to bottom execution process, the list of rules is also top to bottom in order to perform）

 0: realIpFrom_Mod ==> get user real IP (get from HTTP header, as set）

 1: ip_Mod ==> request ip black / white list, log record

 2:host\_method\_Mod ==> host and method filter (whitelist）

 3:rewrite_Mod ==> jump module, set-cookie operation

 4: host_Mod ==> filter (uri,referer,useragent, etc.)）

    Here are the filtering rules available to individual users in the product.Currently supports custom rule groups (arbitrary parameters, arbitrary combinations）

 5: app_Mod ==> user-defined application layer filtering

 6: referer_Mod = = > referer filter (black / white list, log record）

 7: uri_Mod ==> uri filtering (black / white list, log record）

 8: header_Mod ==> header filter (blacklist）

 9: useragent_Mod ==> useragent filter (black / white list, log record）

 10: cookie_Mod = = > cookie filtering (black / white list, log record）

 11: args\_Mod = = > args parameter filtering [actual is query_string] (black / white list, log record）

 12: post_Mod = = > post parameter filtering [actual entire post content] (black / white list, log record）

 13: network_Mod ==> application layer network frequency limit (frequency blacklist）

 - body stage

 14: replace\_Mod = = > content replacement rules (dynamic content replacement, high performance consumption with caution, you can use app\_Mod in rehtml, refile these 2 custom action）

## <span id = "step0">STEP 0 : realIpFrom_Mod </span>

 - Description：
`{"101.200.122.200:5460": {"ips": ["*",""],"realipset": "x-for-f"}}`

 With the example above,表示域名id.game.com, from the IPs to the direct connect ip, the user's real ip in x-for-f, ips is to support the second-order matching, you can refer to the example to set, ips\*, said it does not distinguish between direct connect ip.

## STEP 1: ip_Mod (black / white list, log record）

 - Description：
 `{"ip":"111.206.199.61","action":"allow"}`
`{"ip":"www.game.com-111.206.199.1","action":"deny"}`

 The example above, indicates that the ip is 111.206.199.61 (fetched from the http header, as set) whitelist
 action can take the value of [allow, deny], den represents the Black List; the second represents the corresponding host ip black/white list, other host is not affected.

 [Back] (#top)

## < span id = "step2">STEP 2: host\_method\_Mod (whitelist)< / span>

 - Description：
 `{"state":"on","method":[["GET","POST"],"list"],"hostname":[["id.game.com","127.0.0.1"],"list"]}`

  The example above shows that the rules are open, host为id\.game\.com, 127.0.0.1 allowed method is GET and POST
  state: indicates whether the rule is open
  method: indicates the allowed method, parameter 2 identifies parameter 1 is a string, A List (list), A Regular Expression, a dictionary (dict)
  hostname: indicates the matching host, the rules are the same

  > **`"method": [["GET", "POST"], "list"] ' ==> means the matching method is GET and POST**

  > **'"method": ["^(get / post)$", "jio"] ' = = > indicates that the matching method is a regular match**

  > * * '"hostname": ["*",""]` ==>indicates that an arbitrary host is matched (string matching, non-regular, very fast）**

  > * * A lot of the following rules are used to match the way**

[Back] (#top)


## STEP 3: rewrite_Mod (jump module）
- Description：
```
    {
        "state": "on",
        "action": ["set-cookie"],
    "set_cookie":["asjldisdafpopliu8909jk34jk","token_name"],
        "hostname": ["101.200.122.200",""],
        "uri": ["^/rewrite$","jio"]
    }
```
The above example shows that the rule is enabled, host is 101.200.122.2200, and the url matches the 302/307 jump, and set a stateless cookie, the name is token.the second parameter in the action is the user ip+and change the parameters for the md5 calculation.Use a meaningless string yourself.Prevent attackers from guessing the algorithm.

 [Back] (#top)

## STEP 4：host_Mod
 - Description：
 The module is to match the corresponding host rule matching, in conf_json / host_json / directory, the local host-based matching rules
 Support host.state state support [on log off], log means that the original match is blocked will fail, off means no rules filtering

## < span id = "step5">STEP 5: app_Mod (custom action)</span>
 - Description：
 ```
{
    "state":"on",
    "action":["deny"],
    "hostname":["127.0.0.1",""],
    "uri": ["^/([\w] {4}\.html/deny1\.do/你好\.html)$","jio"]
}
 ```

  The above example shows that the rule is enabled, the host is 127.0.0.1, and the url is consistent with the regular match, Access is denied

  state: whether the rule is enabled
  action: perform an action

  1: deny ==> deny access

  2: allow ==> allow access

  3: log ==> log only

  4: rehtml ==> means return custom string

  5: refile ==> returns a custom file (returns the contents of the file）

  6: relua ==> means return lua to execute the script(using dofile operation）

  7: relua_str ==> returns lua code execution

  hostname: the matching host

  uri: the matching uri

  > * * hostname and uri use the matching rules described above, parameter 2 tag, parameter 1 content**

  > * * See the demo rules in the project for more details.**

  > * * All kinds of advanced functions basically rely on this module to achieve, you need to play the imagination**

 [Back] (#top)

## STEP 6: referer_Mod (whitelist）

 - Description：
 `{"state":"on","uri":["\\.(gif|jpg|png|jpeg|bmp|ico)$","jio"],"hostname":["127.0.0.1",""],"referer":["*",""],"action":"allow"}`

  Here put some pictures and other static resources can be put here, because the use of OpenStar, you do not need to access_by_lua_file specifically put different location dynamic node nginx go, so that the subsequent matching rules do not match these static resources, reduce the overall number of matches, improve efficiency]**, action represents the action performed,`allow`represents the rule all subsequent rules (usually static resource picture), referer match fails to deny access (white list), anti-chain-based; anti-rules can be set outside the CSRF protection station

  state: indicates whether the rule is open
  uri: the uri that represents the match
  hostname: match host
  referer: match referer
  action: match action

  > referer match is a white list, note that you can
  > These matches are based on the second-order matching method described above

 [Back] (#top)

## STEP 7: uri_Mod (black & white list）

 - Description：
 `{"state":"on","hostname":["\*",""],"uri":["\\.(css|js|flv|swf|zip|txt)$","jio"],"action":"allow"}`

  The above example shows that the rule is enabled, any host, and the uri is released after a regular match is successful, and no subsequent rule matching is performed(the same scene is released as a static resource such as an image, and subsequent matching is reduced）
  state: indicates whether the rule is open
  hostname: indicates the host that matches
  uri: indicates a matching uri
  action: a value of [allow, deny, log] indicates the action to be performed after a successful match

  > Under normal circumstances, after filtering static resources, the rest is to deny access to the uri, such as.some sensitive directories or files like svn

 [Back] (#top)

## STEP 8: header_Mod (blacklisted）

 - Description：
 `{"state":"on","uri":["\*",""],"hostname":["\*",""],"header":["Acunetix_Aspect","\*",""]}`

 The above example shows that the matching of the acunetix_aspect content in the rule enable, match arbitrary host, arbitrary uri, header (this match arbitrary content) this match is some scanner filtering, the rule is the feature of the wvs scanner
 state: whether the rule is enabled
 uri: match uri
 hostname: match host
 header: Match header header

 [Back] (#top)

## STEP 9: useragent_Mod (blacklisted）
  - Description：
  `{"state":"off","action":"deny","useragent":["HTTrack|harvest|audit|dirbuster|pangolin|nmap|sqln|-scan|hydra|Parser|libwww|BBBike|sqlmap|w3af|owasp|Nikto|fimap|havij|PycURL|zmeu|BabyKrokodil|netsparker|httperf|bench","jio"],"hostname":[["127.0.0.1:8080","127.0.0.1"],"list"]}`

  The above example shows that the rule is closed, the matching host is 127.0.0.1 or 127.0.0.1: 8080, and the useragent regular match is denied access if the match succeeds.":["*",""]` represents all (string matching, very fast）
  state: whether the rule is enabled
  hostname: match host
  useragent: match agent
  action: match action

 [Back] (#top)

## STEP 10: cookie_Mod (blacklisted）
 - Description：
 `{"state":"on","cookie":["\\.\\./","jio"],"hostname":["*",""],"action":"deny"}`

  The above example shows that the rules are enabled, match any host, the cookies match the regular, and the matching is successful
  state: indicates whether the rule is enabled
  cookie: means match cookie
  hostname: match host
  action: the optional parameter [deny, allow] indicates that the action is performed

  > action can be added to other actions, so this is reserved, otherwise the blacklist does not need the action parameter

 [Back] (#top)

## STEP 11: args_Mod (Black List）

 - Description：
 `{"state":"on","hostname":["*",""],"args_data":["\\:\\$","jio"],"action":"deny"}`

 The above example shows that the rule is enabled, matches any host, and the query_string parameter group matches the regular rule.
 state: indicates whether the rule is enabled
 hostname: match host
 query_string: indicates that the args parameter group is matched
 action: indicates that the match was successful and access was denied

 [Back] (#top)

## STEP 12: post_Mod (Black List）
 - Description：
 `{"state":"on","hostname":["*",""],"posts_data":["\\$\\{","jio"],"action":"deny"}`

  The above example shows that the rule is enabled, matches any host, and the post_str parameter group matches a regular rule.
  state: indicates whether the rule is enabled
  hostname: match host
  post_str: matches the post parameter group
  action: access is denied after a successful match

 [Back] (#top)

## STEP 13: network_Mod (frequency blacklist）
 - Description：
 `{"state":"on","network":{"maxReqs":20,"pTime":10,"blackTime":600},"hostname":["id.game.com",""],"uri":["^/2.html$","jio"]}`

  The example above says that the rule is enabled, host为id.game.com, url matches the regular, matching the success of the access frequency limit, in 10 seconds more than 20 times the number of visits, the requested IP to IP blacklist 10 minutes (60 seconds\ * 10）
  state: indicates whether the rule is enabled
  hostname: match host
  uri: indicates a matching uri
  network: maxReqs = = > number of requests; pTime ==> unit time; blacktime = = > ip blacklist duration

  > In general, the point of cc attack a site is only one of the few places that are vulnerable to attack, so when designing, consider adding a match through url refinement.

 [Back] (#top)

## STEP 14: replace_Mod (content replacement）
 - Description：
 `{"state":"on", "uri":["^/$","jio"], "hostname":["passport.game.com",""],"replace_list": [["Union","","Joint FUCK"], ["login","", "Login POSS"], ["lzcaptcha\\?key=' \\s\*\ + key", "jio", " lzcaptcha?keY='+key+'&keytoken=@token@'"]]}`

  The example above says that the rule is enabled, host为passport.game.com, url is a regular match, the match is successful to return the contents of the replacement
  1: replace "joint" with " joint FUCK"；
  2: replace login with login POSS"；
  3: match by regex ('ngx. re. gsub') where@token@represents a dynamic substitution for a unique random string generated by the server
  state: indicates whether the rule is enabled
  hostname: indicates the host that matches
  uri: the uri that represents the match
  replace_list: indicates the replacement list, parameter 1 = = > is replaced by the content; parameter 2 ==> matching pattern(regular, string) as in the example of the first two replacement list is a string match, use "" can, can not be no; parameter 3 ==> is replaced by the content

# API related
Refer to the api in the doc directory.md description

# Example
- See doc, demo.md description


# Performance evaluation

** Operating system information**
OpenStar test server：

```
 Microsoft Virtual Machine, intranet testing

 uname -a :
 Linux dpicsvr01 4.2.0-30-generic #36-Ubuntu SMP Fri Feb 26 00:58:07 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux

 Memory：
 cat /proc/meminfo | grep MemTotal
 MemTotal:       14360276 kB// 14GB

 CPU model: cat / proc / cpuinfo / grep 'model name' / uniq
 Intel(R) Xeon(R) CPU E5-2660 0 @ 2.20GHz

 CPU cores: cat / proc / cpuinfo / grep "cpu cores" | uniq
 4

 CPU: cat / proc / cpuinfo / grep "physical id" | uniq | wc-l
 1
 ab：
 ab -c 1000 -n 100000 "http://10.0.0.4/test/a?a=b&c=d"
```
Test results：
![enter description here][6]
 Can be seen through the picture, close all the rules, did 2 tests, take the highest '8542'；

 Enable rules (exclude app, network, replace), test result '8388', performance drop '1.81%'；

 Enable rule (exclude replace, app is not enabled relua this high consumption point), test results '7959', performance degradation '6.83%'；

 Enable rules (exclude useragent, ab tool is blocked by default, the second Test is not complete. Test results '7116', performance degradation ' 16%'；

 In general, after enabling the rules, the performance loss can be accepted, adjusted according to their own business, but also can be optimized.


# About

- On the front of the project actually has said a lot, from scratch to have said, stressed, thank you, [loveshell][9]!！！
- About me: security, architecture-related work.
- Copyright and License
GPL（GNU General Public License）
Copyright (C) 2011-2016, by zj


  [1]: https://github.com/agentzh
  [2]: http://openresty.org/cn/
  [3]: https://github.com/starjun/openstar/wiki/%E5%AE%89%E8%A3%85%E7%AF%87
  [4]: https://github.com/starjun/openstar/wiki/base.json
  [5]: ./doc/Openstar.jpg "OpenStar.jpg"
  [6]: ./doc/test.png "test.png"
  [7]: https://moonbingbing.gitbooks.io/openresty-best-practices/content/index.html
  [8]: http://www.modsecurity.org/
  [9]: https://github.com/loveshell/ngx_lua_waf
  [10]: https://github.com/starjun/openstar/wiki/0-realIpFrom_Mod
  [11]: https://github.com/starjun/openstar/wiki/1-ip_Mod
  [12]: https://github.com/starjun/openstar/wiki/2-host_method_Mod
  [13]: https://github.com/starjun/openstar/wiki/3-rewrite_Mod
  [14]: https://github.com/starjun/openstar/wiki/4-host_Mod
  [15]: https://github.com/starjun/openstar/wiki/5-app_Mod
  [16]: https://github.com/starjun/openstar/wiki/6-referer_Mod
  [17]: https://github.com/starjun/openstar/wiki/7-uri_Mod
  [18]: https://github.com/starjun/openstar/wiki/8-header_Mod
  [19]: https://github.com/starjun/openstar/wiki/9-useragent_Mod
  [20]: https://github.com/starjun/openstar/wiki/10-cookie_Mod
  [21]: https://github.com/starjun/openstar/wiki/11-args_Mod
  [22]: https://github.com/starjun/openstar/wiki/12-post_Mod
  [23]: https://github.com/starjun/openstar/wiki/13-network_Mod
  [24]: https://github.com/starjun/openstar/wiki/14-replace_Mod
