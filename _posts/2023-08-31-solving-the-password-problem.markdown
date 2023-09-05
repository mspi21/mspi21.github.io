---
layout: post
title:  "Solving the password problem"
date:   2023-08-31 18:23:10 +0200
categories: blog security
---
Passwords are an incredibly simple authentication mechanism<sup>1</sup>. If you know the password, you are authenticated, if you don't, you're not. They are probably the number one thing that you think of when you hear the words "computer security". *So what is "the password problem"?*

<small>\[1\] Authentication = making sure that the person or program (on the other side of the network, for example) is who or what they claim to be.</small>

Well, it turns out passwords aren't such a great method of authenticating computer users on the internet, for several reasons:

**# 1 --- How passwords are stored**

It used to be the case that an application on the internet would ask the user for their username and password, and when the user clicked on the login button, the browser would send the username and password unencrypted over the internet to the server. The server would then read the request, compare the submitted password to the one it had stored somewhere in its database and if it matched, it would let the user in.

This was probably fine back in the early 2000s, since there would be hardly any profit for an attacker to steal someone's account on a science fiction forum site. But as web applications began playing a more and more critical role, with banks, government websites, industrial infrastructure and the lot relying on web services for their existence, sending a password unencrypted over a network became unviable, as did keeping a database full of users' human readable (*plaintext*) passwords.

Eventually, websites started adopting the HTTPS protocol, which (when set up properly...) takes care of encryption between the user's browser and the web server, so that a third party cannot read (or alter) the messages they exchange. As for storing passwords in the database, a rather clever piece of cryptography was used to solve the issue: a *hashing function*.

A cryptographic hashing function is kind of like a fingerprint, or you can think of it as a blender --- you pour in your data (e.g. a password), the function does some transformations to it, and out comes a bunch of totally random-looking gooey paste, which we call the hash. The hashing function has to satisfy some important conditions. One necessary property is that given the same input, it will always generate the same output (the function is what we call an *oracle*). This means that the server can take a sample of the gooey paste when saving the password for the first time, and whenever it then receives your password again (over an encrypted channel), it can simply put it in its own copy of the blender and compare the outcome gooey paste to the sample it saved upon registering the user. The second necessary property of a hashing function is that it is irreversible<sup>2</sup> and random, i.e. any (possibly small) change in the input has to result in an unpredictably different gooey paste coming out of the blender.

<small>\[2\] Irreversible = reversible with unreasonable difficulty.</small>

{% highlight shell %}
$ printf password | sha256sum
5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
$ printf passwort | sha256sum
33c5ebbb01d608c254b3b12413bdb03e46c12797e591770ccf20f5e2819929b2
{% endhighlight %}
<small>A SHA-256 hash of the words *password* and *passwort*.</small>

So, with the database only storing hashes and not passwords in plain text, web security was achieved and no attacks ever happened again. Well, except they did. While it is impossible to reverse the hash into the original text, it turns out that if an attacker can steal hashed passwords from a database, they can simply run the hash function on a list of potential passwords (what we call a *dictionary attack*, or in this case a *rainbow table attack*) and see if any stolen hashes match one of the pre-computed hashes. Furthermore, if two users shared the same password, their hashes would be the same, providing additional information to the attacker. That is one of the reasons it was advised not to reuse passwords across different websites --- if your password was cracked once, determining whether you used the same password on a different (vulnerable) website was a matter of comparing the hashes.

Fast forward to today, it seems that most of the issues regarding password hashes have been addressed, at least in theory. To mitigate the issue described in the previous paragraph, a random block of data (a *salt*) is generated for each user and hashed together with the password, ensuring that users with matching passwords don't have the same hash and that rainbow-table attacks (comparing known hashes) are not possible. Sometimes, a server-side secret (a *pepper*) is also added to the mix. Finally, much slower and more resilient algorithms were invented that make cracking passwords a painfully slow process.

That sounds great, it seems like humans know how to store passwords these days. But how can you know if the web application you use combines your password with a salt and/or a pepper? How can you know if it uses the right algorithms with the right parameters? Well, if it's a bank we're talking about, they absolutely do --- the law requires them to. But what about that online shop selling fantasy movie merch that was probably coded by the shopkeeper's nephew who's in high school and *really good with computers*?

This is the reason why, even today, it's kind of important to think about what kind of passwords you use with what kinds of online services. You might not want to share the same password between your internet banking and an online game account.

**# 2 --- What passwords people choose**

If you're not really interested in computer security, chances are that your passwords start with an uppercase letter, contain one or two words and end with a number, maybe ocasionally followed by a single special character. And you're not alone. Web security is not a baby anymore, but it is kind of like an adolescent --- its adult qualities are starting to emerge and form a solid foundation, but the shell of a confused teenager who isn't quite sure who they are can still be seen on the surface. At least that's the impression I get from websites guiding (forcing) their users to pick "appropriate" passwords.

Sometimes grotesquely reminiscent of the [password game](https://neal.fun/password-game/){:target="_blank"}, some sites will just not let you sign up unless your password has at least one lowercase letter, one uppercase letter, a number, a special character, a name of a greek god and a solution to a linear recurrence equation. (An even more absurd fact is that some services, on the other hand, limit the password length to at most 8 (or 10, 12...) letters or disallow any special characters at all.) But humans are extremely predictable. Almost everyone starts with a simple password, and if it's not enough, they capitalize the first word or add a number at the end. The result is a universal password template that usually passes all requirements across different websites and therefore requires the least amount of effort to use. All this is not to mention that apparently, the most widely used password in 2022 was... still the word 'password'.<sup>3</sup>

<small>\[3\] No, I don't know how people get these statistics, so take it with a grain of *salt*.</small>

So why don't people just agree on what security researchers find to be the proper requirements for a password and just use that? Well, there is in fact a great guide by the [OWASP project](https://owasp.org/){:target="_blank"} for developers addressing exactly this --- what passwords should be allowed, disallowed, encouraged, etc. The only problem is that one barely ever comes across a service that fully adopts these recommendations (or even at least most of them).

Hence the user is faced with a dilemma. Since no one can remember as many unique and random passwords as they use online services, should you use a single password (or a password "template") everywhere and sacrifice *some* security, or should you generate random passwords for every online service and keep them stored somewhere, massively sacrificing convenience?

**# 3 --- Two-factor authentication (2FA) and One-time passcodes (OTP)**

Another inherent problem with passwords is that they do not prove someone's *identity*, they only prove someone's *knowledge*. I can tell my relatives or my partner my password and they can use it the same as I can, but that doesn't mean they're me. But applications often need verification of identity, not knowledge. This is why it's become a huge trend during the past ~5 years for applications to use something called Two-factor authentication, where one factor of authentication is the knowledge of a passphrase and the other factor is e.g. possession of a physical device, access to text messages, etc. Typically, you enter your password and then you are prompted to enter an OTP code sent to your phone number via SMS, or to your email, etc.

There can be almost no doubt about the security of this mechanism. It is much harder for an attacker to steal your password *and* your phone, compared to just the password alone. Furthermore, when the password is compromised, the service simply informs its users, requires them to reset their passwords and the attacker's efforts are wasted.

There's just one problem --- again, this is terribly inconvenient, especially if you regularly clear the cookies in your browser (thus the service does not "remember you", or your browser, to be precise). While for example the iPhone supports pasting of SMS codes with a single tap, that still doesn't make the process any more convenient on a desktop computer.

Or so it used to be.

## The solution

__Use a password manager.__ It's that simple. Well, not *that* simple. You still need to think about and pay attention to a couple details, but once you're done with the setup, it's a solution that is bullet-proof, because it's __secure *and* convenient__.

**What the heck is a password manager?**

It's exactly what it sounds like. It's sort of a digital vault or notebook where you keep all of the passwords across all of the services you use. That alone may not sound that convenient, but a password manager is much more than just an encrypted note. Some popular features of passwords managers are:
- Filling login information with one click. PMs usually come with an Android app, an iOS app as well as browser extension for most popular browsers, so once you authenticate yourself with your master password (or Face ID, a fingerprint, ...), filling out login information becomes trivial, while maintaining good password strength.
- Automatic generation of random, strong passwords. These can be human readable (memorable) or completely random gibberish, with adjustable length, etc.
- Notifications whenever one of your passwords is cracked. PMs communicate with a database of leaked passwords that were compromised in an attack, which is regularly updated. So whenever one of your passwords appears in the database, the PM informs you and urges you to change the password wherever it's used.
- Encrypted notes and card infos. Despite being called password managers, nothing stops you from using them to store PINs, passwords for physical locks, answers to security questions or your hard disk encryption keys.
- **Providing 2FA and automatic filling of OTP codes (!).** A newer form of 2FA relies on third-party OTP providers (such as Google Authenticator, Microsoft Authenticator, etc.) to provide independent OTP generation. Services that support this include GitHub, Twitch, and many more. Some password manager services include their own authenticator to use in place of Google or MS, making life much easier thanks to autofill.

**So how do I set one up?**

I can't help but recommend the [Proton Pass](https://proton.me/pass){:target="_blank"} manager. Of course, there are other good alternatives (I have also used [Bitwarden](https://bitwarden.com/){:target="_blank"} for some time), but in the end I decided to accept a limited offer from Proton and get the Proton Pass Plus for 1&euro;. Proton offers a free variant, but the plus version features unlimited e-mail aliases and the integrated 2FA authenticator I mentioned before, which is well worth the money in my opinion.

In general, it is a good idea to use a popular open source password manager, since open-source software can be inspected by anyone with internet access and any security flaws can thus be found much quicker by the community. Proton Pass also has a [publicly available report from a penetration test](https://drive.proton.me/urls/AS97HV90MW#1RzmiLrBTUg4){:target="_blank"} conducted by Cure53 in June of this year, indicating that thorough, professional testing was done to verify the security of the software.

As for the actual setup, the process will be mostly the same for all PMs. I recommend to put your best effort into creating a strong, memorable master password to unlock the vault --- since it is the only password you will have to remember, it is well worth it. For some tips on choosing a strong password, see the appendix below.

Note that none of the problems discussed above apply to the master password used to unlock the vault:
1. The password isn't stored in a database, it only serves as an encryption key to encrypt and decrypt the data in your vault.
2. You don't have to worry about reusing passwords or memorizing many different ones, you only need one strong memorable password to access all others that can be randomly generated and then auto-filled or copied and pasted.
3. Two-factor authentication is typically not used with password managers (which however also means that only you must know the master password).

**Aren't there any attacks against password managers?**

Well, a password manager is still just a service. While it is unlikely that someone without your master password will decrypt your passwords (thanks to strong, secure ciphers), it is not unthinkable that it gets attacked, becomes unavailable, or shuts down completely. Just for peace of mind, it may be desirable to memorize the most important information and/or keep a copy elsewhere. It is ultimately up to you whether all your passwords will be randomly generated or if you still pick them yourself and just use the PM as a backup for when you forget. Regardless, a forgotten password isn't as bad as a weak password, since almost all online services provide and are required to provide a password reset mechanism, using for example email as verification.

Another thing to be mindful of is auto-filling without user interaction. Bitwarden, for instance, allows auto-filling credentials immediately when the login page is loaded. This can be a little dangerous in practice, since the website is technically not guaranteed to hide the password. So, if you're doing a live presentation or you are sitting in a full lecture/conference hall, I'd suggest leaving the autofill-on-load feature off and instead autofill passwords by explicitly interacting with the password manager UI.

## Appendix: Types of attacks against passwords

When choosing a password or assessing a password's strength, it is key to take into account the different kinds of attacks that can be conducted against you.

**Scenario #1: A password leak**

When you use a password that was compromised in the past and don't have 2FA set up, it is not unlikely that eventually some bot somewhere in Russia will try that password with your username or email and get access to your account.

**Scenario #2: A dictionary/brute-force attack**

This is already a more complex topic. To recapitulate, a dictionary attack consists of an attacker using a dictionary of common words or passwords, optionally along with a couple rules to combine them (for example, flower becomes Flower1, fl0w3r, flowerflower, etc.) and trying passwords until the correct one is found. A brute force attack consists of an attacker trying *all possible combinations* of characters from an alphabet up to a certain length, so for example all combinations of lowercase and uppercase letters up to 8 characters. In this scenario, the attacker knows almost nothing about the victims and is going off of probability alone. The more password hashes they get, the higher the chance of one of the passwords being weak (= short or common). At the same time, this kind of attack is the most common in practice. (Although, of course, almost surely the attacker will try all leaked passwords at his disposal first.)

It is worth noting that the time required to guess a password by brute force grows exponentially with the length of the password, so while it takes on average ~154 million attempts to crack a 6-letter all-lowercase password, it takes ~4.7 * 10^16 attempts to crack a 12-letter password with the same alphabet. So, if the 6-letter password takes on average 1 second to crack<sup>4</sup>, the 12-letter one will take 9 years and 290 days on average.

As for dictionary attacks, in practice, only relatively small dictionaries can be used, so only the most common words are checked. Combining even two or three unusual words into a password should be enough to protect yourself from a dictionary attack.

<small>\[4\] That of course depends on the hashing function which is used and how many times it is applied, as well as the hardware capabilities of the attacker. The recommended, de-facto standard in 2023 for password storing is the Argon2 hashing algorithm.</small>

So, to protect yourself from brute-force and dictionary attacks, use either passphrases comprising of several non-common words (optionally add numbers or special characters, but it is not necessary), or use randomly generated ones with at least 8 or more characters, including letters, numbers and special characters.

**Scenario #3: A targeted attack**

This is probably not an attack that should worry you too much unless you're a president of a country, a critic of a totalitarian regime, or an otherwise publicly known figure. (If you are, you should probably not be taking security advice from some guy on the internet.)

In what I call a targeted attack, the attacker gathers (or already has) information about the subject of the attack. For example, let's say you wanted to get into my CTU email. You would go online and look for information about me. You would look at my Facebook profile, my Instagram page, you would take note of the places I have visited, my interests, my date and place of birth, and so on, and you would hand-craft a dictionary suited specifically to try passwords that I could have chosen.

So while the password `open your eyes, look up to the skies` would take millenia to crack with a brute-force approach and it's highly unlikely to be in any dictionary, you should keep in mind that a targeted attack is still possible in theory, if it's a well known fact that you're a massive Queen nerd or if you've let people know in your blog that song lyrics make great passwords.
