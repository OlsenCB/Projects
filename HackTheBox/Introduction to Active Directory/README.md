HackTheBox Introduction to Active Directory 

# Active Directory Fundamentals

## Active Directory Structure

### Q1: What Active Directory structure can contain one or more domains?

In large enterprise environments, we need a top-level security boundary. This role is fulfilled by the **Forest**, which acts as a container for one or more domain trees that share a common global catalog and logical structure.

### Q2: True or False; It can be common to see multiple domains linked together by trust relationships?

**True**. Trust relationships are the backbone of cross-domain resource access, allowing users from a "Marketing" domain to authenticate against resources in a "Production" domain within the same organization.

### Q3: Active Directory provides authentication and <____> within a Windows domain environment.

AD serves a dual purpose: it first verifies identity via authentication and then determines specific access rights through **authorization**, ensuring that users only interact with permitted resources.

## Active Directory Terminology

### Q1: What is known as the "Blueprint" of an Active Directory environment?

Every object and attribute in the directory must follow a strict definition. This master "blueprint" is called the **Schema**, and it dictates what data can be stored (e.g., user phone numbers, machine names).

### Q2: What uniquely identifies a Service instance? (full name, space-separated, not abbreviated)

For Kerberos to function, every service needs a unique identifier linked to a service account. This is known as a **Service Principal Name** (SPN), which is a frequent target during "Kerberoasting" attacks.

### Q3: True or False; Group Policy objects can be applied to user and computer objects.

**True**. GPOs are highly flexible, they can be used to enforce screen lock timers for users or to push specific registry settings and software updates to computer objects.

### Q4: What container in AD holds deleted objects?

When an object is removed, it is moved to a hidden location known as the Deleted Objects container (or **Tombstone**), where it remains for a set period before permanent deletion.

### Q5: What file contains the hashes of passwords for all users in a domain?

The "holy grail" for attackers is the **ntds.dit** file. Located on Domain Controllers, this database stores all domain data, including the encrypted password hashes for every account.

## Active Directory Objects

### Q1: True or False; Computers are considered leaf objects.

**True**. In the hierarchical structure of Active Directory (based on LDAP), a "leaf" is an object that cannot contain other objects. Since you cannot nest a user or another group inside a computer object, it sits at the end of its branch.

### Q2: <___> are objects that are used to store similar objects for ease of administration. (Fill in the blank)

**Organizational Units (OUs)** act as specialized containers used to group users, groups, and computers. Their primary purpose is to simplify administration by allowing GPOs to be linked to specific departments and delegating administrative control without granting full domain privileges.

### Q3: What AD object handles all authentication requests for a domain?

The **Domain Controller (DC)** is the server responsible for the entire security mesh of the domain. It hosts the AD DS role, maintains the directory database, and acts as the gatekeeper by verifying user credentials and issuing Kerberos tickets.

## Active Directory Functionality

### Q1: What role maintains time for a domain?

Precise time is critical for security protocols. The **PDC Emulator** FSMO role acts as the authoritative time source for the domain to prevent clock skew issues during authentication.

### Q2: What domain functional level introduced Managed Service Accounts?

To improve security for service passwords, Microsoft introduced MSAs starting with the **Windows Server 2008 R2** functional level, automating password rotation for automated tasks.

### Q3: What type of trust is a link between two child domains in a forest?

To optimize the authentication path between two domains in the same forest and avoid the "long way" through the parent domain, admins can implement a **Cross-link** trust (also known as a shortcut trust). This directly connects two subdivisions of a domain tree to speed up logons and resource access.

### Q4: What role ensures that objects in a domain are not assigned the same SID? (full name)

The **Relative ID Master** (Relative ID) is responsible for handing out unique blocks of IDs to each Domain Controller, ensuring that every new user or group gets a unique Security Identifier.

# Active Directory Protocols

## Kerberos, DNS, LDAP, MSRPC

### Q1: What networking port does Kerberos use?

When troubleshooting or sniffing Kerberos traffic, we look for activity on **port 88**. It is the standard port used by the Key Distribution Center (KDC).

### Q2: What protocol is utilized to translate names into IP addresses? (acronym)

Without **DNS**, Active Directory would fail to function. It allows clients to resolve human-readable names into IP addresses and find Domain Controllers via SRV records.

### Q3: What protocol does RFC 4511 specify? (acronym)

RFC 4511 defines the standards for **LDAP** (Lightweight Directory Access Protocol), which is the primary language used to query or modify objects within the AD database.

## NTLM Authentication

### Q1: What Hashing protocol is capable of symmetric and asymmetric cryptography?

While NTLM is older, **Kerberos** provides a more robust framework using tickets and both symmetric and asymmetric encryption to protect credentials in transit.

### Q2: NTLM uses three messages to authenticate; Negotiate, Challenge, and <__>. What is the missing message? (fill in the blank)

The NTLM authentication process follows a specific three-step handshake. First, the client sends a "Negotiate" message, the server replies with a "Challenge," and finally, the client must **Authenticate** by sending a response that proves they know the password without actually transmitting it.

### Q3: How many hashes does the Domain Cached Credentials mechanism save to a host by default?

Windows typically caches the last **10** successful logins. This "mscache" allows users to log in when the DC is offline, but these hashes can be targeted by offline cracking tools.

# All About Users

## User and Machine Accounts

### Q1: True or False; A local user account can be used to login to any domain connected host.

**False**. Local accounts are tied to the local SAM database of one specific machine. To log into any machine in the network, a Domain Account is required.

### Q2: What default user account has the SID "S-1-5-domain-500" ?

The SID ending in -500 always identifies the built-in **Administrator** account. This RID is a constant, even if the account name is changed for security reasons.

### Q3: What account has the highest permission level possible on a Windows host

Even "Admins" are secondary to the **SYSTEM** account (NT AUTHORITY\SYSTEM), which has full access to the OS kernel and local resources.

### Q4: What user naming attribute is unique to the user and will remain so even if the account is deleted?

While SIDs are unique to a session, the **ObjectGUID** is the absolute, immutable identifier for an AD object. Even if a user is moved or their name changes, the GUID remains constant throughout the object's entire lifetime; however, once an account is deleted, that specific GUID is gone forever and never reused for new accounts.

## Active Directory Groups

### Q1: What group type is best utilized for assigning permissions and right to users?

When managing access to resources, administrators use **Security Groups**. Unlike distribution groups (used only for email), security groups are assigned SIDs, allowing them to be added to Access Control Lists (ACLs) to grant specific permissions.

### Q2:  True or False; A "Global Group" can only contain accounts from the domain where it was created.

**True**. Global groups have a strict membership scope, meaning they can only hold objects from their own domain. However, they are highly flexible in terms of visibility, as they can be granted permissions to resources located in any domain within the same forest.

### Q3: Can a Universal group be converted to a Domain Local group? (yes or no)

**Yes**. Active Directory allows for group scope conversion under specific conditions. A Universal group can be converted to a Domain Local group, provided it is not a member of another Universal group, allowing for more granular local resource management.

## Active Directory Rights and Privileges

### Q1: What built-in group will grant a user full and unrestricted access to a computer?

Membership in the **Administrators** group is the highest level of local access. Users in this group can bypass most security checks, install software, and modify system-level configurations that affect all other users on the machine.

### Q2: What user right grants a user the ability to make backups of a system?

The **SeBackupPrivilege** is a powerful right that allows a user to read any file on the system, bypassing disk quotas and standard NTFS permissions. From a security standpoint, this privilege is highly sensitive as it can be abused to extract the NTDS.dit file or other sensitive data.

### Q3: What Windows command can show us all user rights assigned to the current user?

To audit what specific "privileges" or "rights" your current session holds (like the ability to shut down the system or debug programs), you should use the **whoami /priv** command. It is a fundamental tool for initial reconnaissance during a penetration test.

# Digging in Deeper

## Security in Active Directory

### Q1: Confidentiality, <___>, and Availability are the pillars of the CIA Triad. What term is missing? (fill in the blank)

In the context of AD security, we must ensure **Integrity**, which means protecting data from unauthorized modification. Together with Confidentiality and Availability, it forms the foundation of a secure information system.

### Q2: What security policies can block certain users from running all executables?

To enforce strict "allow-only" environments and stop unauthorized programs, administrators use **Application control policies** (such as AppLocker). These policies provide a granular way to permit or block executables, scripts, and Windows Installer files based on unique file attributes or digital signatures.

## Examining Group Policy

### Q1: Computer settings for Group Policies are gathered and applied at a <___> minute interval? (answer is a number, fill in the blank )

To ensure changes propagate across the network without overwhelming the Domain Controller, Windows clients refresh their GPOs every **90** minutes. A random offset (staggering) is usually added to this timer to distribute the network load.

### Q2: True or False: A policy applied to a user at the domain level would be overwritten by a policy at the site level.

**False**. According to the LSDOU inheritance order (Local, Site, Domain, OU), policies applied at the Domain level take precedence over those at the Site level, and policies at the OU level override both.

### Q3: What Group Policy Object is created when the domain is created?

Every new AD domain automatically generates the **Default Domain Policy**. This critical GPO defines the baseline security posture for all users and computers, including password complexity, account lockout thresholds, and Kerberos settings.