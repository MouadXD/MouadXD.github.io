
---
title: "Demo Lab: Finding SQL Injection in a Login Form"
date: 2026-10-14
draft: false
description: "A simulated web security lab demonstrating SQL injection, root cause analysis, and secure remediation."
tags:
  - Web Security
  - SQL Injection
  - Authentication
categories:
  - Demo Labs
---

> **DEMO LAB — SIMULATED RESULTS**
>
> Acme Shop is a fictional training application created for this
> demonstration. The requests, database behavior, and results below
> illustrate a hypothetical vulnerable implementation. This is not
> a report of a completed HTB, TryHackMe, or real-world engagement.

## Overview

**Target:** Acme Shop — fictional local training application  
**Area:** Web application security  
**Vulnerability:** SQL injection  
**Objective:** Understand how unsafe SQL query construction can compromise an authentication flow.

SQL injection occurs when an application combines untrusted input with a SQL query in a way that allows the input to change the query's intended structure.

The objective of this exercise is to understand the vulnerability, demonstrate its potential impact in a controlled example, and identify the appropriate fix.

## 01 — Understanding the login flow

Imagine the application provides a login form that accepts a username and password.

A vulnerable backend might construct its database query like this:

```python
query = (
    "SELECT id, username FROM users "
    f"WHERE username = '{username}' "
    f"AND password = '{password}'"
)
```

The problem is not the login form itself. The problem is that user-controlled values are inserted directly into the SQL statement.

The application treats input as part of the query's syntax instead of keeping data separate from instructions.

## 02 — Identifying the weakness

During an authorized test, the first step would be to understand the normal response to valid and invalid login attempts.

Next, the tester would investigate whether specially crafted input changes the application's behavior in a way consistent with SQL injection.

For this fictional example, assume testing confirms that the backend interprets injected SQL syntax rather than treating the submitted value as ordinary text.

**Illustrative finding:** the login query is vulnerable because untrusted input can alter its logical conditions.

No actual server response or live test evidence is claimed here.

## 03 — Why the vulnerability matters

If an attacker can influence the query's logic, the consequences may include:

- Authentication bypass, depending on the query and application logic.
- Unauthorized access to records available to the database account.
- Exposure or modification of data if the database permissions allow it.
- Further compromise if the application has excessive database privileges.

The actual impact depends on the database engine, query structure, account permissions, and other security controls. SQL injection does not automatically mean every one of these outcomes is possible.

## 04 — Root cause

The underlying problem is unsafe query construction.

Consider this safer implementation using parameterized SQL:

```python
query = """
    SELECT id, username
    FROM users
    WHERE username = ?
      AND password_hash = ?
"""

cursor.execute(query, (username, password_hash))
```

The placeholder syntax shown here is used by some database drivers; the exact placeholder format depends on the driver.

With parameterized queries, the SQL statement is defined separately from its values. Input is handled as data rather than being concatenated into executable SQL syntax.

**Important:** real applications should also store password hashes using an appropriate password-hashing algorithm and verify passwords through the application's authentication logic. They should not store plaintext passwords.

## 05 — Remediation

Recommended corrective actions:

1. **Use parameterized queries.** Avoid building SQL statements through string concatenation.
2. **Hash passwords properly.** Use a dedicated password-hashing algorithm such as Argon2id, bcrypt, or scrypt.
3. **Apply least privilege.** Give the application's database account only the permissions it needs.
4. **Handle errors safely.** Do not expose SQL statements, database credentials, or detailed internal errors to users.
5. **Add regression tests.** Verify that unusual input is treated as data and cannot change query logic.

Input validation can provide additional protection, but it is not a substitute for parameterized queries.

## 06 — Key takeaways

- A seemingly ordinary login form can expose a serious database vulnerability.
- The key question is whether untrusted input can change the structure of a SQL query.
- Exploitability and impact must be demonstrated rather than assumed.
- Parameterized queries address the central cause of this class of vulnerability.
- A useful security report explains the root cause and gives developers a practical fix.

---

*This article is an illustrative portfolio demo, not evidence of a real assessment. All security testing should be performed only on systems you own or are explicitly authorized to assess.*
