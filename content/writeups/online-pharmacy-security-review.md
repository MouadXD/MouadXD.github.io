---
title: "Web Application & API Security Assessment: e-Pharmacy Platform"
date: 2026-11-12
draft: false
summary: "Black-box review of a React and Node.js pharmacy web app and API. I found an IDOR, a NoSQL injection, and other vulnerabilities, fixed and retested them, and added CI checks to catch regressions."
tags:
  - IDOR
  - NoSQL Injection
  - CI
  - Gitleaks
  - Semgrep
  - Trivy
categories:
  - Application Security
---

Hey. In this writeup, I’ll walk through a security assessment I did on an e-Pharmacy app I built.

This project started with a simple question: how secure is an application when you look at it from an attacker’s perspective?

I used an online pharmacy application I had built with React, Node.js, Express, and MongoDB as the target. It includes customer and admin functionality, JWT authentication, Google OAuth, and payment integrations.

I approached the assessment using a black-box methodology, testing the application through its interface and REST API before using source-code access to investigate the issues I discovered.

The assessment identified five vulnerabilities. In this article, I’ll focus on two of them (an IDOR in order retrieval and a NoSQL injection in coupon validation) and explain how I investigated, fixed, and retested them. I’ll also cover the security checks added to the project’s CI pipeline.

The source code is in the {{< extlink url="https://github.com/MouadXD/e-Pharmacy-Platform" text="GitHub repository" >}}, and the {{< extlink url="/reports/e-Pharmacy_Web-App_Assessment_Report.pdf" text="full assessment report" >}} is available as a PDF.

## 1. Reconnaissance & Application Mapping

I started by exploring the application as a regular user, going through its main features and understanding how the storefront and admin dashboard worked.

Using Burp Suite, I intercepted HTTP traffic exchanged between the frontend and REST API. I examined the requests, responses, parameters, and available endpoints to understand how the application handled different operations.

This initial exploration helped me identify interesting areas for further testing, particularly authentication, order management, coupon validation, and administrative functionality.

For the flow capture shown below, I ran mitmweb with a local listener and wrote the captured traffic to a file:

```bash
mitmweb \
  --listen-host 127.0.0.1 \
  --listen-port 8082 \
  --web-host 127.0.0.1 \
  --web-port 8083 \
  -w pentest/captures/initial-exploration.flow
```

I browsed the storefront through the proxy and reviewed the recorded requests in mitmweb. The flow list below shows the API calls captured during that pass.

![mitmproxy flow list showing intercepted API requests](/images/mitmproxy-intercepted-requests.webp)

After the capture, I converted the flow file into an OpenAPI document with mitmproxy2swagger:

```bash
mitmproxy2swagger \
  -i pentest/captures/initial-exploration.flow \
  -o pentest/documentation/medicare-api.yml \
  -p http://localhost:8000/api/v1 \
  -f flow
```

I imported the generated spec into Swagger Editor to review the exposed endpoints and remove the noise I did not need. That made the attack surface easier to map before I started testing individual operations.

![API endpoints mapped in Swagger Editor](/images/attack-surface-map.webp)

## 2. Finding One: IDOR in Order Retrieval

### What I discovered

While testing order retrieval, I investigated whether the application properly enforced ownership checks when accessing order resources.

I found that the endpoint relied on an order identifier supplied in the request without adequately verifying that the requested order belonged to the authenticated user.

This meant that an authenticated customer could manipulate the identifier and retrieve another customer’s order information.

The route followed the pattern `GET /api/v1/orders/:userId/user`, with the user ID taken directly from the path.

### Setting up test accounts

To verify the issue, I created two regular accounts, User A with `test_user_a@email.com` and User B with `test_user_b@email.com`, and captured a token for each one.

![Creating test user A](/images/create-test-user-a.webp)

![Creating test user B](/images/create-test-user-b.webp)

I then logged in as each account and saved the returned access token for the order requests. User A’s ID was `6af360dc46ca7a5a04dd0b4e`, and User B’s ID was `6af3610346ca7a5a04dd0b51`.

![Logging in as test user A and receiving an access token](/images/test-user-a-login-token.webp)

![Logging in as test user B and receiving an access token](/images/test-user-b-login-token.webp)

### Reproducing the issue

I first sent a normal order retrieval request using User A’s token and User A’s ID. The application returned User A’s orders as expected.

![User A retrieving their own orders](/images/test-user-a-own-orders.webp)

I then kept User A’s token but changed the user ID in the path to User B’s ID.

![User A’s token retrieving User B’s orders](/images/test-user-b-orders-with-user-a-token.webp)

The server returned the requested order instead of rejecting access, demonstrating an authorization weakness.

### Impact

An attacker with a valid account could potentially access other customers’ order information by manipulating order identifiers.

This represents a breach of data confidentiality and could expose information associated with customer purchases.

### Remediation

The application was updated to enforce resource ownership on the server side. Order retrieval must verify that the requested order belongs to the authenticated user, rather than relying on the supplied identifier alone.

The original handler trusted the `userId` from the route and queried orders with it directly:

![Vulnerable order handler trusting the userId from the request](/images/idor-vulnerable-order-handler.webp)

The fix added a check against the authenticated user before the query:

![Fixed order handler checking the authenticated user](/images/idor-fixed-order-handler.webp)

### Retesting

After implementing the fix, I repeated both requests.

The legitimate request for User A’s own orders still worked:

![User A still retrieving their own orders after the fix](/images/idor-retest-own-orders-allowed.webp)

The request that used User A’s token with User B’s ID was rejected with a `403 Forbidden` response:

![Blocked attempt to retrieve User B’s orders with User A’s token](/images/idor-retest-cross-user-blocked.webp)

The fix closed the authorization gap while keeping normal order retrieval working.

## 3. Finding Two: NoSQL Injection in Coupon Validation

### What I discovered

During testing of the coupon validation functionality, I examined how the API processed the `couponCode` parameter.

The endpoint accepted user-controlled JSON input without properly restricting its expected data type. By supplying a MongoDB query operator instead of a regular coupon string, I was able to manipulate the database lookup.

### Reproducing the issue

I started with a normal request containing an invalid coupon code, `TEST_COUPON`:

```json
{
  "couponCode": "TEST_COUPON"
}
```

The application returned a `404` response indicating that the coupon could not be found.

The screenshot below shows the baseline request in Burp Repeater and the resulting `404` response.

![Baseline coupon request returning 404](/images/coupon-baseline-404.webp)

I then changed the parameter to an object containing the `$regex` MongoDB operator:

```json
{
  "couponCode": {
    "$regex": ".*"
  }
}
```

Instead of rejecting the unexpected input, the application returned a successful response containing an active coupon.

The screenshot below shows the `$regex` payload in Burp Repeater; I also tested `$ne` and confirmed it was accepted the same way.

![NoSQL operator injection in the coupon request returning a valid coupon](/images/coupon-nosql-injection-200.webp)

This demonstrated that user-controlled input was being interpreted as part of a database query rather than being handled strictly as a coupon string.

### Impact

An attacker could manipulate coupon validation queries and retrieve coupon information without supplying a legitimate coupon code.

The issue also demonstrated insufficient input validation at the API boundary.

### Remediation

The input handling was corrected to enforce the expected data type and reject unexpected objects or operator-based input. Database queries should use validated values rather than accepting arbitrary user-controlled query structures.

The original handler passed the `couponCode` value straight into the coupon lookup:

![Vulnerable coupon lookup using the unvalidated couponCode value](/images/nosql-vulnerable-coupon-lookup.webp)

The fix started with a strict schema that only accepts a string for `couponCode`:

![Joi schema requiring couponCode to be a string](/images/nosql-coupon-validation-schema.webp)

I then applied that schema to the route:

![Coupon route using the validation schema](/images/nosql-coupon-route-validation.webp)

Because the schema only allows a string, an object containing `$ne` or `$regex` is rejected before the controller reaches the database.

### Retesting

I repeated both the original request and the injection attempt after applying the fix.

The application continued to handle valid coupon requests correctly, while the manipulated object input was rejected.

I also checked that the endpoint still required authentication and that normal invalid coupon requests behaved correctly.

Without an access token, the endpoint returned `401 Unauthorized`:

![Coupon check rejected without an access token](/images/nosql-retest-missing-token.webp)

With a valid token and a normal invalid coupon string, it returned `404 Not Found`:

![Authenticated coupon check returning 404 for an invalid coupon](/images/nosql-retest-invalid-coupon.webp)

I then repeated the injection with the `$ne` operator and a valid token. The validation layer rejected it with a `400 Bad Request` and a `ValidationError` stating that `couponCode` must be a string:

![Authenticated NoSQL injection attempt rejected by validation](/images/nosql-retest-injection-blocked.webp)

## 4. Additional Findings

Beyond the two vulnerabilities covered above, the assessment identified three additional security weaknesses.

These were also addressed and retested as part of the project:

- **Finding 3: Insecure HTTP Cookie:** At the time of testing, the OAuth flow stored an access token in a `user` cookie without `HttpOnly`, `Secure`, or `SameSite`. Any script running on the frontend origin could read the token, the cookie could be sent over unencrypted HTTP, and the browser did not apply a same-site restriction. Exploiting this required an additional exposure path, such as XSS or HTTP interception; the missing flags alone did not bypass authentication.
- **Finding 4: Token Management Weakness:** At the time of testing, access tokens remained valid after logout and password changes. This meant that previously issued tokens could continue to be used to access protected resources until they expired, even after the user had logged out or changed their password. As a result, a stolen access token could remain usable beyond the intended session.
- **Finding 5: Incorrectly Configured HTTP Security Headers:** At the time of testing, the frontend was missing standard defensive headers such as `Content-Security-Policy` and `X-Frame-Options`. Both the frontend and API also returned `Access-Control-Allow-Origin: *`. On the frontend this mainly affected public static assets, while on the API credentialed CORS was not enabled and protected routes still required a Bearer token, so the wildcard alone did not expose authenticated data. It should still be replaced with an explicit origin allowlist, especially for the API.

For the full technical descriptions, evidence, severity assessments, and remediation recommendations, refer to the complete security assessment report linked below.

## 5. Automated Security Checks (CI)

Identifying and fixing vulnerabilities is only one part of improving application security. To reduce the risk of introducing new vulnerabilities during future development, I integrated automated security checks into the project's development workflow.

I implemented a GitHub Actions CI pipeline that runs multiple security tools whenever changes are pushed to the repository or a pull request is submitted.

The pipeline includes:

- **Gitleaks:** Detects accidentally committed secrets, API keys, and credentials.
- **Semgrep:** Performs Static Application Security Testing (SAST) to identify potentially insecure coding patterns.
- **Dependency auditing:** Uses `npm audit` to identify known vulnerabilities in frontend and backend dependencies.
- **Trivy:** Performs filesystem security scanning to detect vulnerable dependencies, exposed secrets, and configuration-related security issues.

All security checks are integrated into the CI workflow, with blocking findings causing the pipeline to fail until they are addressed.

This approach introduces automated security validation into the development lifecycle, helping identify security regressions earlier and encouraging more secure development practices.

The complete workflow configuration is available on GitHub: [`ci.yml`](https://github.com/MouadXD/e-Pharmacy-Platform/blob/main/.github/workflows/ci.yml).

![Successful CI pipeline execution with all jobs passing](/images/ci-pipeline-passing.webp)

![Gitleaks security scan output with no leaks detected](/images/gitleaks-scan-output.webp)

## 6. Conclusion

This project gave me the opportunity to work through the complete security assessment process: exploring an application, identifying vulnerabilities, investigating their root causes, implementing fixes, and verifying the results.

It also highlighted the importance of integrating security checks into the development workflow rather than treating security as a one-time activity.

The application is still a personal project, but the assessment helped me approach its development from a security perspective and gave me practical experience with both offensive testing and security automation.

![SpongeBob wiping his hands after a job well done](https://media3.giphy.com/media/v1.Y2lkPTc5MGI3NjExZzRoenNxaGNwOTcyMmdoMWtzY3N3MmRoYnJkenU0djhjYnNvMXJmMiZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/26u4lOMA8JKSnL9Uk/giphy.gif)

## Project Resources

- **Full Security Assessment Report:** {{< extlink url="/reports/e-Pharmacy_Web-App_Assessment_Report.pdf" text="Download the full assessment report (PDF)" >}}
- **Source Code:** {{< extlink url="https://github.com/MouadXD/e-Pharmacy-Platform" text="MouadXD/e-Pharmacy-Platform" >}}
