# XSS
## Migitations
- Use output encoding
## Reflected XSS
1. user clicks malicious link (www.acme.com?message=`<script>evil()</script>`)
2. the web server by incorporate the value into the HTML document created for the user (Source code: `<h1>Hello {value of message}</h1>`)
3. the web server returns malicious document to the user (`<h1><script>evil()</script></h1>`)
4. user's browser executes the script `<script>evil()</script>`