# Request and Response Model
- Clients make Requests
- Server sends back a Response to the client

![image](../Images/http1.png)

# Making HTTP Requests
```javascript
const url = 'http://www.site.com'
const settings = {
    method: 'GET',
    mode: 'cors',
    headers: {
        'X-API-Key': apiKey,
        'Content-Type': 'application/json'
    }    
}
const response = await fetch(url, settings)
const responseData = await response.json()
```

# DNS
- every computer has a unique IP address such as 10.18.72.187
- servers are computers, to request information from a server you need to know its IP address
- to map human readable domain names to IP addresses we use DNS

![image](../Images/http2.png)

## Port Number
- For client queries: UDP/53
- For zone transfers: TCP/53

## How DNS works