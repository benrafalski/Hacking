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
- We use DNS to resolve human readable domain names to IP addresses

![image](../Images/http2.png)

## Port Number
- For client queries: UDP/53
- For zone transfers: TCP/53

## How DNS works
1. user types domain name into browser
2. if browser does not have the domain name in it's cache, it sends a request to a *DNS resolver* server
3. if the resolver does not have the domain name saved, it sends a query to the *root server*. 
    - The root server is the top of the DNS heirarchy.
    - There are 13 DNS root servers localed around the world. 
4. The root server will then tell the resolver where to get the IP address for their domain name by sending them the correct *TLD server*
5. the resolver will then send a query to the TLD server
    - TLD servers store address info for top level domains such as .com, .net, .org, etc. 
6. The TLD server will then tell the resolver where to get the IP address for their domain name by sending them to the correct *Authoritative Name server*
7. The resolver will then send a domain name query to the authoritative name server.
8. The authoritative name server will then respond with the IP address for the requested domain name. 
9. Then the resolver responds to the user's browser with the correct IP address for the requested domain name.
10. The resolver will store the IP address for the requested domain name in their cache so they can more easily respond to future requests.  

![image](../Images/http3.png)



# URIs and URLs
- URI: Uniform Resource Identifier
- URL: subset within URIs

![image](../Images/http4.png)

## URL Parts

- protocol/domain is required
- username/password/query/hash are optional
- default port for protocol is used if not provided (e.g. HTTP=80, HTTPS=443)

### Query Parameter
- appears after the *?* in the URL
- set of key value pairs in the form *key=value*
- multiple queries are split using the *&*
- Example: https://www.google.com/search?q=hello?a=world

### Example

```javascript
const url = new URL('http://testuser:testpass@testdomain.com:8080/testpath?testsearch=testvalue#testhash')
console.log(`protocol: ${url.protocol}`)
console.log(`username: ${url.username}`)
console.log(`password: ${url.password}`)
console.log(`hostname: ${url.hostname}`)
console.log(`port: ${url.port}`)
console.log(`pathname: ${url.pathname}`)
console.log(`search: ${url.search}`)
console.log(`hash: ${url.hash}`)
```

```output
protocol: http:
username: testuser
password: testpass
hostname: testdomain.com
port: 8080
pathname: /testpath
search: ?testsearch=testvalue
hash: #testhash
```


# Synchronous vs Asynchronous
- Synchronous: each line of code is executed in the order it appears
- Asynchronous: code executes in unpredictable order, allows for two lines of code to execute at the same time

![image](../Images/http5.png)

## I/O Timing
- RAM: ns -> sync
- Disk 1ms -> async/sync
- Network 100ms-2000ms -> async

## Promises in JavaScript
- Promise can either be pending, fulfilled, or rejected


```javascript
// declare a new Promise
const promise = new Promise((resolve, reject) => {
    setTimeout(() => {
        if(Math.random() > 5){
            resolve("resolved") // runs if Promise is fulfilled
        }else{
            reject("rejected") // runs if Promise is rejected
        }
    }, 1000)
})

// .then executes if Promise is fulfilled
// .catch executes if Promise is rejected
promise.then((message) => {
    console.log(`Message: ${message}`)
}).catch((message) => {
    console.log(`Message: ${message}`)
})
```

### .then vs await
both do the same thing, just different syntax
```javascript
// using .then
promise.then((message) => {
    console.log(`Message: ${message}`)
}).catch((message) => {
    console.log(`Message: ${message}`)
})
// using await
try{
    const message = await promise
    console.log(`Message: ${message}`)
} catch (err){
    console.log(err)
}

```

### new Promise vs async
both are ways of creating a Promise
- async just auto creates a new Promise object
```javascript
// using new Promise
function getPromiseForUserData() {
    return new Promise((resolve) => {
        fetchDataFromServer().then(function(user){
            resolve(user)
        })
    })
}
const promise = getPromiseForUserData()

// using async
async function getPromiseForUserData() {
    const user = await fetchDataFromServer()
    return user
}
const promise = getPromiseForUserData()
```

# HTTP Headers
- Allows additional content to be passed with each request/response. 
- Headers are often used for authentication in HTTP.

## headers.get()
Use this to get header value from request/response
```javascript
const response = await fetchResponse()
const headers = response.headers.get('content-type')
console.log(headers)
```
```output
application/json
```

## View in browser
1. Right-click -> Inspect 
2. Go to the Network tab
3. Reload the page and click on a request to view the headers for the request


# JSON
- JavaScript object notation
- structred way of sending information over HTTP

## Syntax
- always an object at the highest level
- objects are key: value pairs, where the key is always a string
- values can have string, int, float, bool, list, or object
```output
{
    "string": "value",
    "integer" : 2,
    "float": 1.92,
    "boolean": true,
    "list": [
        "1": 1,
        "2": 2
    ],
    "object": {
        "field1": "value",
        "field2": "value"
    }
}
```

## .json() and JSON.parse()
- need to use when recieving JSON objects
- .json() is asynchronous
- .parse() is synchronous
```javascript
const resp = await fetchRespons()

// .json()
const json = await resp.json()
console.log(json)

// .parse()
const parse = JSON.parse(resp)
console.log(parse)
```
```output
{"name":"John", "age":30, "car":null}
{"name":"John", "age":30, "car":null}
```

## JSON.stringfy()
- need to use when sending JSON objects
```javascript
const response = await fetch(path, {
    method: "PUT",
    mode: "cors",
    headers: getHeaders(),
    body: JSON.stringify(myBody)
})
```

## XML
- alternative to JSON
### JSON vs XML
```json
// JSON
{
    "id":"1",
    "genre":"Action",
    "title":"Iron Man",
    "director":"Jon Favreau",
}
```
```xml
<!-- XML -->
<root>
    <id>1</id>
    <genre>Action</genre>
    <title>Iron Man</title>
    <director>Jon Favreau</director>
</root>
```


# HTTP Methods

## CRUD
- create, read, update, delete
- create: POST
- read: GET
- update: PUT/PATCH
- delete: DELETE

## GET
- read information from an HTTP server

```javascript
const getReq = await fetch(url, {
    method: 'GET',
    mode: 'cors',
    headers: {
        'API-Key': '_idmykeyforgetrequest'
    }
})
```

## POST
- sends information to an HTTP server to create new information
```javascript
const postReq = await fetch(url, {
    method: 'POST',
    mode: 'cors',
    headers: {
        'Content-Type': 'application/json'
    }
    body: JSON.stringify(data)
})
```


## PUT
- used for updating a resource or creating a resource
- if you send a new resource it will create it
- if you send the same resource again it will update it
- PUT is intended to modify an entire resource
- PATCH is intended to partially modify a resource
- most people just use PUT for both use cases
```javascript
const putReq = await fetch(url, {
    method: 'PUT',
    mode: 'cors',
    headers: {
        'Content-Type': 'application/json'
    }
    body: JSON.stringify(data)
})
```

## DELETE
- deletes a resource
```javascript
const putReq = await fetch(url, {
    method: 'DELETE',
    mode: 'cors'
})
```

## Status Codes
- *100-199*: informational responses, very rare
- *200-299*: successful responses
- *300-399*: redirection responses
- *400-499*: client error responses
- *500-599*: server error responses

### Common Codes
- *200*: OK
- *201*: Created successfully (response to POST)
- *301*: Moved permanently
- *400*: Bad Request
- *403*: Unauthorized
- *404*: Not found
- *500*: Internal server error

### .status
```javascript
const response = await fetchResponse(url, apiKey)
console.log(response.status)
```
```output
404
```
