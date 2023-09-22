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
})
// using await
const message = await promise
console.log(`Message: ${message}`)
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


