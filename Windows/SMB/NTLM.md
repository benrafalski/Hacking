# NTLM

- NT Lan Manager
- Only lets designated users access network resources
- collection of Microsoft authentication protocols
- mutual authentication: both sides need to verify each other's identity
- uses a **challenge response protocol**

## NTLM Protocol

1. client sends their username to the host
2. host responds with a nonce (random number, i.e. the challenge)
3. user generates a hash with the concatenation of their password and nonce and sends to the host
4. since the host already knows the user's password, they can compare to the client's response

## Extract NTLM hash from Wireshark

### use filter "ntlmssp"

1. NTLMSSP_NETGOTIATE: Client will send request to authenticate
2. NTLMSSP_CHALLENGE: Host will send the challenge to the client
3. NTLMSSP_AUTH: client will send username and challenge response

![alt text](../Images/ntlm1.png "Title")

### Where to find NTLM info in SMB2 packets

1. SMB2
2. SMB2 Header
3. Session Setup Response (0x01)
4. Security Blob
5. GSS-API
6. Simple Protected Negotiation
7. negTokenTarg
8. NTLM Secure Service Provider
9. NTLM Server Challenge (for NTLMSSP_CHALLENGE) / NTLM Response (for NTLMSSP_AUTH)

### Information needed for hash cracking

1. User: In NTLMSSP_AUTH
2. Domain: In NTLMSSP_AUTH
3. Challenge: In NTLMSSP_CHALLENGE
4. HMAC-MD5: "NTProofStr" in the NTLMv2 Response in NTLMSSP_AUTH
5. NTLMv2Response: In NTLMSSP_AUTH

## Cracking NTLM hash with hashcat

### Hash file format
```bash
cat hashes.txt
```

```output
user::domain:challenge:HMAC-MD5:NTLMv2Response(with HMAC-MD5 removed from first 32 chars)
```
### hashcat command
```bash
# 1000 NTLM
# 5600 NTLMv2
hashcat -a 0 -m 5600 hashes.txt /usr/share/wordlists/kali-wordlists/rockyou.txt 
```
