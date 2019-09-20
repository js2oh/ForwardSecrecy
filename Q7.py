import nacl.public
import nacl.utils
import nacl.encoding
import nacl.hash
import nacl.secret
import nacl.pwhash
import nacl.signing
import requests
import json
import base64
import binascii

# Question 7: Forward Secrecy 
urlSetIdentityKey = "https://whoomp.cs.uwaterloo.ca/458a3/api/prekey/set-identity-key"
urlSetSignedPrekey = "https://whoomp.cs.uwaterloo.ca/458a3/api/prekey/set-signed-prekey"
urlGetIdKey = "https://whoomp.cs.uwaterloo.ca/458a3/api/prekey/get-identity-key"
urlGetSignedPrekey = "https://whoomp.cs.uwaterloo.ca/458a3/api/prekey/get-signed-prekey"
urlSend = "https://whoomp.cs.uwaterloo.ca/458a3/api/prekey/send"
urlReceive = "https://whoomp.cs.uwaterloo.ca/458a3/api/prekey/inbox"

apiToken = "3b09f0398adddf74e7eb3831b38e709f5078d964bf67608fe95923a1bed3a3fa"

headers = {
	"Accept": "application/json",
	"Content-Type": "application/json" 
}


# Part1
# Generate a new random signing key and upload an identity verification key
signingKey = nacl.signing.SigningKey.generate()
# Obtain the verify key for a given signing key
verifyKey = signingKey.verify_key
# Serialize the verify key to send it to a third party
verifyKeyB64 = verifyKey.encode(encoder=nacl.encoding.Base64Encoder)

bodySetIdentityKey = {
	"api_token": apiToken,
	"public_key": verifyKeyB64
}

r1 = requests.post(url=urlSetIdentityKey, data=json.dumps(bodySetIdentityKey), headers=headers)

if r1.status_code == 200:
	print('Uploaded public verification key')
else:
	print('Uploading failed')

# Generate a prekey
mySecretKey = nacl.public.PrivateKey.generate()
myPreKey = mySecretKey.public_key

# Sign a prekey with the signing key
signedPKB64 = signingKey.sign(myPreKey._public_key, encoder=nacl.encoding.Base64Encoder)

# Upload the signed prekey to the server
bodySetSignedPrekey = {
	"api_token": apiToken,
	"public_key": signedPKB64
}

r2 = requests.post(url=urlSetSignedPrekey, data=json.dumps(bodySetSignedPrekey), headers=headers)

if r2.status_code == 200:
	print('Uploaded signed prekey')
else:
	print('Uploading signed prekey failed')


# Part2
# Download Jessie's identity verification key
bodyGetIdKey = {
	"api_token": apiToken,
	"user": "jessie"
}

r3 = requests.post(url=urlGetIdKey, data=json.dumps(bodyGetIdKey), headers=headers)

if r3.status_code == 200:
	print('Id verification key received')

else:
	print('Id verification key not received')

ivKeyReceive = json.loads(r3.text)['public_key']
decodedIVKey = base64.b64decode(ivKeyReceive)

# Obtain Jessie's signed prekey
bodyGetSignedPrekey = {
	"api_token": apiToken,
	"user": "jessie"
}

r4 = requests.post(url=urlGetSignedPrekey, data=json.dumps(bodyGetSignedPrekey), headers=headers)

if r4.status_code == 200:
	print('Signed prekey received')

else:
	print('Signed prekey not received')

signedPrekeyReceive = json.loads(r4.text)['public_key']
decodedSPKey = base64.b64decode(signedPrekeyReceive)

# Verify the signature on this signed prekey and obtain the prekey
jessieIVKey = nacl.signing.VerifyKey(decodedIVKey)
unsignedPk = jessieIVKey.verify(decodedSPKey)

jessiePrekey = nacl.public.PublicKey(unsignedPk)

# Encrypt the plaintext using Jessie's prekey as the public key, and the secret key associated with your prekey
myBox = nacl.public.Box(mySecretKey, jessiePrekey)
messageSend = b"Polar bear is the love"
encryptedMessageSend = myBox.encrypt(messageSend)
encodedMessageSend = base64.b64encode(encryptedMessageSend)

# Send the nonce and the ciphertext to Jessie
bodySend = {
	"api_token": apiToken,
	"to": "jessie",
	"message": encodedMessageSend
}

r5 = requests.post(url=urlSend, data=json.dumps(bodySend), headers=headers)

if r5.status_code == 200:
	print('Message Sent')
else:
	print('Message sending failed')


# Part3
# receive a message
bodyReceive = {
	"api_token": apiToken,
}

r6 = requests.post(url=urlReceive, data=json.dumps(bodyReceive), headers=headers)

if r4.status_code == 200:
	print('Message Received!')
	messageReceive = json.loads(r6.text)[0]['message']
	decodedMessage = base64.b64decode(messageReceive)
	decryptedMessage = myBox.decrypt(decodedMessage)
	print(decryptedMessage)
else:
	print('Message Not Received!')