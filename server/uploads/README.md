# OLAF-Neighbourhood
The file upload endpoint for OLAF's Neighbourhood protocol.

## Debugging

To debug the file upload server, use the cURL commands:


### Upload
```
curl -X POST -k --tls-max 1.2 --ciphers 'HIGH:!SSLv2:!SSLv3:!TLSv1:!TLSv1.1' --key server.key --cert server.cert --data-binary "@local_filename" https://localhost:[port]/api/upload
```

### Download
```
curl -X GET -k --tls-max 1.2 --ciphers 'HIGH:!SSLv2:!SSLv3:!TLSv1:!TLSv1.1' --key server.key "remote_filename"
```