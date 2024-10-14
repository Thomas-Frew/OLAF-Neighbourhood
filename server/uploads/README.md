# OLAF-Neighbourhood
_Created by Jack Morton and Thomas Frew, of group 48._

The file upload endpoint for OLAF's Neighbourhood protocol.

## Debugging

To debug the file upload server, use the cURL commands:


### Upload
```
curl -X POST -k --tls-max 1.2 --ciphers 'HIGH:!SSLv2:!SSLv3:!TLSv1:!TLSv1.1' --data-binary "@local_filename" https://localhost:[port]/api/upload
```

### Download
```
curl -X GET -k --tls-max 1.2 --ciphers 'HIGH:!SSLv2:!SSLv3:!TLSv1:!TLSv1.1' "remote_filename"
```
