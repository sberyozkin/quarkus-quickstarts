1. Start application, go to https://localhost:8443/hello, confirm in the browser that the certificate is not the one issued by lets encrypt

2. mvn quarkus:dev -Dquarkus.http.port=8082 -Demail=email -Ddomain=domain -Dpem-folder-path=application-pem-folder -Dmanagement-url=https://localhost:9000/q/lets-encrypt

3. ngrok http --domain your-ngrok-domain 8080 --scheme http

4. http://localhost:8082/acme/first-certificate

5. go to https://localhost:8443/hello, confirm it is a new certificate now


