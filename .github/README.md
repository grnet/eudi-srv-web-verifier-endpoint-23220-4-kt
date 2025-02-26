# To install

1. Switch to the `okeanos` branch.

```bash
git checkout okeanos-v2.0
```

2. The verifier backend is configured to use the `x509\_san\_dns` client id scheme, which requires a JAR signing certificate. To obtain one, you need to visit https://registry.serviceproviders.eudiw.dev using a mobile device or emulator that features the (Android) EUDI wallet app (or scan the QR code that is generated when one hits the link from another device's web browser). Use `snf-895798.vm.okeanos.grnet.gr` in the provided fields (e.g. CN and DNS) and a password (e.g. grnet) for the keystore. Once the certificate is obtained, execute the following command to insert the certificate in the verifier backend's default keystore.

```bash
cd okeanos
./cert_keystore.sh
```

3. Enter the `okeanos` directory and execute the installation script with sudo privileges.

```bash
cd okeanos
sudo ./install.sh
```

# To execute

From the root project directory execute the gradle wrapper in order to build and run the application as follows.
```java
./gradlew bootRun
```

# More

For more information regarding this repository check the full [README](https://github.com/grnet/eudi-srv-web-verifier-endpoint-23220-4-kt/blob/main/README.md).
