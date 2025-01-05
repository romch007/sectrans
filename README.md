# sectrans

Secure transfer

## Usage

Generate a certificate and a private key:
```
$ openssl req -x509 -nodes -days 1825 -newkey rsa:4096 -keyout server.key -out server.crt
```

Build the app:
```
$ cargo build --release
```

Start the server:
```
$ target/release/server --cert server.crt --private-key server.key --dir data
```

Use the client:
```
$ target/release/client -k list
$ target/release/client -k upload somefile.txt
$ target/release/client -k download otherfile.pdf
```
