# CESR decoder

Browser based [CESR decoder app](https://psteniusubi.github.io/cesr-decoder/) implemented in javascript. The purpose of this app is to visualize CESR streams and values. I have found this useful when learning how CESR works.

This implementation is based on following specifications 

* https://weboftrust.github.io/ietf-cesr/draft-ssmith-cesr.html
* https://weboftrust.github.io/ietf-cesr-proof/draft-pfeairheller-cesr-proof.html
* https://trustoverip.github.io/tswg-acdc-specification/draft-ssmith-acdc.html
* https://weboftrust.github.io/ietf-keri/draft-ssmith-keri.html

The CESR tables used by this app are automatically generated from [keripy](https://github.com/WebOfTrust/keripy). See also [cesr-schema](./cesr-schema).

## Usage

1. Navigate to https://psteniusubi.github.io/cesr-decoder/
2. Paste CESR text into textbox or click any of the CESR sample links
3. Check Interleaved if CESR text is stream content (stream has JSON and CESR interleaved)
4. Click Decode

## Development workflow - WebStorm/IntelliJ

1. Clone the repository
    ```shell
   git clone git@github.com:kentbull/cesr-decoder.git
   cd cesr-decoder
   ```
2. Install the `http-server` package globally
   ```shell
   npm install -g http-server
   ```
3. Start the `http-server` with the `./docs` directory as the content root. This should start an http server on `http://localhost:8080`.
   ```shell
   http-server ./docs
   ```
4. Create a JavaScript Debug configuration in WebStorm/IntelliJ
    1. Open the Run/Debug Configurations dialog
    2. Click the `+` button and select JavaScript Debug
    3. Name the configuration `Chrome index.html`
    4. Set the URL to `http://localhost:8080`
    5. Click OK
5. Set breakpoints as desired in the code in `./docs/assets/common/modules`.
6. Start the debug configuration. This should automatically open a Chrome browser window to `http://localhost:8080` with the debugger attached.
7. Debug as normal.


## Sample CESR content

Top of the page has a number of links to previously recorded CESR streams. Click on the links to see the CESR stream decoded.

### From GLEIF Root public sources

See https://github.com/GLEIF-IT/GLEIF-IT.github.io/tree/main/.well-known/keri/oobi

* [GLEIF Root-witness.cesr](./docs/samples/GLEIF%20Root-witness.cesr?raw=1)
    * `curl http://5.161.69.25:5623/oobi/EDP1vHcw_wc4M__Fj53-cJaBnZZASd-aMTaSyWEQ-PC2/witness`
* [GLEIF External-witness.cesr](./docs/samples/GLEIF%20External-witness.cesr?raw=1)
    * `http://65.21.253.212:5623/oobi/EINmHd5g7iV-UldkkkKyBIH052bIyxZNBn9pq-zNrYoS/witness`
* [GLEIF Internal-witness.cesr](./docs/samples/GLEIF%20Internal-witness.cesr?raw=1)
    * `curl http://13.244.119.106:5623/oobi/EFcrtYzHx11TElxDmEDx355zm7nJhbmdcIluw7UMbUIL/witness`

### From development environment

* [My Root GAR Group-witness.cesr](./docs/samples/My%20Root%20GAR%20Group-witness.cesr?raw=1)
    * Root AID 
    * `curl http://localhost:5642/oobi/EPgISkuC1ZS9kisgufpzQYvurZcuu2hpLRBT2ZJuOJ9z/witness/BIfjEfe_3R6Svl6M9qcek9XIK0E7_DAJXRnWF-_feU98`
* [qvi-vc.cesr](./docs/samples/qvi-vc.cesr?raw=1)
    * QVI credential issued by External Root to QVI
    * `kli vc export --said EOiLKDVNJj-2FCWypOKEwC_QcWmu5KIJ7Ux2qXVXSo3I --full`
* And many more...
