#SYSCOIN COMMANDS

Syscoin commands can be called just like any other standard commands like gettransaction - you may call them either on the command-line using the daemon (as shown in the examples underneath) or you may call them from the QT client console window, in which case omit the 'syscoind' portion of the commands as shown in the examples underneath.

All commands use a 'register-activate' pattern, whereby an object is first laid claim to using a 'new' command, and then permanently registered using an 'activate' command, called at least one block after the according 'new' transaction has been recorded on the blockchain. In the case of aliases, a minimum period of 120 blocks must be added to the blockchain before an activate command can be called. This is to minimize alias squatting and frivolous registrations. For testing purposes however, this period has been set to 3 blocks. However, the activate command in all cases may be called immediately after the new command; the transactions will simply pend in the memory queue until the target block height has been reached.

## Alias commands - these commands deal with standard aliases.

###aliasnew *Create a new alias*
####**aliasnew** < aliasName >
- **parameters:**
  - < aliasName > alias name, 255 chars max.
- **returns:**
  - txid
  - guid
- **example:** 
  - *$ syscoind aliasnew /d/microsoft.bit* 
  - *[ "577b0f85da4744cbbe7ce763fe58bd4e3fc9817271fbc3785c6178217246ba94", "1150cd188f74c8df00" ]*

###aliasactivate *Activate the alias*

####**aliasactivate** < aliasName > < guid > [ < txid > ] < value >
- **parameters:**
  - < aliasName > alias name.
  - < guid > alias guid .
  - < txid > txid of aliasnew for this alias, required if daemon restarted.
  - < value > alias value, 1023 chars max.
  - May be called directly after aliasnew; however, the transaction isn’t actually posted to the network until 120 blocks after the aliasnew. 
  - If the client is restarted before aliasactivate is called, then alias txid parameter is required.
- **returns:**
  - txid
- **example:** 
  - *$ syscoind aliasactivate /d/microsoft.bit 1150cd188f74c8df00 RESERVED*
  - *8aba3631593aeb622d07900bad4c30d91d79377a2dd8cd3e5db6e972cca54282*

###aliasupdate *Update(or transfer) alias with new data(also resets expiration height)*

####**aliasupdate** < aliasName > < value > [ < toaddress > ] 
- **parameters:**
  - < aliasName > alias name.
  - < value > alias value, 1023 chars max.
  - < toaddress > receiver syscoin address, if transferring alias.
- **returns:**
  - txid
- **example:**
  - *$ syscoind aliasupdate /d/microsoft.bit "{ns:['17.17.17.17','12.12.12.12']}"*
  - *0da9761fccd19a881ceb06a90a61386fa2104a726eba631eea0ef2084a281c00*

###aliasinfo *Show the values of an alias*

####**aliasinfo** < aliasName >
- **parameters:**
  -< aliasName > alias name.
- **returns:**
  - aliasName
  - value
  - txid
  - address
  - expires_in
- **example:**
  - *$ syscoind aliasinfo “microsoft”*

###aliashistory *List all stored values of an alias*

####**aliashistory** < aliasName >
- **parameters:**
  - < aliasName > alias name.
- **returns:**
  - aliasName
  - value
  - txid
  - address
  - expires_in
- **example:**
  - *$ syscoind aliashistory “microsoft”*

###aliasfilter *Scan and filter aliases*

####**aliasfilter** < regexp >
- **parameters:**
  - < keyword > keyword used to filter results(can be left blank to show all)
- **returns:**
  - aliasName
  - value
  - txid
  - address
  - expires_in
- **example:** 
  - *$ syscoind aliasfilter “micro”*

## Data alias commands

###datanew *Create a new data alias*

####**datanew** < dataName >
- **parameters:**
  - < dataName > data name , 255 chars max. 
- **returns:**
  - txid
  - guid
- **example:** 
  - *$ syscoind datanew /dat/mycompany/readme*
  - *[ "a42f21f1502fa6078b62cc6500f31815bbc97fb4f12a91e95e5f242d9d467728", "40738ea3fbd88d5c" ]*

###dataactivate *Activate an data alias*

####**dataactivate** < dataName  > < guid > [ < txid > ] < filename > < data >
- **parameters:**
  - < dataName  > data name.
  - < guid > alias guid.
  - < txid > txid of datanew for this data alias, required if daemon restarted.
  - < filename > filename, 1023 chars max.
  - < data >  data base64-encoded. Max 256kB.
  - May be called directly after datanew; however, the transaction isn’t actually posted to the network until 120 blocks after the datanew.
  - If the client is restarted before dataactivate is called, then dataalias txid parameter is required.
- **returns:**
  - txid
- **example:**
  - *$ syscoind dataactivate /dat/mycompany/readme 40738ea3fbd88d5c readme.txt VGhpcyBpcyBteSBjb21wYW55Cg==*
  - *ae07eedeb53b6103d8fa6e689b1466e4c2853f27f5cc389bef910c59eb041dc81*

###dataupdate *Update data alias with new data(also resets expiration height)*

####**dataupdate** < dataName > < filename > < data > [ < toaddress > ]
- **parameters:**
  - < dataName > data name.
  - < filename > name for file, 1023 chars max.
  - < data > new data to update
  - < toaddress > 
- **returns:**
  - txid
- **example:**
  - *$ syscoind dataupdate /dat/mycompany/readme readme.txt V2VsY29tZSB0byBteSBjb21wYW55Cg==*
  - *82fa2fbbf640fd7ad002552399b1094d50861f7a9c5d5402fbe0ad4d14d3e907* 

###datainfo *Show the values of an data alias*

####datainfo < dataName >

- **parameters:**
  - < dataName > data name.
- **returns:**
  - dataName
  - filename
  - txid
  - address
  - expires_in
  - data
- **example:** 
  - *$ syscoind datainfo /dat/mycompany/readme* 
  - *{ "name" : "/dat/mycompany/readme", "filename" : "readme.txt", "txid" "ae07eedeb53b6103d8fa6e689b1466e4c2853f27f5cc389bef910c59eb041dc1", "address" : "3K6fZck7ksF6jXZcsfHE2LWbrjX4Knunpn", "expires_in" : 157872, "data" : "VGhpcyBpcyBteSBjb21wYW55Cg==" }*

###datahistory
Same functionality as aliashistory

###datafilter
Same functionality as aliasfilter (Use aliasfilter for now)

###datascan
Same functionality as aliasscan (Use aliasscan for now)

##Marketplace Offer commands - these commands deal with creating or purchasing offers.

###offernew *Create a new offer*

####**offernew** < category > < offertitle > < quantity > < price > < offerdescription >
- **parameters:**
  - < category > category of offer, 255 chars max.
  - < offertitle > title of offer 255 chars max.
  - < quantity > Quantity available.
  - < price > Price per item/unit.
  - < offerdescription > description of offer, 16000 chars max.
- **returns:**
  - txtid
  - guid
- **example:**
  - *$ syscoind offernew "General/Widgets" "Model T Widget Manifolds" 25 249 "One brand new model T widget manifold, still in original packaging."* 
  - *[ "7c6f5d153f2b8f7b1e38772c45370ab647335eea30ece99740ebeb3e43c18652", "8d0dabf5e7f2a4a300" ]*

###offeractivate *Activate the offer*

####**offeractivate** < guid > [ < txid > ]
- **parameters:**
  - < guid > guid provided at offernew.
  - < txid > txid provided at offernew, required if daemon restarted.
  - May be called directly after offernew; 
  - If the client is restarted before offeractivate is called, then offer txid parameter is required.
- **returns:**
  - txid
- **example:** 
  - *$ syscoind offeractivate 8d0dabf5e7f2a4a300 913c83bb63998421f9425c21e2b15bf09a96ea8dcbc03722efc3d2f6ffb0e867*

###offerupdate *Update an offer(also resets expiration height)*

####**offerupdate** < guid > < category > < title > < quantity > < price > [ < description > ]
- **parameters:**
  - < guid > offerkey
  - < category > category of offer, 255 chars max.
  - < offertitle > title of offer 255 chars max.
  - < quantity > Quantity available. NOTE : this is a summed value for offerupdate. 5 will add 5 more to the current value. -1 will subtract one. Use 0 to not change.
  - < price > Price per item/unit.
- **returns:**
  - txid
- **example:** 
  - *$ syscoind offerupdate 8d0dabf5e7f2a4a300 "General/Widgets" "Model T Widget Manifolds" 10 249 "One brand new model T widget manifold, still in original packaging."*
  - *95d6385779e43a705c27cfc1347fa70e3583b06e357836cdf36059e7594da946*

###offeraccept  *Accept an offer*

####**offeraccept** < guid > < quantity >
- **parameters:**
  - < guid > guid provided at offernew.
  - < quantity > quantity to accept (optional, default set to 1)
- **returns:**
  - txid
  - guid
- **example:**
  - $ syscoind offeraccept 8d0dabf5e7f2a4a300 5 
  - [ "e229b2ef75807a4d5ceaa46b92677647de6363e45a5374670e500522bf1f2e71", "24579dbfc4b4c3eb00" ]

###offerpay  *Sends seller payment in Syscoin, and also pays all syscoin service fees and marks the offer as ‘paid’*

####**offerpay** < guid > [ < accept txid > ]  < message >
- **parameters:**
  - < guid > guid provided at offeraccept.
  - < txid > accept txid provided at offeraccept (only required if client is restarted)
  - < message > message to seller, accept-specific. ie: buyer’s shipping address. 
- **returns:**
  - pay txid
  - offeraccept txid
- **example:**
  - *$ syscoind offerpay 24579dbfc4b4c3eb00 "Please ship to: John Smith, 123 Main Street, Anytown CA 91111"*
  - *[ "387f8e5ea2d21a4c6b679cf33d6dfd2366b0f43222811b21cc1441ed9e680ff7", "3d99e7650dfb60b377717ac4328f13bda92610a8e7076d3e065e231281f13d76" ]*

###offerinfo *Show the values of an offer*

####**offerinfo** < guid >
- **parameters:**
  - < guid > offer guid provided at offernew.
- **returns:**
  - guid
  - txid
  - address
  - expires_in
  - payment_address
  - category
  - title
  - quantity
  - price
  - fee
  - description
  - accepts
- **example:**
  - *$ syscoind offerinfo 8d0dabf5e7f2a4a300*
  - *{ "id" : "8d0dabf5e7f2a4a300" , "txid" : "3d99e7650dfb60b377717ac4328f13bda92610a8e7076d3e065e231281f13d76" , "address" : "3F1282vJVPhVz5dxDJ5r3SPNy61kWDy7SF" , "expires_in" : 111947 , "payment_address" : "SbxUr7CVa4UYfxn1pkT1SNqQEAM3bzrYvX" , "category" : "General/Widgets" , "title" : "Model T Widget Manifolds" , "quantity" : 30 , "price" : 249.00000000 , "fee" : 24.45000000, "description" : "One brand new model T widget manifold, still in original packaging.", "accepts" : [ { "id" : "24579dbfc4b4c3eb00", "txid" : "3d99e7650dfb60b377717ac4328f13bda92610a8e7076d3e065e231281f13d76" , "height" : "444", "time" : "1396853158", "quantity" : 5, "price" : 249.00000000, "paid" : "true", "fee" : 10.22500000, "paytxid" : "31215b19260474d41c0627778e2ccf5a3974551ca396e2a9bb9dea5209251061", "message" : "Please ship to: John Smith, 123 Main Street, Anytown CA 91111" } ] } *


###offerhistory
Same functionality as aliashistory

###offerfilter
Same functionality as aliasfilter

###offerscan
Same functionality as aliasscan

##Certificate commands - these commands deal with issuing and transferring certificates.

###Certissuernew *Create certificate title*

####**certissuernew** < certificatetitle > < certificatedata > < quantity > < price > < offerdescription >
- **parameters:**
  - < certificatetitle > Title of certificate, 255 chars max.
  - < certificatedata > Data contained in certificate 64 KB max
- **returns:**
  - certissuertxid
  - certissuerkey

- **example:** 
  - *$ syscoind certissuernew "Nerd Academy - We Teach you the Art of Nerd" "This certificate issuer is used to generate certificate of accreditations for our students. These are lifetime certificate and not honored if transferred or stolen."*
  - *[ "76ac8fc00b06c722918e6702837077bb27cf56a384f12935f5b3d40c7b3efc62", "d9d333abf5d9714f" ]*

###certissueractivate *Activate the certificate issuance*

####**certissueractivate**  < guid > [ < txid > ]
- **parameters:**
  - < guid > guid provided at certissuernew.
  - < txid > certissuer txid provided at certissuernew.
- **returns:**
  - txid 
- **example:**
  - *$ syscoind certissueractivate d9d333abf5d9714f 2088c50c7de00c30ed6e6ffa0661b18ad148cf8b8dcc5927ae844e58e2b78678*

###certissuerupdate *Update a certificate issuer that you control(also resets expiration height)*

####**certissuerupdate** < guid > < title > < data >
- **parameters:**
  - < guid > guid from certissuernew 
  - < title > Title of certificate, 255 chars max.
  - < data > Data contained in certificate 64 KB
- **returns:**
  - txid
  - guid
- **example:**
  - *$ syscoind certissuerupdate d9d333abf5d9714f "Nerd Academy - We Teach you the Art of Nerd" "This certificate issuer is used to generate certificate of accreditations for our students. These are lifetime certificate and not honored if transferred or stolen."*
  - *[ "76ac8fc00b06c722918e6702837077bb27cf56a384f12935f5b3d40c7b3efc62", "d9d333abf5d9714f" ]*

###certnew *Issue a new cert*

####**certnew** < guid > < destaddress > < title > < data >
- **parameters:**
	- <guid> guid from certissuernew 
	- <destaddress> destination Syscoin address
	- <title>: certificate title. max 255 chars.
	- <data>: certificate data, max 64 kB
- **returns**
  - txid,
  - guid
- **example:**
  - *$ syscoind certnew d9d333abf5d9714f Scq4eMRi8aRZxJXWas5MW8uxYCtZZgkcT1 "Certificate of Nerd Master" "Owner has achieved Nerd Mastery."
  - *[ "6b79eaf9c171fb92a5873f86e0b1069dbd79359b0f0cce14c201fc8fd2863587", "d532408da773032a" ]*

###certnew *Transfer a cert to another Syscoin address*

####**certtransfer** < cert guid > < destaddress >
- **parameters:**
	- <guid> guid of certificate
	- <destaddress> destination Syscoin address
- **returns:**
  - txid 

###certissuerinfo *List all details about a specific certissuer*

####**certissuerinfo** < guid >
- **parameters:**
	- <guid> certissuer guid
- **returns:**
  - guid
  - txid
  - address
  - expires_in
  - title
  - data
  - certificates

- **example:**
  - *$ syscoind certissuerinfo d9d333abf5d9714f
{
    "id" : "d9d333abf5d9714f",
    "txid" : "6b79eaf9c171fb92a5873f86e0b1069dbd79359b0f0cce14c201fc8fd2863587",
    "address" : "33h59NnTq48hgrFUXYBrpL6pGhgmE8Fdjk",
    "expires_in" : 123029,
    "title" : "Nerd Academy - We Teach you the Art of Nerd",
    "data" : "This certificate issuer is used to generate certificate of accreditations for our students. These are lifetime certificate and not honored if transferred or stolen.",
    "certificates" : [
        {
            "id" : "d532408da773032a",
            "txid" : "6b79eaf9c171fb92a5873f86e0b1069dbd79359b0f0cce14c201fc8fd2863587",
            "height" : "483",
            "time" : "1396857128",
            "fee" : 0.00000000,
            "title" : "Certificate of Nerd Master",
            "data" : "Owner has achieved Nerd Mastery."
        }
    ]
}

###certinfo *List all details about a specific cert*

####**certinfo** < guid >
- **parameters:**
	- <guid> cert guid
- **returns:**
  - id
  - txid
  - height
  - time
  - fee
  - title
  - data
  - issuer

- **example:**
  - *$ syscoind certinfo d532408da773032a
{
    "id" : "d532408da773032a",
    "txid" : "6b79eaf9c171fb92a5873f86e0b1069dbd79359b0f0cce14c201fc8fd2863587",
    "height" : "483",
    "time" : "1396857128",
    "fee" : 0.00000000,
    "title" : "Certificate of Nerd Master",
    "data" : "Owner has achieved Nerd Mastery.",
    "issuer" : {
        "id" : "d9d333abf5d9714f",
        "txid" : "6b79eaf9c171fb92a5873f86e0b1069dbd79359b0f0cce14c201fc8fd2863587",
        "address" : "33h59NnTq48hgrFUXYBrpL6pGhgmE8Fdjk",
        "expires_in" : 123029,
        "title" : "Nerd Academy - We Teach you the Art of Nerd",
        "data" : "This certificate issuer is used to generate certificate of accreditations for our students. These are lifetime certificate and not honored if transferred or stolen."
    }
}

###certissuerhistory
Same functionality as aliashistory

###certissuerfilter
Same functionality as aliasfilter

###certissuerscan
Same functionality as aliasscan
