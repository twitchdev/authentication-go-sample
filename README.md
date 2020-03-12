# Twitch Authentication Go Samples
Here you will find sample Go apps illustrating how to authenticate Twitch API calls using the OAuth2 and OIDC authorization code flows, as well as the OAuth2 client credentials flow.

## Installation
```sh
$ go get -u github.com/twitchdev/authentication-samples/go/...
```

## Usage
Before running each sample, you will need to set two configuration variables at the top of `main.go`:

1. `CLIENT_ID` - This is the Client ID of your registered application. You can register an application in your [dashboard](https://glass.twitch.tv/console/apps).
2. `CLIENT_SECRET` - This is the secret generated for you when you register your application; do not share this. In a production environment, it is STRONGLY recommended that you do not store application secrets in your source code.

Optionally, you may modify the requested scopes and/or claims. 

After setting these variables, you may run the server from within each directory:

```sh
$ go run main.go
```

The access token will be shown in the console.


## License

Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at

    http://aws.amazon.com/apache2.0/

or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.