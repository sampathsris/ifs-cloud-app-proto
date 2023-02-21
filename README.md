# ifs-cloud-app-proto

An [Express.js](https://expressjs.com/) app that authenticates with an [IFS Cloud](https://www.ifs.com/ifs-cloud/ifs-cloud-overview) instance using [Passport.js](https://www.passportjs.org/) and [openid-client](https://github.com/panva/node-openid-client).

## Disclaimer

This implementation is only meant for educational purposes. It is not an official impelemntation. The implementation details of the underlying system may change without notice.

## How to Use

1. Create an IAM Client:
	- Provide a Client ID (Copy this for later use).
	- Enabled: Yes.
	- Service Account: Yes.
	- Redirect URIs: `[ '<your_app_root_url>', '<your_app_root_url>/login/callback' ]`.
	- Service User: Create one, or use an existing user.
	- Save.
	- Copy the generated Client Secret (You may need to regenerate the client secret).
2. Clone this repository and download dependencies:
	```shell
	git clone https://github.com/sampathsris/ifs-cloud-app-proto.git
	cd ifs-cloud-app-proto
	pnpm install
	# or
	npm install
	# or
	yarn
	```
3. Create a `.env` file in the root of the repository:
	```shell
	IFS_SYSTEM_URL=#System URL of the IFS Cloud Instance
	IFS_NAMESPACE=#Name of the IFS Customer Namespace
	CLIENT_ID=#Previously copied Client ID
	CLIENT_SECRET=#Previously copied Cliet Secret
	
	# Use this only if there is a self-signed certificate in the chain
	# Warning: Using this in production systems will probably create a
	# security issue enabling MITM attacks.
	NODE_TLS_REJECT_UNAUTHORIZED=0
	```
4. Run the app:
	```shell
	pnpm start
	# or
	npm start
	# or
	yarn start
	```

## License

MIT

