// Okta Event Hooks utility

////////////////////////////////////////////////////

require('dotenv').config()

const express = require('express')

const request = require('request')

///////////////////////////////////////////////////

const verification_header = "X-Okta-Verification-Challenge"

// SET UP WEB SERVER
const app = express()

var port = process.env.PORT

app.use(express.urlencoded({ extended: true }))

app.use(express.json())

app.listen(port, function () {
	console.log('App listening on port ' + port + '...');
})

//////////////////////////////////////////////////

// just display an "I'm awake" message on home page
app.get('/', function (req, res) {
	res.send("I'm awake and ready to receive web hooks in 2021!")
})

// Verify an event hook
app.get('/event_hooks', function (req, res) {
	console.log("received a verification request from okta")

	console.log("the header is: " + req.header(verification_header))

	var response_obj = {
		verification: req.header(verification_header)
	}

	// response_obj["verification"] = req.header(verification_header)

	res.json(response_obj)
})

app.post('/token_hook', function (req, res) {
	const hook_obj = req.body
	console.dir(JSON.stringify(hook_obj))

	client_id = hook_obj.data.context.protocol.request.client_id

	console.log("the client id is: " + client_id)

	if (client_id == "0oar121ah8mqWv9Re0h7") {
		response_obj = {
			"commands": [
				{
					"type": "com.okta.access.patch",
					"value": [
						{
							"op": "add",
							"path": "/claims/scp/-",
							"value": "test_scope"
						}
					]
				},
				{
					"type": "com.okta.identity.patch",
					"value": [
						{
							"op": "add",
							"path": "/claims/external_attribute",
							"value": "1234"
						}
					]
				},
				{
					"type": "com.okta.access.patch",
					"value": [
						{
							"op": "add",
							"path": "/claims/external_attribute",
							"value": "1234"
						}
					]
				}
			]
		}
	}
	else {
		response_obj = {
			"commands": [
				{
					"type": "com.okta.access.patch",
					"value": [
						{
							"op": "add",
							"path": "/claims/external_attribute",
							"value": "1234"
						}
					]
				},
				{
					"type": "com.okta.identity.patch",
					"value": [
						{
							"op": "add",
							"path": "/claims/external_attribute",
							"value": "1234"
						}
					]
				}
			]
		}
	}
	res.json(response_obj)
})

// Receive an event hook
app.post('/event_hooks', function (req, res) {

	const hook_obj = req.body

	console.dir(JSON.stringify(hook_obj))

	// sends a POST to HOOK_TEST_URI
	// test_request()

	// sends a POST to HOOK_TEST_URI with the hook payload
	// test_request_with_payload(hook_obj)

	// parses okta org and events arr from hook and passes them to 
	// the handle_request function

	if (hook_obj.eventType == "com.okta.oauth2.tokens.transform") {
		console.log("this is a token inline hook.")

		// response_obj = {
		// 	"commands": [
		// 		{
		// 			"type": "com.okta.identity.patch",
		// 			"value": [
		// 				{
		// 					"op": "add",
		// 					"path": "/claims/external_attribute",
		// 					"value": "1234"
		// 				}
		// 			]
		// 		}
		// 	]
		// }

		response_obj = {
			"commands": [
				{
					"type": "com.okta.access.patch",
					"value": [
						{
							"op": "add",
							"path": "/claims/external_attribute",
							"value": "1234"
						}
					]
				},
				{
					"type": "com.okta.identity.patch",
					"value": [
						{
							"op": "add",
							"path": "/claims/external_attribute",
							"value": "1234"
						}
					]
				}
			]
		}
		res.json(response_obj)
	}

	else {
		route_request(hook_obj)
		res.sendStatus(200)
	}
})

//////////////////////////////////////////////////

function get_okta_org(hook_obj, callback) {
	const source = hook_obj.source

	var arr = source.split(".com/")

	const okta_org = arr[0] + ".com"

	console.log("the okta org is: " + okta_org)

	return callback(null, okta_org)
}

function enrich_token(okta_org, hook_obj) {

	response_obj = {
		"commands": [
			{
				"type": "com.okta.identity.patch",
				"value": [
					{
						"op": "add",
						"path": "/claims/external_attribute",
						"value": "1234"
					}
				]
			}
		]
	}

	res.json(response_obj)
}

function handle_event(okta_org, event) {

	// OKTA_ORG_01 + OKTA_ORG_03
	if (okta_org === process.env.OKTA_ORG_01 || okta_org === process.env.OKTA_ORG_03) {
		if (event.eventType === "user.session.start") {
			console.log("the event type is: " + event.eventType)
			console.log("and the okta org is: " + okta_org)
		}
		else if (event.eventType === "user.lifecycle.create" || event.eventType === "user.lifecycle.activate") {

			var target = event.target[0]

			var user_id = target.id

			var email = target.alternateId

			var name = target.displayName

			let buff = new Buffer(process.env.SEGMENT_KEY + ':')

			let authz_string = buff.toString('base64')

			var options = {
				method: 'POST',
				url: process.env.SEGMENT_URI,
				headers: {
					'cache-control': 'no-cache',
					Connection: 'keep-alive',
					'Cache-Control': 'no-cache',
					Accept: '*/*',
					Authorization: 'Basic ' + authz_string,
					'Content-Type': 'application/json'
				},
				body: {
					userId: user_id,
					traits: {
						email: email,
						name: name
					},
					integrations: {
						'Salesforce': true
					}
				},
				json: true
			}

			console.log("sending this object to segment:")

			console.dir(options)

			request(options, function (error, response, body) {
				if (error) throw new Error(error);

				console.log(body);
			})
		}
	}
	else if (okta_org === process.env.OKTA_ORG_02) {
		if (event.eventType === "user.account.update_profile") {
		}
	}
	else if (okta_org === process.env.OKTA_ORG_04) {
		if (event.eventType === "user.account.update_profile" || 
			event.eventType === "user.lifecycle.create" ||
			event.eventType === "user.lifecycle.activate") {

			console.log("the event is: ")
			console.dir(event)

			console.log(JSON.stringify(event))

			var options = {
				method: 'POST',
				url: process.env.ONETRUST_URI,
				headers: {
					'cache-control': 'no-cache',
					Connection: 'keep-alive',
					'Cache-Control': 'no-cache',
					Accept: '*/*',
					'Content-Type': 'application/json',
					'apiKey': process.env.ONETRUST_API_KEY
				},
				body: event,
				json: true
			}

			console.log("sending this object to onetrust:")

			console.dir(options)

			request(options, function (error, response, body) {
				if (error) throw new Error(error);

				console.log(body);
			})
		}
	}
	else if (okta_org === process.env.OKTA_ORG_05) {
		console.log(process.env.OKTA_ORG_05 + " is sending a message.")
	}
	else if (okta_org === process.env.OKTA_ORG_06) {
		console.log(process.env.OKTA_ORG_06 + " is sending a message.")
	}
	else if (okta_org === process.env.OKTA_ORG_07) {
		console.log(process.env.OKTA_ORG_07 + " is sending a message.")

		var url = 'https://okta-solar-system.herokuapp.com/risk_score'

		request(url, function (error, response, body) {
			console.error('error:', error) // Print the error if one occurred
			console.log('statusCode:', response && response.statusCode)
			console.log('body:', body) // Print the HTML for the Google homepage.

			var obj = JSON.parse(body)

			var risk_score = obj.risk_score

			console.log('the risk score is: ' + risk_score)

			console.log('the type of event is: ' + typeof(event))

			var user_id = event.target[0].id

			console.log('the user id is: ' + user_id)

			var options = {
				method: 'POST',
				url: okta_org + '/api/v1/users/' + user_id,
				headers: {
					'cache-control': 'no-cache',
					Connection: 'keep-alive',
					Host: 'okta-gs.oktapreview.com',
					Authorization: 'SSWS ' + process.env.OKTA_ORG_07_API_KEY,
					'Content-Type': 'application/json',
					Accept: 'application/json'
				},
				body: { profile: { external_risk_score: risk_score } },
				json: true
			}

			request(options, function (error, response, body) {
				if (error) throw new Error(error);

				console.log(body);
			})
		})
	}
}

function route_request(hook_obj) {

	get_okta_org(hook_obj, function(err, okta_org) {

		if (hook_obj.eventType == "com.okta.event_hook") {
			console.log("this is an event hook.")

			for (var i = 0; i < hook_obj.data.events.length; i++) {
				handle_event(okta_org, hook_obj.data.events[i])
			}
		}
		else if (hook_obj.eventType == "com.okta.oauth2.tokens.transform") {
			console.log("this is a token inline hook.")

			enrich_token(okta_org, hook_obj)
		}


	})
}

function test_request() {
	request.post(process.env.HOOK_TEST_URI, {form:{msg:'got an event hook from Okta!'}})
}

function test_request_with_payload(hook_obj) {
	request.post(process.env.HOOK_TEST_URI, {form: hook_obj})
}
