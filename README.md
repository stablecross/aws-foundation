###aws-foundation:  A Common Lisp Interface to Amazon AWS Services.

The primary purpose of this libary is provide support for access to Amazon services, such as Cognito or Transcribe.


[Function]<br>
**aws4-post** (service region target content &key (access-key nil) (secret-key nil) (the-time (local-time:now)))

		=> result, code, response
		
		aws4-post signs and sends a request to Amazon.
		
		On error, **result** is nil.
		
		**code** is the HTTP response code.
		
		On success, **response** is nil.  On error, **response** is the decoded JSON response provided by Amazon.
		
		Example:
		
			(aws-foundation:aws4-post "cognito-idp" "us-east-1"
			                          "AWSCognitoIdentityProviderService.ListUsers"
			                          `(("UserPoolId" . ,pool-id)
			                          ,@(if pagination-token `(("PaginationToken" . ,pagination-token))))
			                          :access-key access-key
			                          :secret-key secret-key))
			                          
  			(aws-foundation:aws4-post "transcribe" "us-east-1"
			                          "Transcribe.StartTranscriptionJob"
			                          `(("LanguageCode" . ,language-code)
			                            ("Media" . (("MediaFileUri" . ,url)))
			                            ("MediaFormat" . ,media)
			                            ("MediaSampleRateHertz" . ,sample-rate)
			                            ("TranscriptionJobName" . , job-name))
			                           :access-key access-key
			                           :secret-key secret-key))
			                          

[Function]<br>
**aws-get** (url_s &key (headers nil))

		=> result, code, response

		Constructs and makes an http GET request and decodes the result using Amazon conventions (JSON error
		responses, for example).
		  
		
[Function]<br>
**region/s** (pool-id)

		Returns the region portion of a pool id.
		
		(region/s "us-east-1_abcdefghi") -> "us-east-1"

[Function]<br>
**pool/s** (pool-id)

		Returns the pool portion of a pool id.
		
		(region/s "us-east-1_abcdefghi") -> "abcdefghi"

[Function]<br>
**string-to-octets** (string)

		Converts string to a vector of octets using utf-8 encoding.
		
[Function]<br>
**sha256/ba** (vector)

		Create a sha256 digest of the vector of octets

[Function]<br>
**sha256/hs64** (vector)

		Create a 64 character string, padded with '0' on the left, of the sha256 digest of the vector of octets

		
#### HTTP engine
[Dexador](http://quickdocs.org/dexador/) is used to process HTTPS requests.  The code encapsulates this in two functions, aws-post and aws-get, so it would be easyto use [Drakma](http://www.weitz.de/drakma/), instead.

#### Repository
[https://github.com/stablecross/aws-foundation](https://github.com/stablecross/aws-foundation)

####License
aws-foundation is available under a BSD-like license.  See the file LICENSE for details.

#### Contact
For any questions or comments, please feel free to email me, Bob Felts
<wrf3@stablecross.com>
