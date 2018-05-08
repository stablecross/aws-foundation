;;; Copyright (c) 2018 William R. Felts III, All Rights Reserved
;;;
;;; Redistribution and use in source and binary forms, with or without
;;; modification, are permitted provided that the following conditions
;;; are met:
;;;
;;;   * Redistributions of source code must retain the above copyright
;;;     notice, this list of conditions and the following disclaimer.
;;;
;;;   * Redistributions in binary form must reproduce the above
;;;     copyright notice, this list of conditions and the following
;;;     disclaimer in the documentation and/or other materials
;;;     provided with the distribution.
;;;
;;; THIS SOFTWARE IS PROVIDED BY THE AUTHOR 'AS IS' AND ANY EXPRESSED
;;; OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
;;; WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
;;; ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
;;; DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
;;; DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
;;; GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
;;; INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
;;; WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
;;; NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
;;; SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;;;

;;;; aws-foundation.lisp

(in-package #:aws-foundation)

(defparameter *nl* (format nil "~c" #\Newline))

;;;;
;;;; encryption support routines
;;;;


;;; ensure hs at least 64 characters with leading zero fill
;;;
(defun pad-hex-string (hs)
  (format nil "~64,1,0,'0@a" hs))

(defun sha256/ba (vector_ba)
  (ironclad:digest-sequence :sha256 vector_ba))

(defun ba/hs64 (vector_ba)
  (pad-hex-string (ironclad:byte-array-to-hex-string vector_ba)))

(defun sha256/hs64 (vector_ba)
  (ba/hs64 (sha256/ba vector_ba)))

;;;;
;;;; dexador interface
;;;;
(defparameter *dex-keep-alive* nil)
(defparameter *dex-verbose* nil)

;;;
;;; http support routines
;;;
(defun octets-to-string (octets)
  (babel:octets-to-string octets :encoding :utf-8))

(defun json-decode-octets/js (octets)
  (let ((string (octets-to-string octets)))
    (if (equalp string "")
	nil
	(json:decode-json-from-string string))))

(defun string-to-octets (string)
  (babel:string-to-octets string :encoding :utf-8))

;;;
;;; returns:
;;;  result code nil => in the success case
;;;  nil code response => in the error case
;;;
(defun aws-post (url_s headers content_s)
  (handler-case
      (multiple-value-bind (result code)
	  (dex:post url_s
		    :headers headers
		    :content content_s
		    :keep-alive *dex-keep-alive*
		    :verbose *dex-verbose*)
	(values (json-decode-octets/js result) code nil))
    (dex:http-request-failed (e)
      (values nil (dex:response-status e) (json-decode-octets/js (dex:response-body e))))))

(defun aws-get (url_s &key (headers nil))
  (handler-case
      (multiple-value-bind (result code)
	  (if headers
	      (dex:get url_s
		       :headers headers
		       :verbose *dex-verbose*)
	      (dex:get url_s
		       :verbose *dex-verbose*))
	(values (json-decode-octets/js result) code nil))
    (dex:http-request-failed (e)
      (values nil (dex:response-status e) (json-decode-octets/js (dex:response-body e))))))

;;;
;;; if pool-id is "us-east-1_pppp1111"
;;; then
;;;   region -> "us-east"
;;;   pool -> "pppp1111"
;;;
(defun region/s (pool-id_s)
  (let ((underscore (position #\_ pool-id_s)))
    (if underscore
	(subseq pool-id_s 0 underscore)
	pool-id_s)))

(defun pool/s (pool-id_s)
  (let ((underscore (position #\_ pool-id_s)))
    (if underscore
	(subseq pool-id_s (1+ underscore))
	pool-id_s)))

;;;
;;; so far, the URL to use for Cognito REST APIs is based on the region code.
;;; It may more complicated than the simple string concatentation method used
;;; here.  For example, I've seen (but not studied) code that special cases
;;; things in Canada.
;;;
(defun make-aws-host/s (service_s region_s)
  (concatenate 'string service_s "." region_s ".amazonaws.com"))

(defun make-aws-endpoint (host_s)
  (concatenate 'string "https://" host_s))

(defun make-aws-url/s (service_s region_s)
  (make-aws-endpoint (make-aws-host/s service_s region_s)))


;;;
;;; http://docs.aws.amazon.com/general/latest/gr/sigv4-date-handling.html
;;;
;;;  The time stamp must be in UTC and in the following ISO 8601 format: YYYYMMDD'T'HHMMSS'Z'.
;;;  For example, 20150830T123600Z is a valid time stamp.
;;;
(defun aws-timestamp (the-time)
    (local-time:format-timestring nil the-time
				:format '(:year (:month 2) (:day 2) "T" (:hour 2) (:min 2) (:sec 2) "Z")
				:timezone local-time:+utc-zone+))
;;;
;;; YYYYMMDD
;;;
(defun aws-datestamp (the-time)
    (local-time:format-timestring nil the-time
				:format '(:year (:month 2) (:day 2))
				:timezone local-time:+utc-zone+))
  

(defun aws4-credential-scope (the-time region service)
  (format nil "~a/~a/~a/aws4_request" (aws-datestamp the-time) region service))

(defun aws-sign (msg key)
  (let ((hmac (ironclad:make-hmac key :sha256)))
    (ironclad:update-hmac hmac (aws-foundation:string-to-octets msg))
    (ironclad:hmac-digest hmac)))

;;;
;;; http://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html
;;; 
(defun aws4-signing-key (secret-key the-time region service)
  (let ((key (string-to-octets (concatenate 'string "AWS4" secret-key)))
	(date (aws-datestamp the-time)))
    (aws-sign "aws4_request" (aws-sign service (aws-sign region (aws-sign date key))))))

(defun aws4-authorization-header (aws-host base-headers content_s the-time amz-time region_s service access-key secret-key)
  (let ((authorization-string (aws4-authorization-string aws-host base-headers content_s the-time amz-time region_s service access-key secret-key)))
    (when authorization-string
      (list (cons "Authorization" authorization-string)))))

;;;
;;; http://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html
;;;
(defun trim-white (s)
  (string-trim '(#\Space #\Tab) s))

(defun trim-downcase-header (header)
  (cons (string-downcase (trim-white (car header))) (cdr header)))

(defun format-canonical-header-string (canonical-headers &optional (result ""))
  (let ((header (first canonical-headers)))
    (if (null header)
	result
	(format-canonical-header-string (rest canonical-headers) (format nil "~a~a:~a~c" result (car header) (cdr header) #\Newline)))))

;;;
;;; '(("a" . 1) ("b" . 2) ("c" . 3)) -> "a;b;c"
;;;
(defun format-canonical-signed-headers-string (canonical-headers &optional (result "") (separator ""))
  (let ((header (first canonical-headers)))
    (if (null header)
	result
	(format-canonical-signed-headers-string (rest canonical-headers) (format nil "~a~a~a" result separator (car header)) ";"))))

;;;
;;; take a list of ("a" . b) pairs, trim and downcase the car ("a"),
;;; then sort
;;;
(defun canonical-headers (headers)
  (sort (mapcar #'trim-downcase-header headers) #'string< :key #'car))

(defun aws4-authorization-string (aws-host base-headers content_s the-time amz-time region_s service access-key secret-key)
  (when (and access-key secret-key)
    (let* ((canonical-headers (canonical-headers (cons (cons "host" aws-host) base-headers)))
	   (signed-headers-string (format-canonical-signed-headers-string canonical-headers))
	   (payload-hash (sha256/hs64 (string-to-octets content_s)))
	   (canonical-request (concatenate 'string "POST" *nl* "/" *nl* "" *nl* (format-canonical-header-string canonical-headers) *nl* signed-headers-string *nl* payload-hash))
	   (algorithm "AWS4-HMAC-SHA256")
	   (credential-scope (aws4-credential-scope the-time region_s service))
	   (string-to-sign (concatenate 'string algorithm  *nl* amz-time *nl* credential-scope *nl* (sha256/hs64 (string-to-octets canonical-request))))
	   (signature (ba/hs64 (aws-sign string-to-sign (aws4-signing-key secret-key the-time region_s service)))))
      (concatenate 'string  algorithm " " "Credential=" access-key "/" credential-scope ", SignedHeaders=" signed-headers-string ", Signature=" signature))))

;;;
;;; service = "cognito-idp"
;;; region = "us-east-1"
;;; target = "AWSCognitoIdentityProviderService.AdminGetUser"
;;;
;;; service = "transcribe"
;;; region = "us-east=11"
;;; target = 
;;;
;;; => result_js result-code response_js
;;;    if result-code is 200, result_js will be forced to t if it is nil,
;;;       otherwise result_js passed unchanged
;;;
(defun aws4-post (service region target content &key (access-key nil) (secret-key nil) (the-time (local-time:now)))
  (assert (equal (null access-key) (null secret-key)))
  (let* ((aws-host (make-aws-host/s service region))
	 (content_s (cl-json:encode-json-to-string (or content (xjson:json-empty))))
	 (amz-time (aws-timestamp the-time))
	 (base-headers `(("Content-type" . "application/x-amz-json-1.1")
			 ("X-Amz-Date" . ,amz-time)
			 ("X-Amz-Target" . ,target))))
    (multiple-value-bind (result_js result-code response_js)
	(aws-post (make-aws-endpoint aws-host)
		  (append base-headers (aws4-authorization-header aws-host base-headers content_s the-time amz-time region service access-key secret-key))
		  content_s)
      (if (equal result-code 200)
	  (if result_js
	      (values result_js result-code response_js)
	      (values t result-code response_js))
	  (values result_js result-code response_js)))))
