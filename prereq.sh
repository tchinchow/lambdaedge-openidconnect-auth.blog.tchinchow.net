

export DEPLOY_BUCKET="$1" # this is the S3 Bucket where to which SAM deploys the Lambda@Edge code

export STATIC_WEBSITE_BUCKET="$2" # new S3 bucket for content that will serve as the origin for CloudFront

export YOUR_LOG_BUCKET_NAME="$3" # S3 bucket for your Logs

export YOUR_SECRETS_MANAGER_KEY_NAME="$4" # Secret managerKey containing OpenID Connect configuration

export CLIENT_ID_FROM_IDP="$5"

export IDP_DOMAIN_NAME="$6"

echo $YOUR_SECRETS_MANAGER_KEY_NAME > src/js/okta-key.txt

echo "SAM BUILD"
sam build -b ./build -s . -t template.yaml -u

echo "SAM PACKAGE"
sam package \
 --template-file build/template.yaml \
 --s3-bucket ${DEPLOY_BUCKET} \
 --output-template-file build/packaged.yaml
 
echo "SAM DEPLOY"
sam deploy \
 --template-file build/packaged.yaml \
 --stack-name oidc-auth \
 --capabilities CAPABILITY_NAMED_IAM \
 --parameter-overrides BucketName=${STATIC_WEBSITE_BUCKET}
   LogBucketName=${YOUR_LOG_BUCKET_NAME} SecretKeyName=${YOUR_SECRETS_MANAGER_KEY_NAME}

export CLOUDFRONT_DIST_URL=$(aws cloudformation  describe-stacks --stack-name oidc-auth --query "Stacks[0].Outputs[?OutputKey=='CloudFrontDomain'].OutputValue" --output text)

echo "{
 "AUTH_REQUEST": {
 "client_id": "${CLIENT_ID_FROM_IDP}",
 "response_type": "code",
 "scope": "openidemail",
 "redirect_uri": "https://${CLOUDFRONT_DIST_URL}/_callback"
 },
 "TOKEN_REQUEST": {
 "client_id": "${CLIENT_ID_FROM_IDP}",
 "redirect_uri": "https://${CLOUDFRONT_DIST_URL}/_callback",
 "grant_type": "authorization_code",
 "client_secret": "${CLIENT_SECRET_FROM_IDP}"
 },
 "DISTRIBUTION": "amazon-oai",
 "AUTHN": "COGNITO",
 "DISCOVERY_DOCUMENT": "https://${IDP_DOMAIN_NAME}/.well-known/openid-configuration",
 "SESSION_DURATION": 30,
 "BASE_URL": "https://${IDP_DOMAIN_NAME}/",
 "CALLBACK_PATH": "/_callback",
 "AUTHZ": "COGNITO"
 }" | base64 > encode.txt


 aws secretsmanager create-secret --name ${YOUR_SECRETS_MANAGER_KEY_NAME} --secret-string file://encode.txt

