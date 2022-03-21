# Automate Deployment of Lambda Function

## Purpose

Automate the deployment of CloudFront and Lambda@edge Function

## Dependencies

- AWS SAM CLI
- AWS Credentials in Environment

### TL;DR

#### This will create the following AWS infrastructure

- S3 Bucket
- CloudFront Distribution
- Lambda@Edge Function
- Attaching Lambda@Edge Function to CloudFront for OpenID Connect Flow to Okta.


#### 1. Prerequisites/Assumptions

  Assumption : Secret Manager has the base64 encoded Okta configuration file (sample of the original configuration file is shown below with the dummy values, please replace the dummy values after setting up the values in Okta)

  1. git clone https://github.com/aws-samples/lambdaedge-openidconnect-samples
  2. cd lambdaedge-openidconnect-samples
  3. Pass the below values in prereq.sh script
  	- DEPLOY_BUCKET (this is the S3 Bucket where to which SAM deploys the Lambda@Edge code),
	- STATIC_WEBSITE_BUCKET (new S3 bucket for content that will serve as the origin for CloudFront)- YOUR_LOG_BUCKET_NAME (S3 bucket for your Logs)
	- YOUR_SECRETS_MANAGER_KEY_NAME (Secret managerKey name containing OpenID Connect configuration)
	- CLIENT_ID_FROM_IDP (IDP Provider Client ID for e.g. okta)
	- IDP_DOMAIN_NAME (HostName for the Website)
  ```
  ./prereq.sh DEPLOY_BUCKET STATIC_WEBSITE_BUCKET YOUR_LOG_BUCKET_NAME YOUR_SECRETS_MANAGER_KEY_NAME CLIENT_ID_FROM_IDP IDP_DOMAIN_NAME

  ```

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

## Contributors

- Matt Noyce
- Viyoma Sachdeva

