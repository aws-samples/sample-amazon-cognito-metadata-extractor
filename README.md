# Amazon Cognito Metadata Extractor

This solution facilitates integration between Amazon Cognito User Pools(SP) and external Identity Providers(IdP). The deployed API enables extraction of general SP metadata, including entityID, AssertionConsumerService, SingleLogoutService, and NameIDFormat from a specified User Pool. Additionally, it can retrieve SAML signing and encryption certificate details from the designated User Pool and provider. 

## Pre-requisites
- AWS account and permissions to create CloudFormation stacks, Cognito resources and lambda functions
- Amazon Cognito User Pool and/or SAML provider
- Python, PIP, AWS CLI, and SAM installed

###### Note: Please verify Python version compatibility for lxml and defusedxml libraries. Update the requirements.txt file accordingly to ensure proper dependency management.

## Deployment steps
###### Clone the project
```sh
git clone https://github.com/aws-samples/sample-amazon-cognito-metadata-extractor.git && cd sample-amazon-cognito-metadata-extractor
```
# 1. Create a new virtual environment (recommended):

## Create virtual environment
```sh
python3 -m venv venv
```

## Activate virtual environment
### For Windows:
```sh
venv\Scripts\activate
```
### For Unix/MacOS:
```sh
source venv/bin/activate
```

# 2.Update/Install the dependencies(if not already existing):
```sh
pip install -r requirements.txt
```
# 3.Verify Installation: ensure you have the following prerequisites installed:
## AWS CLI
```sh
aws --version
```
## SAM CLI
```sh
sam --version
```
# 4.Deployment folder structure should look as follows:

```
cognito-metadata-extractor/
│   .gitignore
│   app.py
│   authorizer.py
│   README.md
│   requirements.txt
│   serve_test_page.py       
│   template.yml
│   view_metadata.html
```

# 5.Build the SAM application:
```sh
sam build
```


# 6.Deploy the application:
## For first-time deployment, use guided mode:
```sh
sam deploy --guided
```

During the guided deployment, you'll need to:

- Enter a stack name (e.g., "cognito-metadata-service")

- Choose your AWS Region

- Confirm IAM role creation

- Allow SAM CLI to create named roles

- Choose deployment options for changes/rollbacks

For subsequent deployments, you can simply use:
```sh
sam deploy
```
6.	After deployment, SAM will output:
    - The API Gateway endpoint URLs for generic SP metadata and specific SAML provider metadata


# To consume the deployed API:

There are several ways to test the API after deployment:

**Note:** Replace the example values with your actual API endpoint, User Pool ID, and/or Provider Name. You can find your User Pool ID in the Overview section of your user pool and the Provider Name in the SAML "identity provider" section under your User Pool's _Social and external providers_ settings.

## Option 1: Using browser
Open your browser and navigate to:
```
https://myapi.execute-api.us-east-1.amazonaws.com/prod/metadata/myuserpoolid
```
Or with SAML provider:
```
https://myapi.execute-api.us-east-1.amazonaws.com/prod/metadata/myuserpoolid/mysamlprovidername
```

## Option 2: Using curl
```sh
# Set your values
myapi="your-api-id"
region="us-east-1"
myuserpoolid="us-east-1_example"
mysamlprovidername="Azure-EntraID"

# User pool metadata only
curl https://${myapi}.execute-api.${region}.amazonaws.com/prod/metadata/${myuserpoolid}/
```

OR

```sh
# With SAML provider
curl https://${myapi}.execute-api.${region}.amazonaws.com/prod/metadata/${myuserpoolid}/${mysamlprovidername}
```
## Option 3: Using the HTML test pages
Open the `view_metadata.html` in your browser. 

If you encounter CORS issues with the HTML page, you can use the serve_test_page.py script to serve the page locally:
```sh
python3 serve_test_page.py
```
This automaticlaly launches http://localhost:8000/view_metadata.html in your web browser. Populate the form fields and click 'Fetch Metadata' to view the SAML provider details.

## Option 4: Using Postman or another API testing tool
1. Create a new GET request
2. Enter your API URL Ex: https://myapi.execute-api.us-east-1.amazonaws.com/prod/metadata/myuserpoolid/mysamlprovidername
3. Click Send

To update the function code:
1.	Modify the app.py file
2.	Rebuild and redeploy:
```sh
sam build
sam deploy
```

To delete the stack when needed:
```sh
sam delete
```
Remember:
- Ensure you have appropriate AWS credentials configured in your execution environment(CLI/Terminal)
- The AWS region should match where your Cognito User Pool exists
- The IAM role needs permissions to access Cognito services
- Keep track of the API endpoint URL provided in the deployment outputs
- The deployment will create:
    - Lambda functions 
    - API Gateway
    - IAM roles and policies
    - CloudWatch Log groups


## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

