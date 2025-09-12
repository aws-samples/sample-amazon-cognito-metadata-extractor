import json
import logging

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """
    Simple Lambda authorizer that allows all requests
    For production, implement proper authorization logic
    """
    try:
        logger.info("Authorizer function invoked")
        
        # Log the event in a safe way
        try:
            logger.info(f"Event: {json.dumps(event)}")
        except:
            logger.info("Could not log event as JSON")
        
        # Extract method ARN - this is required for the policy
        method_arn = event.get('methodArn')
        
        # If methodArn is missing, use a wildcard resource
        if not method_arn:
            logger.warning("methodArn not found in event, using wildcard")
            # Use a wildcard ARN as fallback
            account_id = context.invoked_function_arn.split(':')[4]
            region = context.invoked_function_arn.split(':')[3]
            api_id = event.get('requestContext', {}).get('apiId', '*')
            stage = event.get('requestContext', {}).get('stage', '*')
            method_arn = f"arn:aws:execute-api:{region}:{account_id}:{api_id}/{stage}/*/*"
        
        # Always allow access for this demo
        effect = 'Allow'
        
        # Create policy document
        policy_document = {
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Action': 'execute-api:Invoke',
                    'Effect': effect,
                    'Resource': method_arn
                }
            ]
        }
        
        # Create response with policy document and principal ID
        auth_response = {
            'principalId': 'user',
            'policyDocument': policy_document,
            'context': {
                'stringKey': 'value',
                'numberKey': 123,
                'booleanKey': True
            }
        }
        
        logger.info(f"Authorizer response: {json.dumps(auth_response)}")
        return auth_response
        
    except Exception as e:
        logger.error(f"Error in authorizer: {str(e)}")
        # Even on error, return an Allow policy to prevent API failures
        # In production, you might want to deny access on errors
        return {
            'principalId': 'user',
            'policyDocument': {
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Action': 'execute-api:Invoke',
                        'Effect': 'Allow',
                        'Resource': '*'
                    }
                ]
            }
        }