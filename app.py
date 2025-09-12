import boto3
import json
from defusedxml.ElementTree import parse, fromstring
from defusedxml.minidom import parseString
from defusedxml import defuse_stdlib
import logging
import uuid

# Enable defusedxml security features
defuse_stdlib()

# Configure logging with a detailed format
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Create logger
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

# Ensure boto3 and other libraries don't flood the logs
logging.getLogger('boto3').setLevel(logging.INFO)
logging.getLogger('botocore').setLevel(logging.INFO)
logging.getLogger('urllib3').setLevel(logging.INFO)

def escape_xml(text):
    """Safely escape XML special characters"""
    if not isinstance(text, str):
        text = str(text)
    return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&apos;')

def validate_xml_string(xml_string):
    """Validate XML string for potential security issues."""
    if any(entity in xml_string for entity in ['<!ENTITY', '<!DOCTYPE', 'SYSTEM']):
        raise ValueError("XML contains potentially dangerous elements")

def get_saml_certificates(cognito_client, user_pool_id, provider_name):
    try:
        logging.debug(f"Fetching certificates for provider {provider_name} in user pool {user_pool_id}")
        
        # Get signing certificate
        signing_cert_response = cognito_client.get_signing_certificate(
            UserPoolId=user_pool_id
        )
        signing_certificate = signing_cert_response.get('Certificate')
        
        # Get provider details for encryption certificate
        provider_response = cognito_client.describe_identity_provider(
            UserPoolId=user_pool_id,
            ProviderName=provider_name
        )
        provider_details = provider_response['IdentityProvider']['ProviderDetails']
        encryption_certificate = provider_details.get('ActiveEncryptionCertificate')
        signing_algorithm = provider_details.get('RequestSigningAlgorithm')

        certificates = {
            'signing_certificate': signing_certificate,
            'signing_algorithm': signing_algorithm,
            'encryption_certificate': encryption_certificate
        }
        
        logging.debug(f"Retrieved certificates: Signing cert present: {bool(certificates['signing_certificate'])}, "
                    f"Encryption cert present: {bool(certificates['encryption_certificate'])}")
        
        if not signing_certificate:
            logging.warning("Signing certificate not found")
        if not encryption_certificate:
            logging.warning("Encryption certificate not found")
            
        return certificates
    except Exception as e:
        logging.error(f"Error fetching certificates: {str(e)}", exc_info=True)
        return None

def create_metadata_xml(user_pool_id, domain_prefix, saml_config=None):
    try:
        # Determine if signing and encryption are enabled
        wants_signed_requests = False
        wants_encrypted_assertions = False
        if saml_config and 'ProviderDetails' in saml_config:
            details = saml_config['ProviderDetails']
            wants_signed_requests = details.get('RequestSigningAlgorithm') is not None
            wants_encrypted_assertions = details.get('EncryptedResponses') == 'true'

        # Create XML structure manually as a string
        xml_parts = []
        xml_parts.append('<?xml version="1.0" encoding="UTF-8"?>')
        
        # Create root EntityDescriptor
        xml_parts.append(
            f'<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" '
            f'xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" '
            f'xmlns:ds="http://www.w3.org/2000/09/xmldsig#" '
            f'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
            f'entityID="urn:amazon:cognito:sp:{escape_xml(user_pool_id)}">'
        )

        # Create SPSSODescriptor
        xml_parts.append(
            f'<SPSSODescriptor AuthnRequestsSigned="{str(wants_signed_requests).lower()}" '
            f'WantAssertionsSigned="{str(wants_encrypted_assertions).lower()}" '
            f'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
        )

        # Add KeyDescriptor for signing if enabled
        if wants_signed_requests and saml_config.get('signing_certificate'):
            xml_parts.extend([
                '<KeyDescriptor use="signing">',
                '<ds:KeyInfo>',
                '<ds:X509Data>',
                f'<ds:X509Certificate>{escape_xml(saml_config["signing_certificate"])}</ds:X509Certificate>',
                '</ds:X509Data>',
                '</ds:KeyInfo>',
                '</KeyDescriptor>'
            ])

        # Add KeyDescriptor for encryption if enabled
        if wants_encrypted_assertions and saml_config.get('encryption_certificate'):
            xml_parts.extend([
                '<KeyDescriptor use="encryption">',
                '<ds:KeyInfo>',
                '<ds:X509Data>',
                f'<ds:X509Certificate>{escape_xml(saml_config["encryption_certificate"])}</ds:X509Certificate>',
                '</ds:X509Data>',
                '</ds:KeyInfo>',
                '<EncryptionMethod Algorithm="https://auth0.com/docs/get-started/applications/signing-algorithms"/>',
                '</KeyDescriptor>'
            ])

        # Add SingleLogoutService
        xml_parts.append(
            f'<SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" '
            f'Location="{escape_xml(domain_prefix)}/saml2/logout"/>'
        )

        # Add NameIDFormat
        xml_parts.append(
            '<NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</NameIDFormat>'
        )

        # Add AssertionConsumerService
        xml_parts.append(
            f'<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
            f'Location="{escape_xml(domain_prefix)}/saml2/idpresponse" index="1"/>'
        )

        # Close tags
        xml_parts.append('</SPSSODescriptor>')
        xml_parts.append('</EntityDescriptor>')

        # Join all parts
        xml_str = '\n'.join(xml_parts)

        # Validate the generated XML
        validate_xml_string(xml_str)

        # Use defusedxml to parse and pretty print
        parsed_xml = parseString(xml_str)
        formatted_xml = parsed_xml.toprettyxml(indent="   ")

        return formatted_xml

    except Exception as e:
        logging.error(f"Error creating metadata XML: {str(e)}", exc_info=True)
        raise


def lambda_handler(event, context):
    # Configure CloudWatch logging level
    if logger.handlers:
        for handler in logger.handlers:
            if isinstance(handler, logging.StreamHandler):
                handler.setLevel(logging.DEBUG)
    
    # Add request ID to context
    request_id = str(uuid.uuid4())
    logging_context = {'request_id': request_id}

    try:
        logging.debug("Starting metadata generation process", extra=logging_context)
        logging.debug(f"Received event: {json.dumps(event)}", extra=logging_context)
        
        # Check if pathParameters exists
        if not event.get('pathParameters'):
            logging.error(f"Missing pathParameters in event: {json.dumps(event)}", extra=logging_context)
            return {
                'statusCode': 400,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps({'error': 'Missing path parameters'})
            }
        
        # Get user pool ID and provider name from path parameters
        user_pool_id = event['pathParameters'].get('userPoolId')
        provider_name = event['pathParameters'].get('providerName')  # Optional
        
        # Validate required parameters
        if not user_pool_id:
            logging.error(f"Missing required path parameter userPoolId: {user_pool_id}", extra=logging_context)
            return {
                'statusCode': 400,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps({'error': 'Missing required path parameter: userPoolId'})
            }
        
        # Initialize Cognito client
        cognito = boto3.client('cognito-idp')
        logging.debug(f"Initialized Cognito client", extra=logging_context)
        
        # Extract region from user pool ID
        try:
            region = user_pool_id.split('_')[0]
            logging.debug(f"Extracted region: {region}", extra=logging_context)
        except Exception as e:
            logging.error(f"Error extracting region from user pool ID: {str(e)}", extra=logging_context)
            return {
                'statusCode': 400,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps({'error': f'Invalid user pool ID format: {user_pool_id}'})
            }
        
        # Get user pool info
        try:
            logging.debug(f"Getting user pool info for: {user_pool_id}", extra=logging_context)
            user_pool = cognito.describe_user_pool(UserPoolId=user_pool_id)
            logging.debug(f"Successfully retrieved user pool info", extra=logging_context)
        except cognito.exceptions.ResourceNotFoundException as e:
            logging.error(f"User pool not found: {str(e)}", extra=logging_context)
            return {
                'statusCode': 404,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps({'error': 'User pool not found'})
            }
        except Exception as e:
            logging.error(f"Error getting user pool: {str(e)}", extra=logging_context, exc_info=True)
            return {
                'statusCode': 500,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps({'error': f'Error retrieving user pool: {str(e)}'})
            }
        
        # Get specific identity provider configuration if provider name is provided
        saml_config = None
        if provider_name:
            try:
                logging.debug(f"Getting identity provider details for: {provider_name}", extra=logging_context)
                provider_details = cognito.describe_identity_provider(
                    UserPoolId=user_pool_id,
                    ProviderName=provider_name
                )
                logging.debug(f"Successfully retrieved provider details", extra=logging_context)
                
                saml_config = provider_details['IdentityProvider']
                if saml_config['ProviderType'] != 'SAML':
                    logging.error(f"Provider {provider_name} is not a SAML provider", extra=logging_context)
                    return {
                        'statusCode': 400,
                        'headers': {
                            'Content-Type': 'application/json',
                            'Access-Control-Allow-Origin': '*'
                        },
                        'body': json.dumps({'error': 'Specified provider is not a SAML provider'})
                    }
                    
                # Get certificates for the specific SAML provider
                logging.debug(f"Getting certificates for provider: {provider_name}", extra=logging_context)
                certificates = get_saml_certificates(cognito, user_pool_id, provider_name)
                logging.debug(f"Retrieved certificates", extra=logging_context)
                if certificates:
                    saml_config.update(certificates)
                
            except cognito.exceptions.ResourceNotFoundException as e:
                logging.error(f"Identity provider not found: {str(e)}", extra=logging_context)
                return {
                    'statusCode': 404,
                    'headers': {
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*'
                    },
                    'body': json.dumps({'error': 'Identity provider not found'})
                }
            except Exception as e:
                logging.error(f"Error getting identity provider: {str(e)}", extra=logging_context, exc_info=True)
                return {
                    'statusCode': 500,
                    'headers': {
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*'
                    },
                    'body': json.dumps({'error': f'Error retrieving identity provider: {str(e)}'})
                }
        else:
            logging.debug(f"No provider name provided, generating generic SP metadata", extra=logging_context)
        
        # Get domain and construct domain prefix
        try:
            domain = user_pool['UserPool'].get('Domain')
            if not domain:
                logging.error(f"User pool does not have a domain configured", extra=logging_context)
                return {
                    'statusCode': 400,
                    'headers': {
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*'
                    },
                    'body': json.dumps({'error': 'User pool does not have a domain configured'})
                }
                
            domain_prefix = f'https://{domain}.auth.{region}.amazoncognito.com'
            logging.debug(f"Domain prefix: {domain_prefix}", extra=logging_context)
        except Exception as e:
            logging.error(f"Error constructing domain prefix: {str(e)}", extra=logging_context, exc_info=True)
            return {
                'statusCode': 500,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps({'error': f'Error constructing domain prefix: {str(e)}'})
            }
        
        # Generate metadata XML
        try:
            logging.debug(f"Generating metadata XML", extra=logging_context)
            metadata_xml = create_metadata_xml(user_pool_id, domain_prefix, saml_config)
            logging.debug(f"Successfully generated metadata XML", extra=logging_context)
        except Exception as e:
            logging.error(f"Error generating metadata XML: {str(e)}", extra=logging_context, exc_info=True)
            return {
                'statusCode': 500,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps({'error': f'Error generating metadata XML: {str(e)}'})
            }
        
        # Return successful response
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/xml',
                'Access-Control-Allow-Origin': '*',
                'Cache-Control': 'max-age=300'
            },
            'body': metadata_xml
        }
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}", exc_info=True, extra=logging_context)
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({'error': f'Internal server error: {str(e)}'})
        }
