from onelogin.saml2.settings import OneLogin_Saml2_Settings



def generate_saml_config(
    domain, 
    saml_idp_entity_id, 
    saml_idp_sso_url, 
    saml_idp_slo_url, 
    saml_idp_x509_cert,
    strict=True, 
    debug=False, 
    saml_name_id_format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
    saml_sp_x509_cert="", 
    saml_sp_private_key=""
):
    saml_auth = {
        "strict": strict,
        "debug": debug,
        "sp": {
            "entityId": f"{domain}/api/auth/metadata",
            "assertionConsumerService": {
                "url": f"{domain}/api/auth/acs",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            },
            "singleLogoutService": {
                "url": f"{domain}/api/auth/sls",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            },
            "NameIDFormat": saml_name_id_format,
            "x509cert": saml_sp_x509_cert,
            "privateKey": saml_sp_private_key
        },
        "idp": {
            "entityId": saml_idp_entity_id,
            "singleSignOnService": {
                "url": saml_idp_sso_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            },
            "singleLogoutService": {
                "url": saml_idp_slo_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            },
            "x509cert": saml_idp_x509_cert
        }
    }
    return saml_auth

def verify_metadata(saml_auth_config):
    saml_settings = OneLogin_Saml2_Settings(saml_auth_config)
    metadata = saml_settings.get_sp_metadata()
    errors = saml_settings.validate_metadata(metadata)
    return metadata, errors

def generate_metadata_file(output_file:str="instance/metadata.xml", config=None):

    if not config:
        raise Exception("No config passed to generate_metadata_file")

    metadata, errors = verify_metadata(generate_saml_config(
        domain=config.DOMAIN, 
        saml_idp_entity_id=config.SAML_IDP_ENTITY_ID, 
        saml_idp_sso_url=config.SAML_IDP_SSO_URL, 
        saml_idp_slo_url=config.SAML_IDP_SLO_URL, 
        saml_idp_x509_cert=config.SAML_IDP_X509_CERT,
        strict=config.SAML_STRICT, 
        debug=config.SAML_DEBUG, 
        saml_name_id_format=config.SAML_NAME_ID_FORMAT,
        saml_sp_x509_cert=config.SAML_SP_X509_CERT, 
        saml_sp_private_key=config.SAML_SP_PRIVATE_KEY,
    ))
    
    if len(errors) == 0:
        with open(output_file, "w") as f:
            f.write(metadata)
            print(f"\n\nMetadata successfully generated and saved to {output_file}\n\n")
    else:
        print("\n\nError(s) found in metadata:\n")
        for error in errors:
            print(f" - {error}\n")
