function Send-MyAzEmail {
    param(
        [string]$Email,
        [string]$Password,
        [string]$From,
        [string]$To,
        [string]$Subject,
        [string]$Body,
    )
    $password = ConvertTo-SecureString $Password -AsPlainText -Force
    $creds = New-Object System.Management.Automation.PSCredential($Email, $password)

    if ($From -eq $null) {
        $From = $Email
    }

    $mailParams = @{
        SmtpServer                 = 'smtp.office365.com'
        Port                       = '587' 
        UseSSL                     = $true 
        Credential                 = $creds
        From                       = $From
        To                         = $To
        Subject                    = $Subject
        Body                       = $Body
        DeliveryNotificationOption = 'OnFailure', 'OnSuccess'
    }

    Send-MailMessage @mailParams -Verbose
}