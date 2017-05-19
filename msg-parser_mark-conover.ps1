# This script was taken from the following url and modified:
# https://chris.dziemborowicz.com/blog/2013/05/18/how-to-batch-extract-attachments-from-msg-files-using-powershell/

function Expand-MsgAttachment
{
    [CmdletBinding()]

    Param
    (
        [Parameter(ParameterSetName="Path", Position=0, Mandatory=$True)]
        [String]$Path,

        [Parameter(ParameterSetName="LiteralPath", Mandatory=$True)]
        [String]$LiteralPath,

        [Parameter(ParameterSetName="FileInfo", Mandatory=$True, ValueFromPipeline=$True)]
        [System.IO.FileInfo]$Item
    )

    Begin
    {
        # Load application
        Write-Verbose "Loading Microsoft Outlook..."
        $outlook = New-Object -ComObject Outlook.Application
    }

    Process
    {
        switch ($PSCmdlet.ParameterSetName)
        {
            "Path"        { $files = Get-ChildItem -Path $Path }
            "LiteralPath" { $files = Get-ChildItem -LiteralPath $LiteralPath }
            "FileInfo"    { $files = $Item }
        }

        $files | % {
            # Work out file names
            $msgFn = $_.FullName

            # Skip non-.msg files
            if ($msgFn -notlike "*.msg") {
                Write-Verbose "Skipping $_ (not an .msg file)..."
                return
            }

            # Extract message body
            Write-Verbose "Extracting attachments from $_..."
            $msg = $outlook.CreateItemFromTemplate($msgFn)
            $msg.Attachments | % {
                # Work out attachment file name
                #$attFn = $msgFn -replace '\.msg$', " - Attachment - $($_.FileName)"
                $attDir = $Path + "\msg-attachments"
                New-Item -ItemType directory -Path $attDir
                $attFn = $attDir + "\" + $($_.FileName)
                
                # Do not try to overwrite existing files
                if (Test-Path -literalPath $attFn) {
                    Write-Verbose "Skipping $($_.FileName) (file already exists)..."
                    return
                }

                # Save attachment
                Write-Verbose "Saving $($_.FileName)..."
                $_.SaveAsFile($attFn)

                # Output to pipeline
                Get-ChildItem -LiteralPath $attFn
            }
        }
    }

    End
    {
        Write-Verbose "Done."
    }
}

#Get-ChildItem -Recurse | Expand-MsgAttachment
$PathForMsgFiles = "C:\Users\Mal\Desktop\DELETE_FILES"
$DirAttachmentFiles = $PathForMsgFiles + "\msg-attachment-files"
Expand-MsgAttachment -Path $PathForMsgFiles #-LiteralPath $DirAttachmentFiles
