Get-ChildItem *.mp4 | foreach-object {

    Write-Host $_.name 
    
    [int]$digit = $_.name -replace '\D+(\d+).mp4','$1'
    
    Write-Host $digit
    
    Write-Host ($digit.ToString("D3"))
    
    Write-Host ("{0:D3}" -f $digit)
    
    $newfilename = 'pwk-{0:D3}.mp4' -f $digit
    
    Write-Host $newfilename
    
    Rename-Item $_ -NewName ($newfilename)

}
