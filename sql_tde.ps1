param ($instance = $( Read-Host "Enter Instance name" ),
       $username = $( Read-Host "Enter username" ),
       $password = $( Read-Host -AsSecureString "Enter password" )
       )

$pw=[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))

Import-Module sqlps

$status_query="SELECT DB_NAME(database_id) AS DatabaseName, encryption_state, encryption_state_desc =
                CASE encryption_state
                   WHEN '0' THEN 'No database encryption key present, no encryption'
                   WHEN '1' THEN 'Unencrypted'
                   WHEN '2' THEN 'Encryption in progress'
                   WHEN '3' THEN 'Encrypted'
                   WHEN '4' THEN 'Key change in progress'
                   WHEN '5' THEN 'Decryption in progress'
                   WHEN '6' THEN 'Protection change in progress (The certificate or asymmetric key that is encrypting the database encryption key is being changed.)'
                   ELSE 'No Status'
                   END,
                   percent_complete,encryptor_thumbprint, encryptor_type,create_date,regenerate_date FROM sys.dm_database_encryption_keys
                   WHERE DB_NAME(database_id) NOT IN ('master', 'model', 'tempdb', 'msdb')"


function status
{

    $status1= Invoke-Sqlcmd -Query "SELECT  sys.databases.name AS DatabaseName, sys.asymmetric_keys.name AS KEK, sys.databases.is_encrypted
                                FROM ((sys.dm_database_encryption_keys
                                INNER JOIN sys.asymmetric_keys ON sys.asymmetric_keys.thumbprint = sys.dm_database_encryption_keys.encryptor_thumbprint)
                                INNER JOIN sys.databases ON sys.databases.database_id = sys.dm_database_encryption_keys.database_id)
                                WHERE is_encrypted=1" -ServerInstance $instance -username $username -password $pw | format-table

    $status2=Invoke-Sqlcmd -Query "SELECT name AS DatabaseName, is_encrypted
                                FROM sys.databases
                                WHERE name NOT IN ('master', 'model', 'tempdb', 'msdb') AND is_encrypted=0" -ServerInstance $instance -username $username -password $pw | format-table
    
    Write-Output $status1, $status2
    
}


function enable_tde
{
    $DB=$( Read-Host "Enter database name" )
   
    $status=Invoke-Sqlcmd -Query "$status_query" -ServerInstance $instance -username $username -password $pw

    $count= (Invoke-Sqlcmd -Query "SELECT COUNT(*)
                                FROM ($status_query) AS T" -ServerInstance $instance -username $username -password $pw)[0]


    foreach($item in $status)
    { 
        if($item.Databasename -like $DB -and $status.encryption_state -eq '1')
            {
                Invoke-Sqlcmd -Query "ALTER DATABASE $DB
                                        SET ENCRYPTION ON ;
                                        GO"-ServerInstance $instance -username $username -password $pw
                return
            }
    }

    $status2=Invoke-Sqlcmd -Query "SELECT name, is_encrypted
                            FROM sys.databases
                            WHERE name NOT IN ('master', 'model', 'tempdb', 'msdb')" -ServerInstance $instance -username $username -password $pw

    foreach($item in $status2)
    {
        if($item.name -like $DB -and $item.is_encrypted -eq 0)
        {
            $KEK="ekm_login_key_v1"
            $SO="SQL_Server_Key_v1"

            if($count -eq 0)
            {
                $api_key=$( Read-Host "Enter api-key to create credential" )

                Invoke-Sqlcmd -Query "CREATE CREDENTIAL EKM_TDE_CRED
                                    WITH IDENTITY = 'Identity1',
                                    SECRET = '$api_key'
                                    FOR CRYPTOGRAPHIC PROVIDER EKM_Prov ;
                                    GO" -ServerInstance $instance -username $username -password $pw

                $login_name = $( Read-Host "Enter login name to map credential" )
                $login_name= '"' + $login_name +'"'

                Invoke-Sqlcmd -Query "ALTER LOGIN $login_name
                                    ADD CREDENTIAL EKM_TDE_CRED;
                                    GO" -ServerInstance $instance -username $username -password $pw
            

                Invoke-Sqlcmd -query "USE master ;
                                    GO
                                    CREATE ASYMMETRIC KEY $KEK
                                    FROM PROVIDER EKM_Prov
                                    WITH ALGORITHM = RSA_2048,
                                    PROVIDER_KEY_NAME = '$SO';
                                    GO" -ServerInstance $instance -username $username -password $pw


                Invoke-Sqlcmd -Query "USE master ;
                                    GO
                                    CREATE CREDENTIAL db_ekm_tde_cred
                                    WITH IDENTITY = 'Identity2',
                                    SECRET = '$api_key'
                                    FOR CRYPTOGRAPHIC PROVIDER EKM_Prov" -ServerInstance $instance -username $username -password $pw


                Invoke-Sqlcmd -Query "CREATE LOGIN EKM_Login
                                    FROM ASYMMETRIC KEY $KEK ;
                                    GO" -ServerInstance $instance -username $username -password $pw


                Invoke-Sqlcmd -Query "ALTER LOGIN EKM_Login
                                    ADD CREDENTIAL db_ekm_tde_cred ;
                                    GO" -ServerInstance $instance -username $username -password $pw

            }

            Invoke-Sqlcmd -Query "USE $DB
                                CREATE DATABASE ENCRYPTION KEY
                                WITH ALGORITHM  = AES_256
                                ENCRYPTION BY SERVER ASYMMETRIC KEY $KEK ;" -ServerInstance $instance -username $username -password $pw


            Invoke-Sqlcmd -Query "ALTER DATABASE $DB
                                SET ENCRYPTION ON ;
                                GO"-ServerInstance $instance -username $username -password $pw
            return
                                                                  
        }

        ElseIf($item.name -like $DB -and $item.is_encrypted -eq 1)
        {
            Write-Host “Database is already encrypted”
            return
        }
        
    }

    Write-Host “No such database exist”

}


function rotation
{
    $DB=$( Read-Host "Enter database name" )
    $date=Get-Date -Format "dd_MM_yyyy_HH_mm"

    $status= Invoke-Sqlcmd -Query "SELECT name, is_encrypted
                            FROM sys.databases
                            WHERE name NOT IN ('master', 'model', 'tempdb', 'msdb')" -ServerInstance $instance -username $username -password $pw

    foreach($item in $status)
    {
        if($item.name -like $DB -and $item.is_encrypted -eq 1)
        {
            $KEK = "ekm_login_key_" + $date
            $SO ="SQL_Server_Key_" + $date
            $cred = "db_ekm_tde_cred_" + $date
            $Id = "Identity_" +$date
            $login = "EKM_Login_" + $date

            Invoke-Sqlcmd -Query "USE master ;
                                GO
                                CREATE ASYMMETRIC KEY $KEK
                                FROM PROVIDER EKM_Prov
                                WITH ALGORITHM = RSA_2048,
                                PROVIDER_KEY_NAME = '$SO' ;
                                GO" -ServerInstance $instance -username $username -password $pw

            $api_key=$( Read-Host "Enter api-key to create credential" )

            Invoke-Sqlcmd -Query "USE master ;
                                GO
                                CREATE CREDENTIAL $cred
                                WITH IDENTITY = '$Id',
                                SECRET = '$api_key'
                                FOR CRYPTOGRAPHIC PROVIDER EKM_Prov" -ServerInstance $instance -username $username -password $pw

                        
            Invoke-Sqlcmd -Query "CREATE LOGIN $login
                                FROM ASYMMETRIC KEY $KEK ;
                                GO" -ServerInstance $instance -username $username -password $pw


            Invoke-Sqlcmd -Query "ALTER LOGIN $login 
                                ADD CREDENTIAL $cred;" -ServerInstance $instance -username $username -password $pw

                        
            Invoke-Sqlcmd -Query "USE $DB;
                                ALTER DATABASE ENCRYPTION KEY
                                ENCRYPTION BY SERVER ASYMMETRIC KEY $KEK;" -ServerInstance $instance -username $username -password $pw
            return

        }

        ElseIf($item.name -like $DB -and $item.is_encrypted -eq 0)
        {
            Write-Host “Database is not encrypted”
            return
        }

    } 

    Write-Host “No such database exist”                                               

}

function Show-Menu
{
     param (
           [string]$Title = ‘Menu’
     )
     cls
     Write-Host “================ $Title ================”
    
     Write-Host “1: Press ‘1’ to check status.”
     Write-Host “2: Press ‘2’ to Enable TDE.”
     Write-Host “3: Press ‘3’ for Rotation.”
     Write-Host “Q: Press ‘Q’ to quit.”
}

do
{
     Show-Menu
     $input = Read-Host “Please make a selection”
     switch ($input)
     {
           ‘1’ {
                status
           } ‘2’ {
                enable_tde
           } ‘3’ {
                rotation
           } ‘q’ {
                return
           }
     }
     pause
}
until ($input -eq ‘q’)
