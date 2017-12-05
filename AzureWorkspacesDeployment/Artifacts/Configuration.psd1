@{
    AllNodes = @(
        @{
            NodeName = "WSFront"
			Role = "WSFront"
			Dev = $true
        },
 
        @{
            NodeName = "WSBack"
			Role = "WSBack"
			Dev = $true
        },
 
        @{
            NodeName = "SQL"
			Role = "WSSQL"
			Dev = $false
        }
    );
}