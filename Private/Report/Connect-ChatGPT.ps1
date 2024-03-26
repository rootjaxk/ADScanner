function Connect-ChatGPT {
  <#
    .SYNOPSIS
    This reusable function will take a prompt and connect to the chatGPT API for vulnerabiltity aid (find-userdescription) and report generation (Invoke-ADScanner)  
    A one shot response is chosen as learning from chat history is not required
  
    .PARAMETER APIKey
    The API key to connect to the ChatGPT API to avoid hardcoding the secret in the script

    .PARAMETER Prompt
    The prompt to provide the GPT to generate a response
  
    .EXAMPLE 
    Connect-ChatGPT -APIKey $apiKey -Prompt $prompt
  
  #>
   
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory = $true)]
    [String]
    $APIkey,

    [Parameter(Mandatory = $true)]
    [String]
    $Prompt,

    [Parameter(Mandatory = $true)]
    [int]
    $Temperature,

    [Parameter(Mandatory = $true)]
    [String]
    $AiSystemMessage
  )

  # Set the API endpoint
  $ApiEndpoint = "https://api.openai.com/v1/chat/completions"

  # List of Hashtables that will hold the system message and user message.
  [System.Collections.Generic.List[Hashtable]]$messages = @()

  # Sets the initial system message
  $messages.Add(@{"role" = "system"; "content" = $AiSystemMessage }) | Out-Null

  # Add the user input
  $messages.Add(@{"role" = "user"; "content" = $Prompt })

  # Set the request headers
  $headers = @{
    "Content-Type"  = "application/json"
    "Authorization" = "Bearer $APIkey"
  }   

  # Set the request body
  $requestBody = @{
    "model"       = "gpt-3.5-turbo-0125"    #up to 16385 context windows
    "messages"    = $messages
    "max_tokens"  = 500 # Max amount of tokens the AI will respond with
    "temperature" = $Temperature # Lower is more coherent and conservative, higher is more creative and diverse.
  }

  # Send the request
  Write-Host "Sending request to ChatGPT API..." -ForegroundColor Yellow
  $response = Invoke-RestMethod -Method POST -Uri $ApiEndpoint -Headers $headers -Body (ConvertTo-Json $requestBody)

  # Return the message content
  $response.choices[0].message.content  #return - might need to return 

}