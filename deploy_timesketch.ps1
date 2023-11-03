# Copyright 2023 Steven Maestas. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#Requires -RunAsAdministrator

$START_CONTAINER = ''

# Exit early if run as non-root user
if($args[0] -eq "--start-container") {
    $START_CONTAINER="yes"
}

# Exit early if a time-sketch directory already exists.
if (Test-Path -Path ".\timesketch") {
    Write-Output "ERROR: Timesketch directory already exists."
    exit
}

# Check to see if WSL is installed, if not install it
$WSL = wsl --status
if ($WSL -eq 0) {
    Write-Output "[+] Installing Windows WSL2..."
    wsl --install
    Write-Output "[+] Windows WSL2 is installed!"
}
else {
    Write-Output "[+] Windows WSL2 is installed!"
}

# Function to get Cryptopgraphically random alphanumeric characters
$CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
$rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
Function Get-RandomString {
    Param($length)
    $KEY = ""
    for($i = 0; $i -lt 32; $i++)
    {
        [byte[]] $byte = 1
        $rng.GetBytes($byte)
        $KEY = $KEY + $CHARS[[int]$byte[0]%62]
    }
    $KEY
}

# Function to check if any given CLI command exists
Function Test-CommandExists
{
    Param ($command)
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = ‘stop’
    try {if(Get-Command $command){“$command exists”}}
    Catch {“$command does not exist”}
    Finally {$ErrorActionPreference=$oldPreference}
}

# Check to see if the docker command exists, if not install Docker Desktop for Windows
if ((Test-CommandExists docker) -eq "docker does not exist") {
    Write-Output "[-] Docker does not exist!"
    Write-Output "[+] Installing docker..."
    if(Test-Path -Path ".\Docker Desktop Installer.exe") {
        Write-Output "[+] Docker installer exists, using existing installer"
    }
    else {
        Write-Output "[-] No existing Docker installer, downloading installer..."
        Invoke-WebRequest "https://desktop.docker.com/win/main/amd64/Docker%20Desktop%20Installer.exe" -OutFile "Docker Desktop Installer.exe"
    }
    Write-Output "[+] Installing Docker Desktop for Windows..."
    cmd /c "`"%cd%\Docker Desktop Installer.exe`" install --quiet --backend=wsl-2 --accept-license"
    # Update the PATH after install
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User") 
    Start-Sleep -s 30
    if ((Test-CommandExists docker) -eq "docker exists") {
        Write-Output "[+] Docker Desktop for Windows successfully installed"
    }
}

$SERVICE = "com.docker.service"
$arrService = Get-Service -Name $SERVICE
if ($arrService.Status -ne 'Running') {
    Write-Output "[-] Docker service not started.  Starting service..."
    Start-Service $SERVICE
}
if ($arrService.Status -eq 'Running') {
    Write-Output "[+] Docker service started"
}
else {
    Write-Output "ERROR stating docker service"
    exit
}

if ((Test-CommandExists docker-compose) -eq "docker-compose does not exist") {
    Write-Output "ERROR docker-compose not found"
}
else {
    Write-Output "[+] docker-compose command installed"
}

# Check to make sure docker desktop is running, if not start it
$DOCKER_PS = "Docker Desktop"
$CHECK_PS = Get-Process $DOCKER_PS -ErrorAction SilentlyContinue
if(!$CHECK_PS) {
    Write-Output "[-] Docker Desktop is not running. Starting Docker Desktop..."
    Start-Process -FilePath "C:\Program Files\Docker\Docker\frontend\Docker Desktop.exe"
    Start-Sleep -s 10
    $CHECK_PS = Get-Process $DOCKER_PS -ErrorAction SilentlyContinue
    if($CHECK_PS) {
        Write-Output "[+] Docker Desktop successfully started"
    }
    else {
        Write-Output "ERROR: Docker Desktop could not be started"
    }
} 
else {
    Write-Output "[+] Docker Desktop is already running"
}

# Check to see if Timesketch containers are already running
$TIMESKETCH = docker ps | Select-String -Pattern "timesketch"
if ($TIMESKETCH -ne $null) {
    Write-Output "ERROR: Timesketch is already running. Exiting"
    exit
}

#Tweak for OpenSearch
Write-Output "[+] Setting vm.max_map_count for OpenSearch"
if(Test-Path -Path $env:USERPROFILE/.wlsconfig) {
    "[+] WSL Config exists"
    $TEST = Select-String -Pattern "sysctl\.vm\.max_map_count=262144" -Path $env:USERPROFILE/.wslconfig
    if ($TEST -eq $null) {
        "[-] Configuration file vm.max_map_count not set, creating config"
        Write-Output "[wsl2]" | Out-File -FilePath $env:USERPROFILE/.wslconfig
        Write-Output "kernelCommandLine = `"sysctl.vm.max_map_count=262144`"" | Out-File -Append -FilePath $env:USERPROFILE/.wslconfig
        "[+] WSL configuration file vm.max_map_count set"
    }
    else {
        "[+] WSL file vm.max_map_count set correctly"
    }
}
else {
    "[-] Configuration file vm.max_map_count not set, creating config"
     Write-Output "[wsl2]" | Out-File -FilePath $env:USERPROFILE/.wslconfig
     Write-Output "kernelCommandLine = `"sysctl.vm.max_map_count=262144`"" | Out-File -Append -FilePath $env:USERPROFILE/.wslconfig
}
$RUN_SET = wsl -d docker-desktop -e cat /proc/sys/vm/max_map_count
if($RUN_SET -ge 262144) {
    Write-Output "[+] Running vm.max_map_count set correctly"
}
else {
    Write-Output "[-] Setting running vm.max_map_count"
    Write-Output "sysctl -w vm.max_map_count=262144" | Out-File -FilePath .\vm_max_count.sh -Encoding ascii -NoNewline
    #Write-Output "echo 262144 > /proc/sys/vm/max_map_count" | Out-File -FilePath .\vm_max_count.sh
    wsl -d docker-desktop sh vm_max_count.sh
    $RUN_SET = wsl -d docker-desktop -e cat /proc/sys/vm/max_map_count
    if($RUN_SET -ge 262144) {
        Write-Output "[+] Running vm.max_map_count successfully set"
        #rm .\vm_max_count.sh
    }
    else {
        Write-Output "ERROR: running vm.max_map_count could not be set"
        #rm .\vm_max_count.sh
    }
}

# Set needed directories
Write-Output "[+] Creating required directories..."
New-Item -Path timesketch,timesketch/data/postgresql,timesketch/data/opensearch,timesketch/logs,timesketch/etc,timesketch/etc/timesketch/sigma/rules,timesketch/upload -ItemType Directory

# Set needed variables
Write-Output "[-] Setting default config parameters..."
$POSTGRES_USER="timesketch"
$POSTGRES_PASSWORD=Get-RandomString -length 32
$POSTGRES_ADDRESS="postgres"
$POSTGRES_PORT=5432
$SECRET_KEY=Get-RandomString -length 32
$OPENSEARCH_ADDRESS="opensearch"
$OPENSEARCH_PORT=9200
get-wmiobject -class "Win32_ComputerSystem"
$OPENSEARCH_MEM_USE_GB = [math]::Ceiling($cs.TotalPhysicalMemory / 1024 / 1024 / 1024)/2
#$OPENSEARCH_MEM_USE_GB=$(cat /proc/meminfo | grep MemTotal | awk '{printf "%.0f", ($2 / (1024 * 1024) / 2)}')
$REDIS_ADDRESS="redis"
$REDIS_PORT=6379
$GITHUB_BASE_URL="https://raw.githubusercontent.com/google/timesketch/master"

# Docker compose and configuration
Write-Host "* Fetching configuration files.."
(Invoke-webrequest -URI $GITHUB_BASE_URL/docker/release/docker-compose.yml).Content > timesketch\docker-compose.yml
(Invoke-webrequest -URI $GITHUB_BASE_URL/docker/release/config.env).Content > timesketch\config.env

# Fetch default Timesketch config files
# The encoding is set as UTF8NoBOM as otherwise the dockers can't read the configurations right.
(Invoke-webrequest -URI $GITHUB_BASE_URL/data/timesketch.conf).Content | out-file timesketch\etc\timesketch\timesketch.conf -encoding ascii
(Invoke-webrequest -URI $GITHUB_BASE_URL/data/tags.yaml).Content | out-file timesketch\etc\timesketch\tags.yaml -encoding ascii
(Invoke-webrequest -URI $GITHUB_BASE_URL/data/plaso.mappings).Content | out-file timesketch\etc\timesketch\plaso.mappings -encoding ascii
(Invoke-webrequest -URI $GITHUB_BASE_URL/data/generic.mappings).Content | out-file timesketch\etc\timesketch\generic.mappings -encoding ascii
(Invoke-webrequest -URI $GITHUB_BASE_URL/data/features.yaml).Content | out-file timesketch\etc\timesketch\features.yaml -encoding ascii
(Invoke-webrequest -URI $GITHUB_BASE_URL/data/ontology.yaml).Content | out-file timesketch\etc\timesketch\ontology.yaml -encoding ascii
(Invoke-webrequest -URI $GITHUB_BASE_URL/data/intelligence_tag_metadata.yaml).Content | out-file timesketch\etc\timesketch\intelligence_tag_metadata.yaml -encoding ascii
(Invoke-webrequest -URI $GITHUB_BASE_URL/data/sigma_config.yaml).Content | out-file timesketch\etc\timesketch\sigma_config.yaml -encoding ascii
(Invoke-webrequest -URI $GITHUB_BASE_URL/data/sigma_rule_status.csv).Content | out-file timesketch\etc\timesketch\sigma_rule_status.csv -encoding ascii
(Invoke-webrequest -URI $GITHUB_BASE_URL/data/sigma/rules/lnx_susp_zmap.yml).Content | out-file timesketch\etc\timesketch\sigma\rules\lnx_susp_zmap.yml -encoding ascii
(Invoke-webrequest -URI $GITHUB_BASE_URL/contrib/nginx.conf).Content | out-file timesketch\etc\nginx.conf -encoding ascii
Write-Host "OK"

# Create a minimal Timesketch config
Write-Host "* Edit configuration files."
$timesketchconf = 'timesketch\etc\timesketch\timesketch.conf'
$convfenv = 'timesketch\config.env'
(Get-Content $timesketchconf).replace("SECRET_KEY = '<KEY_GOES_HERE>'", "SECRET_KEY = '$SECRET_KEY'") | Set-Content $timesketchconf

# Set up the OpenSearch connection
(Get-Content $timesketchconf).replace("ELASTIC_HOST = '127.0.0.1'", "ELASTIC_HOST = '$OPENSEARCH_ADDRESS'") | Set-Content $timesketchconf
(Get-Content $timesketchconf).replace("ELASTIC_PORT = 9200", "ELASTIC_PORT = $OPENSEARCH_PORT") | Set-Content $timesketchconf

# Set up the Redis connection
(Get-Content $timesketchconf).replace("UPLOAD_ENABLED = False", "UPLOAD_ENABLED = True") | Set-Content $timesketchconf
(Get-Content $timesketchconf).replace("UPLOAD_FOLDER = '/tmp'", "UPLOAD_FOLDER = '/usr/share/timesketch/upload'") | Set-Content $timesketchconf

(Get-Content $timesketchconf).replace("CELERY_BROKER_URL = 'redis://127.0.0.1:6379'", "CELERY_BROKER_URL = 'redis://$($REDIS_ADDRESS):$($REDIS_PORT)'") | Set-Content $timesketchconf
(Get-Content $timesketchconf).replace("CELERY_RESULT_BACKEND = 'redis://127.0.0.1:6379'", "CELERY_RESULT_BACKEND = 'redis://$($REDIS_ADDRESS):$($REDIS_PORT)'") | Set-Content $timesketchconf

# Set up the Postgres connection
(Get-Content $timesketchconf).replace("SQLALCHEMY_DATABASE_URI = 'postgresql://<USERNAME>:<PASSWORD>@localhost/timesketch'", "SQLALCHEMY_DATABASE_URI = 'postgresql://$($POSTGRES_USER):$($POSTGRES_PASSWORD)@$($POSTGRES_ADDRESS):$($POSTGRES_PORT)/timesketch'") | Set-Content $timesketchconf

(Get-Content $convfenv).replace("POSTGRES_PASSWORD=", "POSTGRES_PASSWORD=$POSTGRES_PASSWORD") | Set-Content $convfenv
(Get-Content $convfenv).replace("OPENSEARCH_MEM_USE_GB=", "OPENSEARCH_MEM_USE_GB=$OPENSEARCH_MEM_USE_GB") | Set-Content $convfenv

copy-item -Path $convfenv -Destination timesketch\.env
Write-Host "OK"
Write-Host "* Installation done."

Write-Host "--"
Write-Host "--"
Write-Host "--"
Write-Host "Start the system:"
Write-Host "1. cd timesketch"
Write-Host "2. docker compose up -d"
Write-Host "3. docker compose exec timesketch-web tsctl create-user <USERNAME>"
Write-Host "--"
Write-Host "WARNING: The server is running without encryption."
Write-Host "Follow the instructions to enable SSL to secure the communications:"
Write-Host "https://github.com/google/timesketch/blob/master/docs/Installation.md"
    

    