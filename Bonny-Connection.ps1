# Bonny Connection helper for Windows. Uses the upstream zapret-win-bundle.
# This helper does not install drivers, change DNS, or create an autostart task.

$ErrorActionPreference = 'Stop'
$script:Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:BundleDirectory = Join-Path $script:Root 'vendor\zapret-win-bundle'
$script:BundleUrl = 'https://github.com/bol-van/zapret-win-bundle/archive/refs/heads/master.zip'
$script:TargetsFile = Join-Path $script:Root 'targets.txt'

function Write-Title {
    Clear-Host
    Write-Host 'Bonny Connection' -ForegroundColor Cyan
    Write-Host 'Проверка сети и запуск официальной диагностики Zapret' -ForegroundColor DarkGray
    Write-Host ''
}

function Get-Targets {
    if (-not (Test-Path -LiteralPath $script:TargetsFile)) {
        throw "Не найден файл со списком доменов: $script:TargetsFile"
    }

    Get-Content -LiteralPath $script:TargetsFile -Encoding UTF8 |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -and $_ -notlike '#*' }
}

function Install-UpstreamBundle {
    if (Test-Path -LiteralPath $script:BundleDirectory) {
        Write-Host 'Папка официальной сборки уже существует:' -ForegroundColor Yellow
        Write-Host "  $script:BundleDirectory"
        Write-Host 'Чтобы не перезаписать ваши файлы, удалите или переименуйте ее вручную перед повторной загрузкой.'
        return
    }

    $vendor = Join-Path $script:Root 'vendor'
    $temporary = Join-Path $script:Root ('.zapret-download-' + [Guid]::NewGuid().ToString('N'))
    $archive = Join-Path $temporary 'bundle.zip'
    $extract = Join-Path $temporary 'extract'

    try {
        New-Item -ItemType Directory -Path $temporary -Force | Out-Null
        New-Item -ItemType Directory -Path $extract -Force | Out-Null
        Write-Host 'Загружаю исходный пакет с github.com/bol-van/zapret-win-bundle ...'
        Invoke-WebRequest -Uri $script:BundleUrl -OutFile $archive -UseBasicParsing
        Expand-Archive -LiteralPath $archive -DestinationPath $extract

        $bundleRoot = Get-ChildItem -LiteralPath $extract -Directory |
            Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'blockcheck\blockcheck.cmd') } |
            Select-Object -First 1
        if (-not $bundleRoot) {
            throw 'В архиве не найдена ожидаемая структура официальной сборки.'
        }

        New-Item -ItemType Directory -Path $vendor -Force | Out-Null
        Move-Item -LiteralPath $bundleRoot.FullName -Destination $script:BundleDirectory
        Write-Host 'Готово. Файлы распакованы; сами программы не запускались.' -ForegroundColor Green
        Write-Host "Папка: $script:BundleDirectory"
    }
    finally {
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -LiteralPath $temporary -Recurse -Force
        }
    }
}

function Test-TcpTls {
    param([Parameter(Mandatory = $true)][string]$HostName)

    $client = $null
    $ssl = $null
    $dnsOk = $false
    $tcpOk = $false
    try {
        $addresses = [System.Net.Dns]::GetHostAddresses($HostName)
        if (-not $addresses -or $addresses.Count -eq 0) {
            return [pscustomobject]@{ Host = $HostName; DNS = 'ошибка'; TCP443 = '—'; TLS = '—'; Detail = 'DNS не вернул адрес' }
        }
        $dnsOk = $true

        $client = New-Object System.Net.Sockets.TcpClient
        # ConnectAsync(host, port) can try another resolved address if the first one is unreachable.
        $connectTask = $client.ConnectAsync($HostName, 443)
        if (-not $connectTask.Wait(3500)) {
            return [pscustomobject]@{ Host = $HostName; DNS = 'OK'; TCP443 = 'тайм-аут'; TLS = '—'; Detail = 'TCP 443 не ответил за 3.5 секунды' }
        }
        $tcpOk = $true

        $ssl = New-Object System.Net.Security.SslStream($client.GetStream(), $false)
        $tlsTask = $ssl.AuthenticateAsClientAsync($HostName)
        if (-not $tlsTask.Wait(4000)) {
            return [pscustomobject]@{ Host = $HostName; DNS = 'OK'; TCP443 = 'OK'; TLS = 'тайм-аут'; Detail = 'TLS рукопожатие не завершилось за 4 секунды' }
        }

        return [pscustomobject]@{ Host = $HostName; DNS = 'OK'; TCP443 = 'OK'; TLS = 'OK'; Detail = $client.Client.RemoteEndPoint.ToString() }
    }
    catch {
        $message = $_.Exception.GetBaseException().Message
        if ($tcpOk) {
            return [pscustomobject]@{ Host = $HostName; DNS = 'OK'; TCP443 = 'OK'; TLS = 'ошибка'; Detail = $message }
        }
        if ($dnsOk) {
            return [pscustomobject]@{ Host = $HostName; DNS = 'OK'; TCP443 = 'ошибка'; TLS = '—'; Detail = $message }
        }
        return [pscustomobject]@{ Host = $HostName; DNS = 'ошибка'; TCP443 = 'ошибка'; TLS = '—'; Detail = $message }
    }
    finally {
        if ($ssl) { $ssl.Dispose() }
        if ($client) { $client.Dispose() }
    }
}

function Test-Services {
    Write-Host 'Проверяю разрешение DNS и HTTPS-подключение (TCP/TLS 443).' -ForegroundColor Cyan
    Write-Host 'Эта проверка не проверяет вход в аккаунт, видеопоток или голосовой UDP-трафик.'
    Write-Host ''

    $results = foreach ($hostName in (Get-Targets)) { Test-TcpTls -HostName $hostName }
    $results | Format-Table -AutoSize -Wrap
    Write-Host 'Если DNS/TLS проходят, а приложение не работает, запустите blockcheck и проверьте сам клиент.'
}

function Start-UpstreamBlockcheck {
    $blockcheckDirectory = Join-Path $script:BundleDirectory 'blockcheck'
    $blockcheck = Join-Path $blockcheckDirectory 'blockcheck.cmd'
    if (-not (Test-Path -LiteralPath $blockcheck)) {
        Write-Host 'Сначала выберите пункт 1, чтобы загрузить официальный пакет.' -ForegroundColor Yellow
        return
    }

    $targets = (Get-Targets) -join ' '
    Write-Host 'Откроется окно диагностики от имени администратора.' -ForegroundColor Cyan
    Write-Host 'Когда blockcheck попросит домены, вставьте этот список:' -ForegroundColor Yellow
    Write-Host $targets -ForegroundColor White
    Write-Host ''
    Write-Host 'blockcheck проверит стратегии для выбранных доменов; универсальный результат для всех провайдеров не гарантирован.'

    $command = 'cd /d "{0}" && call blockcheck.cmd' -f $blockcheckDirectory
    Start-Process -FilePath $env:ComSpec -ArgumentList @('/k', $command) -WorkingDirectory $blockcheckDirectory -Verb RunAs
}

function Show-Menu {
    while ($true) {
        Write-Title
        Write-Host '1. Загрузить официальный пакет Zapret'
        Write-Host '2. Проверить DNS и HTTPS для сервисов'
        Write-Host '3. Запустить blockcheck для подбора стратегии'
        Write-Host '4. Открыть папку пакета'
        Write-Host '5. Открыть официальную инструкцию'
        Write-Host '0. Выход'
        Write-Host ''
        $choice = Read-Host 'Выберите действие'

        try {
            switch ($choice) {
                '1' { Install-UpstreamBundle }
                '2' { Test-Services }
                '3' { Start-UpstreamBlockcheck }
                '4' {
                    if (Test-Path -LiteralPath $script:BundleDirectory) {
                        Start-Process explorer.exe -ArgumentList "`"$script:BundleDirectory`""
                    } else {
                        Write-Host 'Пакет еще не загружен. Выберите пункт 1.' -ForegroundColor Yellow
                    }
                }
                '5' { Start-Process 'https://github.com/bol-van/zapret/blob/master/docs/quick_start_windows.md' }
                '0' { return }
                default { Write-Host 'Выберите пункт из меню.' -ForegroundColor Yellow }
            }
        }
        catch {
            Write-Host ''
            Write-Host ('Ошибка: ' + $_.Exception.GetBaseException().Message) -ForegroundColor Red
        }

        Write-Host ''
        [void](Read-Host 'Нажмите Enter, чтобы вернуться в меню')
    }
}

Show-Menu
