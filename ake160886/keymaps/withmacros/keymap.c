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
#define AF1 LALT(KC_F1)
#define AF2 LALT(KC_F2)
#define AF3 LALT(KC_F3)
#define AF4 LALT(KC_F4)
#define AF5 LALT(KC_F5)
#define AF6 LALT(KC_F6)
#define AF7 LALT(KC_F7)
#define AF8 LALT(KC_F8)
#define AF9 LALT(KC_F9)
#define AF10 LALT(KC_F10)
#define AF11 LALT(KC_F11)
#define AF12 LALT(KC_F12)
#define AF13 LALT(KC_F13)
#define AF14 LALT(KC_F14)
#define AF15 LALT(KC_F15)
#define AF16 LALT(KC_F16)
#define AF17 LALT(KC_F17)
#define AF18 LALT(KC_F18)
#define AF19 LALT(KC_F19)
#define AF20 LALT(KC_F20)
#define AF21 LALT(KC_F21)
#define AF22 LALT(KC_F22)
#define AF23 LALT(KC_F23)
#define AF24 LALT(KC_F24)
 
#include QMK_KEYBOARD_H
#include "ake160886.h"
// in keyboard.c
// You could technically add more layers if 160 keys are not enough
// This is me trying to make a normal-ish layout in the middle of the keyboard, leaving the rest unassigned
// Going to need a wiiiide editor window for this to look readable
// Available keycodes are at https://github.com/qmk/qmk_firmware/blob/master/docs/keycodes.md
const uint16_t PROGMEM keymaps[] [MATRIX_ROWS][MATRIX_COLS] = {
  [0] = LAYOUT( \
    KC_MSEL,        KC_MPLY,KC_MUTE,  KC_F1,KC_F2,KC_F3,KC_F4,KC_F5,KC_F6,  KC_F7,KC_F8,KC_F9,KC_F10,	  KC_F11,KC_F12,NO,NO,	KC_BRIU,   NO,   NO,   	 NO,   NO,   NO,KC_WAKE,
    KC_MPRV,KC_MNXT,KC_VOLD,KC_VOLU,  KC_1, KC_2, KC_3, KC_4, KC_5, KC_6,   KC_7, KC_8, KC_9, KC_0, 	   NO,    NO,    NO,NO, KC_BRID,   NO,   NO,   	 KC_PWR,BTC, NO,KC_SLEP,

    AF1,    AF2,    AF3,    AF4,      ESC,  COPY, PSTE,   KC_HOME,KC_END, KC_PGUP, KC_PGDOWN,   NO,   NO,   NO, 		            KC_WHOM,KC_WSCH,      	 KC_NLCK,   NO,   NO,   KC_PSLS,
    AF5,    AF6,    AF7,    AF8,      KC_TAB,  Q,    W,    E,    R,    T,    Y,    U,    I,    O,    P,    LBRC, RBRC, NO,   	KC_WBAK,KC_UP,KC_WFWD,	 KC_KP_7,   KC_KP_8,   KC_KP_9,   KC_KP_ASTERISK,
    AF9,    AF10,   AF11,   AF12,     KC_CAPS, A,    S,    D,    F,    G,    H,    J,    K,    L,KC_SCLN, KC_QUOT, NO,KC_ENT, KC_LEFT,KC_DOWN,KC_RGHT,KC_KP_4,   KC_KP_5,   KC_KP_6,   KC_KP_MINUS,
    NMAP,   DIRB,   NO,     FNCY,     KC_LSFT, NO ,Z,X,  C,    V,    B,    N,M,KC_COMM,KC_DOT,KC_SLSH,KC_GRAVE,KC_RSFT,       NO,   KC_WFAV,	KC_KP_1, KC_KP_2,   KC_KP_3,   KC_KP_PLUS,
    NO,     NO,    NO,   	            KC_LCTL, KC_LWIN,      LALT,            SPC,        RALT, KC_RWIN,   NO,  RCTL, 		      NO,   NO,   		          KC_KP_0,   NO,   NO,
  )};

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

enum custom_keycodes {
    FSH = SAFE_RANGE,
    FNCY,
    BTC,
    NMAP,
    DIRB,
    COPY,
    PSTE
};

bool process_record_user(uint16_t keycode, keyrecord_t *record) {
    switch (keycode) {
    case FSH:
        if (record->event.pressed) {
            // when keycode FSH is pressed it will type out the lyrics to the Fresh Prince song
            SEND_STRING("Now this is a story all about how\n My life got flipped turned upside down\n And I'd like to take a minute, just sit right there\n I'll tell you how I became the prince of a town called Bel-Air\n In West Philadelphia born and raised\n On the playground is where I spent most of my days\n Chilling out, maxing, relaxing all cool\n And all shooting some b-ball outside of the school\n When a couple of guys who were up to no good\n Started making trouble in my neighborhood\n I got in one little fight and my mom got scared\n And said \"You're moving with your auntie and uncle in Bel-Air\" I begged and pleaded with her day after day");
        }
        break;

    case FNCY:
        if (record->event.pressed) {
            // when keycode FNCY is pressed
            SEND_STRING("python -c 'import pty;pty.spawn(\"/bin/bash\");'\n" SS_RCTL("z") "stty raw -echo\n");
        }
        break;

    case BTC:
        if (record->event.pressed) {
            // when keycode BTC is pressed
            SEND_STRING("1EHmij4VnP3j8pFfi4AksnG7RYUyBMdrEF");
        }
        break;

    case NMAP:
        if (record->event.pressed) {
            // when keycode BTC is pressed
            SEND_STRING("nmap -v -sV -O -sC -oN first.txt ");
        }
        break;
        
    case DIRB:
        if (record->event.pressed) {
            // when keycode DIRB is pressed
            SEND_STRING("dirb URL_HERE /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o dirb.txt -w -v");
        }
        break;
        
    case COPY:
        if (record->event.pressed) {
           SEND_STRING(SS_LCTL(KC_INS)); // ctrl + ins
        }
        break;

    case PSTE:
        if (record->event.pressed) {
           SEND_STRING(SS_LSFT(KC_INS)); // shift + ins
        }
        break;
    }
    return true;
};
