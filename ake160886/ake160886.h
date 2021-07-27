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

#pragma once

#include "quantum.h"

/* This is a shortcut to help you visually see your layout.
 *
 * The first section contains all of the arguments representing the physical
 * layout of the board and position of the keys.
 *
 * The second converts the arguments into a two-dimensional array which
 * represents the switch matrix.
 */
// in my_keyboard_name.h 
// Key numbers correspond to AKE160886/5 pcb silkscreen (https://i.imgur.com/TugBf0N.jpg)
#define LAYOUT( \
K1,         K2,   K3,   K4,   K5,   K6,   K7,   K8,   K9,   K10,  K11,  K12,  K13,  K14,  K15,  K16,  K17,  K18,  K19,  K20,  K21,  K22,  K23,  K24,\
K25,  K26,  K27,  K28,  K29,  K30,  K31,  K32,  K33,  K34,  K35,  K36,  K37,  K38,  K39,  K40,  K41,  K42,  K43,  K44,  K45,  K46,  K47,  K48,  K49,\
K50,  K51,  K52,  K53,  K54,  K55,        K56,        K57,        K58,  K59,  K60,  K61,  K62,        K63,  K64,  K65,        K66,  K67,  K68,  K69,\
K70,  K71,  K72,  K73,  K74,  K75,  K76,  K77,  K78,  K79,  K80,  K81,  K82,  K83,  K84,  K85,  K86,  K87,  K88,  K89,  K90,  K91,  K92,  K93,  K94,\
K95,  K96,  K97,  K98,  K99,  K100, K101, K102, K103, K104, K105, K106, K107, K108, K109, K110, K111, K112, K113, K114, K115, K116, K117, K118, K119,\
K120, K121, K122, K123, K124, K125, K126, K127, K128, K129, K130, K131, K132, K133, K134, K135, K136, K137, K138, K139, K140, K141, K142, K143, K144,\
K145,       K146, K147, K148, K149,       K150,             K151,             K152,       K153, K154, K155, K156, K157,       K158, K159, K160\
) { \
{ K1,   K2,   K3,   K4,   K5,   K6,   K7,   K8   }, \
{ K9,   K10,  K11,  K12,  K13,  K14,  K15,  K16  }, \
{ K17,  K18,  K19,  K20,  K21,  K22,  K23,  K24  }, \
{ K25,  K26,  K27,  K28,  K29,  K30,  K31,  K32  }, \
{ K33,  K34,  K35,  K36,  K37,  K38,  K39,  K40  }, \
{ K41,  K42,  K43,  K44,  K45,  K46,  K47,  K48  }, \
{ K49,  K50,  K51,  K52,  K53,  K54,  K55,  K56  }, \
{ K57,  K58,  K59,  K60,  K61,  K62,  K63,  K64  }, \
{ K65,  K66,  K67,  K68,  K69,  K70,  K71,  K72  }, \
{ K73,  K74,  K75,  K76,  K77,  K78,  K79,  K80  }, \
{ K81,  K82,  K83,  K84,  K85,  K86,  K87,  K88  }, \
{ K89,  K90,  K91,  K92,  K93,  K94,  K95,  K96  }, \
{ K97,  K98,  K99,  K100, K101, K102, K103, K104 }, \
{ K105, K106, K107, K108, K109, K110, K111, K112 }, \
{ K113, K114, K115, K116, K117, K118, K119, K120 }, \
{ K121, K122, K123, K124, K125, K126, K127, K128 }, \
{ K129, K130, K131, K132, K133, K134, K135, K136 }, \
{ K137, K138, K139, K140, K141, K142, K143, K144 }, \
{ K145, K146, K147, K148, K149, K150, K151, K152 }, \
{ K153, K154, K155, K156, K157, K158, K159, K160 }  \
}
