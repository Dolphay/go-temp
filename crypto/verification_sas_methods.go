// Copyright (c) 2020 Nikos Filippakis
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"fmt"

	"github.com/Dolphay/mautrix_tmp/crypto/olm"
	"github.com/Dolphay/mautrix_tmp/event"
	"github.com/Dolphay/mautrix_tmp/id"
)

// SASData contains the data that users need to verify.
type SASData interface {
	Type() event.SASMethod
}

// VerificationMethod describes a method for generating a SAS.
type VerificationMethod interface {
	// GetVerificationSAS uses the user, device ID and key of the user who initiated the verification transaction,
	// the user, device ID and key of the user who accepted, the transaction ID and the SAS object to generate a SAS.
	// The SAS can be any type, such as an array of numbers or emojis.
	GetVerificationSAS(initUserID id.UserID, initDeviceID id.DeviceID, initKey string,
		acceptUserID id.UserID, acceptDeviceID id.DeviceID, acceptKey string,
		transactionID string, sas *olm.SAS) (SASData, error)
	// Type returns the type of this SAS method
	Type() event.SASMethod
}

const sasInfoFormat = "MATRIX_KEY_VERIFICATION_SAS|%s|%s|%s|%s|%s|%s|%s"

// VerificationMethodDecimal describes the decimal SAS method.
type VerificationMethodDecimal struct{}

// DecimalSASData contains the verification numbers for the decimal SAS method.
type DecimalSASData [3]uint

// Type returns the decimal SAS method type.
func (DecimalSASData) Type() event.SASMethod {
	return event.SASDecimal
}

// GetVerificationSAS generates the three numbers that need to match with the other device for a verification to be valid.
func (VerificationMethodDecimal) GetVerificationSAS(initUserID id.UserID, initDeviceID id.DeviceID, initKey string,
	acceptUserID id.UserID, acceptDeviceID id.DeviceID, acceptKey string,
	transactionID string, sas *olm.SAS) (SASData, error) {

	sasInfo := fmt.Sprintf(sasInfoFormat,
		initUserID, initDeviceID, initKey,
		acceptUserID, acceptDeviceID, acceptKey,
		transactionID)

	sasBytes, err := sas.GenerateBytes([]byte(sasInfo), 5)
	if err != nil {
		return DecimalSASData{0, 0, 0}, err
	}

	numbers := DecimalSASData{
		(uint(sasBytes[0])<<5 | uint(sasBytes[1])>>3) + 1000,
		(uint(sasBytes[1]&0x7)<<10 | uint(sasBytes[2])<<2 | uint(sasBytes[3]>>6)) + 1000,
		(uint(sasBytes[3]&0x3F)<<7 | uint(sasBytes[4])>>1) + 1000,
	}

	return numbers, nil
}

// Type returns the decimal SAS method type.
func (VerificationMethodDecimal) Type() event.SASMethod {
	return event.SASDecimal
}

var allEmojis = [...]VerificationEmoji{
	{'🐶', "Dog"},
	{'🐱', "Cat"},
	{'🦁', "Lion"},
	{'🐎', "Horse"},
	{'🦄', "Unicorn"},
	{'🐷', "Pig"},
	{'🐘', "Elephant"},
	{'🐰', "Rabbit"},
	{'🐼', "Panda"},
	{'🐓', "Rooster"},
	{'🐧', "Penguin"},
	{'🐢', "Turtle"},
	{'🐟', "Fish"},
	{'🐙', "Octopus"},
	{'🦋', "Butterfly"},
	{'🌷', "Flower"},
	{'🌳', "Tree"},
	{'🌵', "Cactus"},
	{'🍄', "Mushroom"},
	{'🌏', "Globe"},
	{'🌙', "Moon"},
	{'☁', "Cloud"},
	{'🔥', "Fire"},
	{'🍌', "Banana"},
	{'🍎', "Apple"},
	{'🍓', "Strawberry"},
	{'🌽', "Corn"},
	{'🍕', "Pizza"},
	{'🎂', "Cake"},
	{'❤', "Heart"},
	{'😀', "Smiley"},
	{'🤖', "Robot"},
	{'🎩', "Hat"},
	{'👓', "Glasses"},
	{'🔧', "Spanner"},
	{'🎅', "Santa"},
	{'👍', "Thumbs Up"},
	{'☂', "Umbrella"},
	{'⌛', "Hourglass"},
	{'⏰', "Clock"},
	{'🎁', "Gift"},
	{'💡', "Light Bulb"},
	{'📕', "Book"},
	{'✏', "Pencil"},
	{'📎', "Paperclip"},
	{'✂', "Scissors"},
	{'🔒', "Lock"},
	{'🔑', "Key"},
	{'🔨', "Hammer"},
	{'☎', "Telephone"},
	{'🏁', "Flag"},
	{'🚂', "Train"},
	{'🚲', "Bicycle"},
	{'✈', "Aeroplane"},
	{'🚀', "Rocket"},
	{'🏆', "Trophy"},
	{'⚽', "Ball"},
	{'🎸', "Guitar"},
	{'🎺', "Trumpet"},
	{'🔔', "Bell"},
	{'⚓', "Anchor"},
	{'🎧', "Headphones"},
	{'📁', "Folder"},
	{'📌', "Pin"},
}

// VerificationEmoji describes an emoji that might be sent for verifying devices.
type VerificationEmoji struct {
	Emoji       rune
	Description string
}

func (vm VerificationEmoji) GetEmoji() rune {
	return vm.Emoji
}

func (vm VerificationEmoji) GetDescription() string {
	return vm.Description
}

// EmojiSASData contains the verification emojis for the emoji SAS method.
type EmojiSASData [7]VerificationEmoji

// Type returns the emoji SAS method type.
func (EmojiSASData) Type() event.SASMethod {
	return event.SASEmoji
}

// VerificationMethodEmoji describes the emoji SAS method.
type VerificationMethodEmoji struct{}

// GetVerificationSAS generates the three numbers that need to match with the other device for a verification to be valid.
func (VerificationMethodEmoji) GetVerificationSAS(initUserID id.UserID, initDeviceID id.DeviceID, initKey string,
	acceptUserID id.UserID, acceptDeviceID id.DeviceID, acceptKey string,
	transactionID string, sas *olm.SAS) (SASData, error) {

	sasInfo := fmt.Sprintf(sasInfoFormat,
		initUserID, initDeviceID, initKey,
		acceptUserID, acceptDeviceID, acceptKey,
		transactionID)

	var emojis EmojiSASData
	sasBytes, err := sas.GenerateBytes([]byte(sasInfo), 6)

	if err != nil {
		return emojis, err
	}

	sasNum := uint64(sasBytes[0])<<40 | uint64(sasBytes[1])<<32 | uint64(sasBytes[2])<<24 |
		uint64(sasBytes[3])<<16 | uint64(sasBytes[4])<<8 | uint64(sasBytes[5])

	for i := 0; i < len(emojis); i++ {
		// take nth group of 6 bits
		emojiIdx := (sasNum >> uint(48-(i+1)*6)) & 0x3F
		emoji := allEmojis[emojiIdx]
		emojis[i] = emoji
	}

	return emojis, nil
}

// Type returns the emoji SAS method type.
func (VerificationMethodEmoji) Type() event.SASMethod {
	return event.SASEmoji
}
